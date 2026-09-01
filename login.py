#!/usr/bin/env python3
"""
login.py — SentinelOne session management (multi-tenant).

Cada tenant en config.json tiene sus propias credenciales SentinelOne y su
propio Azure Key Vault. Este módulo hace login con Playwright para cada
tenant y guarda las cookies resultantes en el KV correspondiente.
"""

import json
import logging
import os
import random
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import pyotp
from typing import Optional
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from helpers.tenant_config import load_tenant_configs, resolve_login, tenant_secrets

logger = logging.getLogger(__name__)

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)


def _console_host(login_url: str) -> str:
    return urlparse(login_url).netloc


def _console_base(login_url: str) -> str:
    parsed = urlparse(login_url)
    return f"{parsed.scheme}://{parsed.netloc}"


# ---------------------------------------------------------------------------
# Human typing helper
# ---------------------------------------------------------------------------

def human_fill(page, selector: str, text: str):
    page.click(selector)
    time.sleep(random.uniform(0.2, 0.6))
    for char in text:
        page.type(selector, char, delay=random.uniform(80, 220))
    time.sleep(random.uniform(0.3, 1.0))


# ---------------------------------------------------------------------------
# Core login — opera con credenciales explícitas (no env vars)
# ---------------------------------------------------------------------------

def do_login(tenant_cfg: dict) -> dict:
    """
    Hace login completo en SentinelOne para el tenant dado.

    Args:
        tenant_cfg: entrada de config.json con keys email, password, totp, name...

    Returns:
        dict con all_cookies
    """
    name = tenant_cfg.get("name", "unknown")
    creds = resolve_login(name)
    email       = creds["email"]
    password    = creds["password"]
    totp_secret = creds.get("totp", "")
    login_url   = creds["url"]

    logger.info("=" * 60)
    logger.info(f"🚀 do_login() — tenant: {name}")
    logger.info(f"✓ Email: {email[:3]}***{email[-10:]}")
    logger.info("=" * 60)

    temp_dir = f"/tmp/s1_chrome_{name.lower().replace(' ', '_').replace(',', '')}"
    os.makedirs(temp_dir, exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=temp_dir,
            headless=False,
            no_viewport=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        page = context.new_page()
        page.on("console", lambda msg: logger.debug(f"[browser] {msg.text}"))

        logger.info("🌐 Navigating to SentinelOne login...")
        page.goto(login_url, wait_until="domcontentloaded")

        for _ in range(random.randint(3, 6)):
            page.mouse.move(random.randint(100, 800), random.randint(100, 600), steps=random.randint(5, 20))
            time.sleep(random.uniform(0.1, 0.3))

        logger.info("⏳ Waiting for email input...")
        page.wait_for_selector('[data-mgmtautomationid="username"]', timeout=30000)
        page.wait_for_selector('[data-mgmtautomationid="password"]', timeout=30000)

        logger.info("📧 Typing email...")
        human_fill(page, '[data-mgmtautomationid="username"]', email)

        logger.info("🔒 Typing password...")
        human_fill(page, '[data-mgmtautomationid="password"]', password)

        logger.info("🖱️ Clicking submit...")
        page.click('button[type="submit"]')

        logger.info("⏳ Waiting 8s for MFA page...")
        time.sleep(8)

        otp = pyotp.TOTP(totp_secret).now() if totp_secret else ""
        logger.info(f"🔢 OTP: ***{otp[-3:] if otp else 'N/A'}")

        if otp:
            logger.info("⌨️ Typing MFA code...")
            try:
                page.wait_for_selector('[data-mgmtautomationid="code-input"]', timeout=10000)
                human_fill(page, '[data-mgmtautomationid="code-input"]', otp)

                logger.info("🖱️ Clicking Submit/Enviar...")
                try:
                    page.click('button:has-text("Enviar"), button:has-text("Submit")', timeout=5000)
                    logger.info("✅ Button clicked")
                except Exception as e:
                    logger.warning(f"Button click failed: {e} — trying JS click")
                    page.evaluate("document.querySelector('button[type=\"submit\"]').click()")
            except PlaywrightTimeoutError:
                logger.warning("MFA input not found — login may not require MFA or already passed")

        logger.info("⏳ Waiting for dashboard URL...")
        try:
            host = _console_host(login_url)
            page.wait_for_url(f"*{host}/dashboard*", timeout=30000)
            logger.info(f"✅ Dashboard loaded: {page.url}")
        except Exception:
            logger.warning(f"⚠️ Dashboard URL not detected, current URL: {page.url} — waiting 5s extra")
            time.sleep(5)

        logger.info("🔍 Navigating to Deep Visibility...")
        visibility_cookies = []
        try:
            page.wait_for_selector("i.mgmt-deep-visibility", timeout=15000)
            logger.info(f"📍 URL before click: {page.url}")
            # El click abre una nueva pestaña — capturarla con expect_page
            with context.expect_page(timeout=15000) as new_page_info:
                page.click("i.mgmt-deep-visibility")
            xdr_page = new_page_info.value
            logger.info(f"📍 New tab opened: {xdr_page.url}")
            logger.info("⏳ Waiting for XDR page to load...")
            xdr_page.wait_for_load_state("domcontentloaded", timeout=30000)
            logger.info(f"✅ XDR loaded: {xdr_page.url}")
            time.sleep(8)
            visibility_cookies = context.cookies()
            logger.info(f"🍪 {len(visibility_cookies)} visibility cookies captured")
            for c in visibility_cookies:
                logger.info(f"   cookie: {c.get('name')} | domain: {c.get('domain')}")
        except Exception as e:
            logger.warning(f"⚠️ Deep Visibility navigation failed: {e}")
            logger.warning(f"📍 URL at failure: {page.url}")
            try:
                page.screenshot(path=f"/tmp/s1_visibility_error_{name}.png", full_page=True)
                logger.info("📸 Screenshot saved to /tmp/s1_visibility_error_*.png")
            except Exception:
                pass

        cookies = context.cookies()
        logger.info(f"🍪 {len(cookies)} total cookies found")

        # Guardar todas las cookies de la sesión autenticada
        relevant_cookies = [c for c in cookies if c.get("domain", "").endswith("sentinelone.net")]
        if not relevant_cookies:
            relevant_cookies = cookies  # fallback: guardar todas si ninguna coincide con el dominio

        if not relevant_cookies:
            try:
                page.screenshot(path=f"/tmp/s1_login_error_{name}.png", full_page=True)
                logger.info("📸 Screenshot saved")
            except Exception:
                pass
            raise Exception(f"No cookies found after login for tenant '{name}'")

        logger.info(f"✅ {len(relevant_cookies)} relevant cookies captured")
        context.close()

    return {
        "all_cookies":        relevant_cookies,
        "visibility_cookies": visibility_cookies,
    }


# ---------------------------------------------------------------------------
# Session validation (sin browser) — verifica que la sesión sigue activa
# ---------------------------------------------------------------------------

def check_session_valid(cookies: list, base_url: str | None = None) -> bool:
    import requests
    try:
        cookie_jar = {c["name"]: c["value"] for c in cookies}
        if not base_url:
            for c in cookies:
                domain = (c.get("domain") or "").lstrip(".")
                if domain.endswith("sentinelone.net"):
                    base_url = f"https://{domain}"
                    break
        if not base_url:
            return False
        resp = requests.get(
            f"{base_url.rstrip('/')}/",
            cookies=cookie_jar,
            timeout=10,
            allow_redirects=False,
        )
        valid = resp.status_code not in (302, 401, 403)
        logger.info(f"Session check → HTTP {resp.status_code} → {'✅ valid' if valid else '❌ expired'}")
        return valid
    except Exception as e:
        logger.warning(f"Session check failed: {e}")
        return False


# ---------------------------------------------------------------------------
# get_or_refresh — para un tenant concreto
# ---------------------------------------------------------------------------

def get_or_refresh_session(tenant_cfg: dict) -> list:
    """
    Siempre hace login completo y guarda cookies en KV.
    Devuelve la lista de cookies de la sesión principal.
    """
    from helpers.keyvault_helper import KeyVaultHelper

    ts = tenant_secrets(tenant_cfg.get("name"))
    name             = tenant_cfg.get("name", "unknown")
    cookies_key      = ts.secret_name("session_cookies")
    visibility_key   = ts.secret_name("session_cookies_visibility")

    kv = KeyVaultHelper.from_tenant_config(tenant_cfg)

    logger.info(f"🔄 [{name}] Performing full login...")
    result             = do_login(tenant_cfg)
    all_cookies        = result["all_cookies"]
    visibility_cookies = result["visibility_cookies"]

    kv.set_secret(cookies_key, json.dumps({"cookies": all_cookies}))
    logger.info(f"✅ [{name}] Saved session cookies to KV → {cookies_key}")

    if visibility_cookies:
        kv.set_secret(visibility_key, json.dumps({"cookies": visibility_cookies}))
        logger.info(f"✅ [{name}] Saved visibility cookies to KV → {visibility_key}")
    else:
        logger.warning(f"⚠️ [{name}] No visibility cookies to save")

    return all_cookies


# ---------------------------------------------------------------------------
# run_login_all_tenants — punto de entrada multi-tenant
# ---------------------------------------------------------------------------

def run_login_all_tenants(tenants: Optional[list] = None) -> dict:
    """
    Itera todos los tenants, refresca sesión y guarda en cada KV.

    Returns:
        dict[tenant_name -> cookies_list]
    """
    if tenants is None:
        tenants = load_tenant_configs()

    results = {}
    errors  = []

    for cfg in tenants:
        name = cfg.get("name", "unknown")
        try:
            cookies = get_or_refresh_session(cfg)
            results[name] = cookies
            logger.info(f"✅ [{name}] Done — {len(cookies)} cookies")
        except Exception as e:
            logger.error(f"❌ [{name}] Login failed: {e}")
            errors.append((name, str(e)))

    if errors:
        logger.warning("=" * 60)
        logger.warning(f"⚠️  {len(errors)} tenant(s) failed:")
        for name, err in errors:
            logger.warning(f"   • {name}: {err}")
        logger.warning("=" * 60)

    logger.info(f"✅ Login completed: {len(results)}/{len(tenants)} tenants OK")
    return results


# ---------------------------------------------------------------------------
# Compat: modo CLI
# ---------------------------------------------------------------------------

def run_login_mode() -> list:
    """Single-tenant mode — usa el primer tenant del config."""
    logger.info("Mode: LOGIN (multi-tenant)")
    results = run_login_all_tenants()
    return next(iter(results.values()), [])
