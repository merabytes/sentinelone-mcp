#!/usr/bin/env python3
"""
purple_ai.py — SentinelOne Purple AI via Playwright (headful, playwright-core).
"""

from __future__ import annotations

import logging
import os
import random
import sys
import time
from pathlib import Path
from typing import Any

import pyotp
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from helpers.tenant_config import resolve_login, resolve_tenant
from login import human_fill

logger = logging.getLogger(__name__)

_here = Path(__file__).resolve().parent
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

INPUT_SEL = 'textarea[data-test-id="power-query-input"]'

_EXTRACT_JS = """
() => {
    const items = document.querySelectorAll('.ConversationFeed__Feed__FeedItem');
    if (!items.length) return null;
    const last = items[items.length - 1];
    const get = (sel) => {
        const el = last.querySelector(sel);
        return el ? el.innerText.trim() : '';
    };
    const getAll = (sel) => Array.from(last.querySelectorAll(sel))
        .map(e => e.innerText.trim())
        .filter(t => t.length > 0);
    const loading = last.querySelector(
        '[class*="loading"], [class*="spinner"], [class*="thinking"],' +
        '[class*="Thinking"], .PurpleAI__loading'
    );
    return {
        loading: !!loading,
        heading: get('.ConversationFeed__Feed__FeedItem__Heading__Content'),
        query: get('.PQText__Query'),
        rowCount: get('.PQFeedResults__RowCount'),
        timeRange: get('.PQFeedResults__TimeRange'),
        summary: getAll('.PQFeedResults__Summary .purple-markdown-li p, .PQFeedResults__Summary .purple-markdown-p'),
        followUp: getAll('.ConversationFeed__Feed__FeedItem__Suggestion button .TruncateWithTooltip, .ConversationFeed__Feed__FeedItem__Suggestion button'),
        timestamp: get('.FeedItemFooter__ReturnTimestamp'),
        questionCount: get('.FeedItemFooter__QuestionCount'),
    };
}
"""


def format_purple_response(data: dict[str, Any]) -> str:
    if data.get("loading"):
        return ""
    if not (data.get("rowCount") or data.get("summary")):
        return ""

    width = 62
    lines = ["═" * width]
    if data.get("heading"):
        lines.append(f"  {data['heading']}")
        lines.append("═" * width)
    if data.get("query"):
        lines.append("\n📊 QUERY GENERADO:")
        for ql in data["query"].split("\n"):
            lines.append(f"  {ql}")
    meta = " · ".join(filter(None, [data.get("rowCount"), data.get("timeRange")]))
    if meta:
        lines.append(f"\n📈 {meta}")
    if data.get("summary"):
        lines.append("\n📋 RESUMEN:")
        for bullet in data["summary"]:
            if bullet not in " ".join(lines):
                lines.append(f"  • {bullet}")
    if data.get("followUp"):
        lines.append("\n💬 PREGUNTAS SUGERIDAS:")
        seen: set[str] = set()
        idx = 1
        for q in data["followUp"]:
            if q in seen:
                continue
            seen.add(q)
            lines.append(f"  {idx}. {q}")
            idx += 1
    footer = " · ".join(filter(None, [data.get("timestamp"), data.get("questionCount")]))
    if footer:
        lines.append(f"\n  🕐 {footer}")
    lines.append("═" * width)
    return "\n".join(lines)


class PurpleAISession:
    """Reusable Playwright headful session for Purple AI."""

    def __init__(self, tenant_cfg: dict):
        self.tenant_cfg = tenant_cfg
        name = tenant_cfg.get("name", "unknown")
        creds = resolve_login(name)
        self.email = creds["email"]
        self.password = creds["password"]
        self.totp_secret = creds.get("totp", "")
        self.login_url = creds["url"]
        self.user_data_dir = f"/tmp/s1_purple_{name.lower().replace(' ', '_')}"
        self.playwright = None
        self.context = None
        self.page = None
        self.feed_count = 0
        self.ready = False

    def _user_dir(self) -> str:
        os.makedirs(self.user_data_dir, exist_ok=True)
        return self.user_data_dir

    def _start_browser(self) -> None:
        if self.context is not None:
            return
        logger.info("Launching Playwright (headful)...")
        self.playwright = sync_playwright().start()
        self.context = self.playwright.chromium.launch_persistent_context(
            user_data_dir=self._user_dir(),
            headless=False,
            no_viewport=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        self.page = self.context.pages[0] if self.context.pages else self.context.new_page()

    def _submit_mfa_if_needed(self, page) -> None:
        if not self.totp_secret:
            return
        otp = pyotp.TOTP(self.totp_secret).now()
        for sel in (
            '[data-mgmtautomationid="code-input"]',
            'input[name="otp"]',
            'input[name="totp"]',
            'input[name="code"]',
        ):
            try:
                page.wait_for_selector(sel, timeout=3000)
                human_fill(page, sel, otp)
                try:
                    page.click('button:has-text("Enviar"), button:has-text("Submit")', timeout=5000)
                except Exception:
                    page.keyboard.press("Enter")
                time.sleep(4)
                return
            except PlaywrightTimeoutError:
                continue

    def _login_and_navigate(self) -> None:
        page = self.page
        assert page is not None

        page.goto(self.login_url, wait_until="domcontentloaded")
        page.wait_for_selector('[data-mgmtautomationid="username"]', timeout=30000)
        human_fill(page, '[data-mgmtautomationid="username"]', self.email)
        human_fill(page, '[data-mgmtautomationid="password"]', self.password)
        page.click('button[type="submit"]')
        time.sleep(5)
        self._submit_mfa_if_needed(page)

        try:
            page.wait_for_url("*sentinelone.net*", timeout=30000)
        except PlaywrightTimeoutError:
            logger.warning("Login redirect slow — continuing from %s", page.url)

        xdr_page = page
        try:
            page.wait_for_selector("i.mgmt-deep-visibility", timeout=15000)
            with self.context.expect_page(timeout=15000) as new_page_info:
                page.click("i.mgmt-deep-visibility")
            xdr_page = new_page_info.value
            xdr_page.wait_for_load_state("domcontentloaded", timeout=30000)
            time.sleep(2)
        except Exception as e:
            logger.warning("Visibility nav failed (%s) — trying Purple from current page", e)

        try:
            xdr_page.click('a[data-test-id="nav-purple-button"]', timeout=15000)
        except PlaywrightTimeoutError:
            xdr_page.get_by_text("Purple", exact=False).first.click(timeout=10000)

        xdr_page.wait_for_selector(INPUT_SEL, timeout=30000)
        self.page = xdr_page
        self.feed_count = self._count_feed_items()
        self.ready = True
        logger.info("Purple AI ready at %s", xdr_page.url)

    def _count_feed_items(self) -> int:
        assert self.page is not None
        n = self.page.evaluate(
            "() => document.querySelectorAll('.ConversationFeed__Feed__FeedItem').length"
        )
        return int(n or 0)

    def _extract_response(self) -> dict[str, Any]:
        assert self.page is not None
        data = self.page.evaluate(_EXTRACT_JS)
        return data or {"loading": True}

    def _wait_for_response(self, prev_count: int, timeout: int) -> tuple[dict[str, Any], str, int]:
        logger.info("Waiting for Purple AI response...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            current = self._count_feed_items()
            if current > prev_count:
                data = self._extract_response()
                text = format_purple_response(data)
                if text:
                    return data, text, current
            time.sleep(1.0)

        data = self._extract_response()
        text = format_purple_response(data) or "[Sin respuesta tras timeout]"
        return data, text, self._count_feed_items()

    def ensure_ready(self) -> None:
        if self.ready and self.page is not None:
            return
        self._start_browser()
        self._login_and_navigate()

    def ask(self, query: str, timeout: int = 90) -> dict[str, Any]:
        self.ensure_ready()
        assert self.page is not None

        input_el = self.page.locator(INPUT_SEL)
        input_el.wait_for(state="visible", timeout=10000)
        self.feed_count = self._count_feed_items()

        input_el.click()
        input_el.fill("")
        for char in query:
            input_el.type(char, delay=random.randint(40, 120))
        time.sleep(0.3)

        sent = False
        for sel in (
            'button[data-test-id="send-button"]',
            'button[data-test-id="purple-send"]',
            '[class*="SendButton"]',
        ):
            try:
                self.page.locator(sel).click(timeout=2000)
                sent = True
                break
            except PlaywrightTimeoutError:
                pass
        if not sent:
            input_el.press("Enter")

        data, text, self.feed_count = self._wait_for_response(self.feed_count, timeout)
        return {"query": query, "response": data, "formatted": text}

    def close(self) -> None:
        if self.context:
            self.context.close()
            self.context = None
        if self.playwright:
            self.playwright.stop()
            self.playwright = None
        self.page = None
        self.ready = False


_session: PurpleAISession | None = None
_session_tenant: str | None = None


def reset_purple_session() -> None:
    global _session, _session_tenant
    if _session:
        _session.close()
    _session = None
    _session_tenant = None


def ask_purple_ai(query: str, tenant_name: str | None = None, timeout: int = 90) -> dict[str, Any]:
    global _session, _session_tenant
    tenant = resolve_tenant(tenant_name)
    name = tenant.get("name", "unknown")

    if _session is None or _session_tenant != name:
        if _session:
            _session.close()
        _session = PurpleAISession(tenant)
        _session_tenant = name

    return _session.ask(query, timeout=timeout)
