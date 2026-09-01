#!/usr/bin/env python3
"""
create_alert.py — Process pending XDR alerts from Elasticsearch.

Uses Playwright headful session + KV-stored visibility cookies to run CreateAlert GraphQL.
Requires `refresh_login` / `--mode login` first.
"""

import os
import sys
import json
import logging
import time

logger = logging.getLogger(__name__)

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

ALERTS_INDEX = "alerts"

GRAPHQL_MUTATION = (
    "mutation CreateAlert($alert: AlertInput!) {"
    " createAlert(alert: $alert) {"
    " alertId alertAddresses description gracePeriod note"
    " renotifyPeriod resolutionDelay evaluationFrequency trigger __typename"
    " } }"
)


# ---------------------------------------------------------------------------
# ES helpers — mismo patron que automations.py
# ---------------------------------------------------------------------------

def _get_es_client():
    from elasticsearch import Elasticsearch
    es_host   = os.environ.get("ELASTIC_HOST", "localhost")
    es_port   = int(os.environ.get("ELASTIC_PORT", 9200))
    es_scheme = os.environ.get("ELASTIC_SCHEME", "http")
    es_pass   = os.environ.get("ELASTIC_PASSWORD", "")
    return Elasticsearch(
        hosts=[{"host": es_host, "port": es_port, "scheme": es_scheme}],
        basic_auth=("elastic", es_pass),
        verify_certs=False,
        ssl_show_warn=False,
    )


def load_alerts_queue():
    try:
        ec = _get_es_client()
        if not ec.indices.exists(index=ALERTS_INDEX):
            logger.info("alerts index does not exist yet")
            return []
        resp = ec.search(
            index=ALERTS_INDEX,
            body={
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"status": "pending"}},
                            {"term": {"status.keyword": "pending"}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "sort": [{"created_at": {"order": "asc"}}],
                "size": 100,
            },
        )
        alerts = []
        for hit in resp["hits"]["hits"]:
            item = hit["_source"]
            item["_es_id"] = hit["_id"]
            alerts.append(item)
        logger.info(f"✓ Loaded {len(alerts)} pending alert(s) from ES")
        return alerts
    except Exception as e:
        logger.error(f"Error loading alerts: {e}")
        return []


def save_alert_status(es_id: str, status: str, xdr_alert_id: str = "", error: str = "") -> None:
    try:
        from datetime import datetime, timezone
        ec = _get_es_client()
        doc = {
            "status": status,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }
        if xdr_alert_id:
            doc["xdr_alert_id"] = xdr_alert_id
        if error:
            doc["error"] = error
        ec.update(index=ALERTS_INDEX, id=es_id, body={"doc": doc})
        logger.info(f"📝 ES updated: {es_id} → {status}")
    except Exception as e:
        logger.warning(f"Could not update ES doc {es_id}: {e}")


# ---------------------------------------------------------------------------
# XDR Playwright session (headful persistent context)
# ---------------------------------------------------------------------------

class XDRPlaywrightSession:
    """
    Playwright session for XDR alerts (headful persistent context).
    Loads cookies from KV (SENTINELONE-SESSION-COOKIES-VISIBILITY).
    """

    USER_DATA_DIR = "/tmp/s1_xdr_alerts_session"

    def __init__(self, tenant_cfg: dict, headless: bool = False):
        from helpers.tenant_config import resolve_xdr_region

        self.tenant_cfg = tenant_cfg
        self.headless   = headless
        self.playwright = None
        self.context    = None
        self.region     = resolve_xdr_region(tenant_cfg.get("name"))
        self.xdr_base   = f"https://xdr.{self.region}.sentinelone.net"
        self.graphql_url = f"{self.xdr_base}/v2/graphql"

    def __enter__(self):
        from playwright.sync_api import sync_playwright
        os.makedirs(self.USER_DATA_DIR, exist_ok=True)
        self.playwright = sync_playwright().start()
        self.context = self.playwright.chromium.launch_persistent_context(
            user_data_dir=self.USER_DATA_DIR,
            headless=self.headless,
            no_viewport=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        return self

    def __exit__(self, *_):
        if self.context:
            self.context.close()
        if self.playwright:
            self.playwright.stop()

    def _load_cookies_from_kv(self) -> list:
        from helpers.keyvault_helper import KeyVaultHelper
        from helpers.tenant_config import tenant_secrets

        ts = tenant_secrets(self.tenant_cfg.get("name"))
        kv = KeyVaultHelper.from_tenant_config(self.tenant_cfg)
        visibility_key = ts.secret_name("session_cookies_visibility")
        raw = kv.get_secret(visibility_key)
        if not raw:
            raise RuntimeError(f"No XDR cookies in KV ({visibility_key}) — run --mode login first")
        data = json.loads(raw)
        return data.get("cookies", data) if isinstance(data, dict) else data

    def verify_session(self) -> bool:
        """Navega a XDR y comprueba que no redirige a login."""
        try:
            page = self.context.new_page()
            page.goto(f"{self.xdr_base}/alerts", wait_until="domcontentloaded", timeout=30000)
            time.sleep(3)
            url = page.url
            page.close()
            authenticated = "login" not in url.lower() and "sentinelone.net" in url
            logger.info(f"Session check: {'✅ valid' if authenticated else '❌ expired'} ({url})")
            return authenticated
        except Exception as e:
            logger.warning(f"Session verify failed: {e}")
            return False

    def create_alert(self, doc: dict) -> dict:
        """
        Crea una alerta en XDR via GraphQL.
        Intercepta x-csrf-token + scalyr-team-token de requests reales de la app
        (mismo patron que SentinelDataLakeHelper.create_alert).
        """
        s1ql      = doc.get("s1ql_query", "")
        window    = doc.get("window_minutes", 1)
        threshold = doc.get("threshold", 0)
        trigger   = f"count:{window} minutes({s1ql}) > {threshold}"

        payload = {
            "operationName": "CreateAlert",
            "variables": {
                "alert": {
                    "description":         doc.get("description", ""),
                    "note":                doc.get("note", ""),
                    "trigger":             trigger,
                    "alertAddresses":      doc.get("alert_addresses", ""),
                    "gracePeriod":         doc.get("grace_period", 0),
                    "evaluationFrequency": doc.get("evaluation_frequency", 1),
                    "renotifyPeriod":      doc.get("renotify_period", 60),
                    "resolutionDelay":     doc.get("resolution_delay", 0),
                    "type":                "SINGLE",
                    "siteIds":             doc.get("site_ids", []),
                }
            },
            "query": GRAPHQL_MUTATION,
        }

        # Abrir pagina XDR e interceptar headers reales
        # (mismo patron que SentinelDataLakeHelper.create_alert con CDP route)
        auth_headers = {}
        page = self.context.new_page()

        def on_request(req):
            if "/v2/graphql" in req.url and req.method == "POST" and not auth_headers:
                h = req.headers
                if h.get("x-csrf-token") or h.get("scalyr-team-token"):
                    auth_headers.update(h)
                    logger.debug(f"Captured auth headers: {list(h.keys())}")

        page.on("request", on_request)
        page.goto(f"{self.xdr_base}/alerts", wait_until="domcontentloaded", timeout=60000)

        # Esperar headers hasta 15s
        for _ in range(15):
            if auth_headers:
                break
            time.sleep(1)

        page.close()

        if not auth_headers:
            raise RuntimeError(
                "Could not capture XDR auth headers — session may be expired, run --mode login"
            )

        # Enviar CreateAlert con headers reales via context.request
        response = self.context.request.post(
            self.graphql_url,
            headers={**auth_headers, "content-type": "application/json"},
            data=json.dumps(payload),
        )
        result = response.json()

        errors = result.get("errors")
        if errors:
            raise RuntimeError(f"GraphQL errors: {errors}")

        alert_data = (result.get("data") or {}).get("createAlert") or {}
        if not alert_data.get("alertId"):
            raise RuntimeError(f"Unexpected response: {result}")

        return alert_data


# ---------------------------------------------------------------------------
# Process queue — mismo patron que process_automation_queue
# ---------------------------------------------------------------------------

def process_alerts_queue(alerts: list) -> None:
    from login import load_tenant_configs, get_or_refresh_session

    tenants = load_tenant_configs()
    if not tenants:
        logger.error("No tenant configs found")
        for a in alerts:
            save_alert_status(a["_es_id"], "error", error="No tenant configs")
        return

    tenant = tenants[0]
    total = len(alerts)
    successful = 0
    failed = 0

    # ---------------------------------------------------------------------------
    # IMPORTANTE: sync_playwright() crea y arranca un asyncio event loop propio.
    # Si llamamos a get_or_refresh_session() (que también usa sync_playwright)
    # desde DENTRO de un with XDRPlaywrightSession, Playwright lanza:
    #   "Sync API inside asyncio loop"
    # Solución: resolver las cookies ANTES de abrir cualquier contexto Playwright,
    # y si la sesión expira, CERRAR el contexto primero, hacer login, y reabrir.
    # ---------------------------------------------------------------------------

    def _load_cookies_from_kv():
        try:
            from helpers.keyvault_helper import KeyVaultHelper
            from helpers.tenant_config import tenant_secrets

            ts = tenant_secrets(tenant.get("name"))
            kv = KeyVaultHelper.from_tenant_config(tenant)
            visibility_key = ts.secret_name("session_cookies_visibility")
            raw = kv.get_secret(visibility_key)
            if not raw:
                return None
            import json as _json
            data = _json.loads(raw)
            cookies = data.get("cookies", data) if isinstance(data, dict) else data
            logger.info(f"✅ Loaded {len(cookies)} XDR cookies from KV")
            return cookies
        except Exception as e:
            logger.warning(f"⚠️ Could not load cookies from KV: {e}")
            return None

    # 1. Intentar cargar cookies existentes
    cookies = _load_cookies_from_kv()

    # 2. Si no hay cookies, hacer login ANTES de abrir Playwright
    if not cookies:
        logger.info("🔑 No cookies in KV — running login flow first...")
        try:
            cookies = get_or_refresh_session(tenant)
            logger.info(f"✅ Login done, got {len(cookies)} fresh cookies")
        except Exception as e:
            logger.error(f"❌ Login failed: {e}")
            for a in alerts:
                save_alert_status(a["_es_id"], "error", error=f"Login failed: {e}")
            return

    # 3. Abrir contexto Playwright, verificar sesión.
    #    Si expiró: cerrar, re-login, reabrir (todo FUERA del with).
    logger.info(f"🎭 Opening XDR Playwright session for {total} alert(s)...")

    # Verificar sesión sin procesar alertas
    with XDRPlaywrightSession(tenant_cfg=tenant, headless=False) as xdr:
        xdr.context.add_cookies(cookies)
        session_ok = xdr.verify_session()

    if not session_ok:
        logger.info("🔑 Session expired — re-logging in (outside Playwright context)...")
        try:
            cookies = get_or_refresh_session(tenant)
            logger.info(f"✅ Re-login done, got {len(cookies)} fresh cookies")
        except Exception as e:
            logger.error(f"❌ Login failed: {e}")
            for a in alerts:
                save_alert_status(a["_es_id"], "error", error=f"Login failed: {e}")
            return

        # Verificar de nuevo
        with XDRPlaywrightSession(tenant_cfg=tenant, headless=False) as xdr:
            xdr.context.add_cookies(cookies)
            session_ok = xdr.verify_session()

        if not session_ok:
            logger.error("❌ XDR session still invalid after re-login")
            for a in alerts:
                save_alert_status(a["_es_id"], "error", error="XDR session invalid after login")
            return

    # 4. Sesión válida — procesar alertas
    with XDRPlaywrightSession(tenant_cfg=tenant, headless=False) as xdr:
        xdr.context.add_cookies(cookies)
        for idx, alert in enumerate(alerts, 1):
            es_id = alert.get("_es_id")
            desc  = alert.get("description", es_id)
            logger.info(f"\n[{idx}/{total}] Creating alert: '{desc}'")
            try:
                result = xdr.create_alert(alert)
                xdr_id = result.get("alertId", "")
                logger.info(f"✅ [{idx}/{total}] Created '{desc}' → alertId={xdr_id}")
                save_alert_status(es_id, "created", xdr_alert_id=xdr_id)
                successful += 1
            except Exception as e:
                logger.error(f"❌ [{idx}/{total}] Failed '{desc}': {e}")
                save_alert_status(es_id, "error", error=str(e))
                failed += 1

    logger.info(f"\n{'='*40}")
    logger.info(f"Done: {successful} ok, {failed} failed")


# ---------------------------------------------------------------------------
# Modo CLI
# ---------------------------------------------------------------------------

def run_create_alert_mode(once: bool = True) -> None:
    import time as _time
    logger.info("=" * 60)
    logger.info("Mode: CREATE_ALERT")
    logger.info("=" * 60)

    while True:
        alerts = load_alerts_queue()
        if alerts:
            process_alerts_queue(alerts)
        else:
            logger.info("No pending alerts")

        if once:
            break

        logger.info("Sleeping 60s before next check...")
        _time.sleep(60)
