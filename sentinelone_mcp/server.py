#!/usr/bin/env python3
"""
FastMCP server for SentinelOne — login, XDR alerts, Purple AI, SOC investigation.

Investigation tools delegate to helpers/sentinelone.py (SentinelOneHelper).
"""

from __future__ import annotations

import atexit
import asyncio
import logging
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastmcp import FastMCP

from login import run_login_all_tenants
from helpers.tenant_config import load_tenant_configs
from create_alert import run_create_alert_mode
from purple_ai import PURPLE_ASK_TIMEOUT, ask_purple_ai, force_close_owned_profiles, reset_purple_session
from helpers.s1_factory import resolve_s1_helper, resolve_xdr_helper
from sentinelone_mcp.s1_watch_thread import start_watch_thread

logger = logging.getLogger(__name__)

mcp = FastMCP("SentinelOne MCP")


# ── Tenant / session ops ─────────────────────────────────────────────────────

@mcp.tool(description="List configured SentinelOne tenants from config.json.")
async def list_tenants() -> dict[str, Any]:
    tenants = load_tenant_configs()
    return {
        "tenants": [
            {
                "name": t.get("name"),
                "vault_url": t.get("azure", {}).get("vault_url"),
                "secret_keys": list(t.get("secrets", {}).keys()),
            }
            for t in tenants
        ],
        "count": len(tenants),
    }


@mcp.tool(
    description=(
        "Refresh SentinelOne session cookies for one or all tenants. "
        "Stores cookies in each tenant's Azure Key Vault."
    )
)
async def refresh_login(tenant: str | None = None) -> dict[str, Any]:
    tenants = load_tenant_configs()
    if tenant:
        tenants = [t for t in tenants if t.get("name", "").upper() == tenant.upper()]
        if not tenants:
            return {"error": f"Tenant '{tenant}' not found", "results": {}}

    results = await asyncio.to_thread(run_login_all_tenants, tenants)
    return {
        "success": True,
        "tenants_ok": list(results.keys()),
        "cookie_counts": {name: len(cookies) for name, cookies in results.items()},
    }


@mcp.tool(
    description=(
        "Process pending XDR alerts from Elasticsearch and create them via GraphQL. "
        "Requires prior refresh_login for XDR visibility cookies."
    )
)
async def process_pending_alerts() -> dict[str, Any]:
    await asyncio.to_thread(run_create_alert_mode, True)
    return {"success": True, "message": "Alert queue processed (see logs for details)"}


# ── SOC investigation (SentinelOneHelper) ────────────────────────────────────

@mcp.tool(
    description=(
        "Fetch Cloud Detection alerts from SentinelOne Management API. "
        "Optional filters: site_ids (comma-separated), created_after (ISO8601)."
    )
)
async def get_alerts(
    tenant: str | None = None,
    limit: int = 20,
    site_ids: str | None = None,
    created_after: str | None = None,
) -> dict[str, Any]:
    s1 = resolve_s1_helper(tenant)
    params: dict[str, Any] = {"limit": limit}
    if site_ids:
        params["siteIds"] = site_ids
    if created_after:
        params["createdAt__gte"] = created_after
    data = await asyncio.to_thread(s1.get_alerts, **params)
    alerts = data.get("data", data) if isinstance(data, dict) else data
    count = len(alerts) if isinstance(alerts, list) else 0
    return {"alerts": alerts, "count": count}


@mcp.tool(
    description=(
        "List SentinelOne STAR / cloud-detection rules including name, description, "
        "status, severity, and S1QL body (the custom rule contents)."
    )
)
async def get_cloud_detection_rules(
    tenant: str | None = None,
    limit: int = 200,
    name_contains: str | None = None,
) -> dict[str, Any]:
    s1 = resolve_s1_helper(tenant)
    raw = await asyncio.to_thread(s1.get_rules)
    rules = raw.get("data", raw) if isinstance(raw, dict) else raw
    if not isinstance(rules, list):
        return {"error": "unexpected rules payload", "raw_type": type(raw).__name__}
    slim = []
    needle_l = (name_contains or "").lower()
    for rule in rules:
        name = rule.get("name") or ""
        if needle_l and needle_l not in name.lower() and needle_l not in (rule.get("s1ql") or "").lower():
            continue
        slim.append({
            "id": rule.get("id"),
            "name": name,
            "description": rule.get("description"),
            "status": rule.get("status"),
            "severity": rule.get("severity"),
            "treatAsThreat": rule.get("treatAsThreat"),
            "queryType": rule.get("queryType"),
            "s1ql": rule.get("s1ql"),
        })
        if len(slim) >= limit:
            break
    return {"count": len(slim), "total": len(rules), "rules": slim}


@mcp.tool(
    description=(
        "Fetch recent SentinelOne threats. Returns threatName, storyline, user, computer, "
        "status, engines, maliciousProcessArguments, originatorProcess, initiatedByDescription."
    )
)
async def get_threats(
    tenant: str | None = None,
    limit: int = 10,
    sort_order: str = "desc",
    incident_status: str | None = None,
) -> dict[str, Any]:
    s1 = resolve_s1_helper(tenant)
    filters = {"incidentStatuses": incident_status} if incident_status else None
    threats = await asyncio.to_thread(
        s1.get_threats,
        limit=limit,
        sort_order=sort_order,
        filters=filters,
    )
    return {"threats": threats, "count": len(threats)}


@mcp.tool(
    description=(
        "Fetch unresolved threats created in the last N hours. "
        "Entry point for incident triage — resolved threats are excluded."
    )
)
async def get_unresolved_threats(
    tenant: str | None = None,
    limit: int = 20,
    hours_back: int = 24,
) -> dict[str, Any]:
    s1 = resolve_s1_helper(tenant)
    threats = await asyncio.to_thread(
        s1.get_unresolved_threats, limit=limit, hours_back=hours_back
    )
    return {"threats": threats, "count": len(threats)}


@mcp.tool(
    description=(
        "Get timeline of a threat — reveals the custom rule name that triggered it. "
        "ALWAYS call before verdict. If Custom Rule, the threat name is a label not evidence."
    )
)
async def get_threat_context(threat_id: str, tenant: str | None = None) -> dict[str, Any]:
    s1 = resolve_s1_helper(tenant)
    ctx = await asyncio.to_thread(s1.get_threat_timeline, threat_id=threat_id)
    return {"threat_id": threat_id, **ctx}


@mcp.tool(
    description=(
        "Fetch Deep Visibility events for a storyline (Management API). "
        "Use event_filter for S1QL: ObjectType = \"URL\" for URLs, "
        "event.type = \"Process Creation\" for processes."
    )
)
async def get_storyline_events(
    storyline: str,
    tenant: str | None = None,
    event_filter: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    limit: int = 100,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    s1 = resolve_s1_helper(tenant)
    events = await asyncio.to_thread(
        s1.get_storyline_events,
        storyline=storyline,
        event_filter=event_filter,
        from_date=from_date,
        to_date=to_date,
        limit=limit,
    )
    return {"storyline": storyline, "events": events, "count": len(events)}


@mcp.tool(
    description=(
        "Run a raw Deep Visibility S1QL query (init → poll → events). "
        "Example: storyline = \"ABC123\" AND event.type = \"Process Creation\"."
    )
)
async def run_dv_query(
    query: str,
    tenant: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    limit: int = 100,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    s1 = resolve_s1_helper(tenant)
    events = await asyncio.to_thread(
        s1.run_dv_query,
        query,
        from_date,
        to_date,
        limit,
        timeout_seconds,
    )
    return {"query": query, "events": events, "count": len(events)}


@mcp.tool(
    description=(
        "Query SentinelOne XDR Data Lake (SentinelDataLakeHelper.query). "
        "event_type: PROCESS_CREATION, DNS, NETWORK_CONNECT, FILE_CREATION, LOGIN, "
        "REGISTRY_MODIFIED, COMMAND_SCRIPT, URL, CROSS_PROCESS, etc. "
        "Filter kwargs: endpoint, os, site_id, src_process, src_user, image, cmdline, "
        "domain, url, dst_ip, dst_port, storyline_id."
    )
)
async def xdr_query(
    event_type: str,
    tenant: str | None = None,
    hours: int = 24,
    extra: str | None = None,
    endpoint: str | None = None,
    os: str | None = None,
    site_id: str | None = None,
    src_process: str | None = None,
    src_user: str | None = None,
    image: str | None = None,
    cmdline: str | None = None,
    domain: str | None = None,
    url: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    storyline_id: str | None = None,
) -> dict[str, Any]:
    xdr = resolve_xdr_helper(tenant)
    filters = {
        k: v
        for k, v in {
            "endpoint": endpoint,
            "os": os,
            "site_id": site_id,
            "src_process": src_process,
            "src_user": src_user,
            "image": image,
            "cmdline": cmdline,
            "domain": domain,
            "url": url,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "storyline_id": storyline_id,
        }.items()
        if v is not None
    }
    rows = await asyncio.to_thread(
        xdr.query,
        event_type=event_type,
        hours=hours,
        extra=extra,
        **filters,
    )
    return {"event_type": event_type, "rows": rows, "count": len(rows)}


@mcp.tool(
    description=(
        "Mark one or more threats as resolved with analyst verdict. "
        "verdict: false_positive | true_positive | suspicious | undefined."
    )
)
async def mark_threat_resolved(
    threat_ids: str,
    tenant: str | None = None,
    analyst_verdict: str = "false_positive",
    note: str = "Resolved via SentinelOne MCP",
) -> dict[str, Any]:
    s1 = resolve_s1_helper(tenant)
    return await asyncio.to_thread(
        s1.mark_threat_resolved,
        threat_ids=threat_ids,
        analyst_verdict=analyst_verdict,
        note=note,
    )


# ── Purple AI ────────────────────────────────────────────────────────────────

# FastMCP tool timeout: stdio/server budget for headed login+fill+send.
# Old: decorator timeout unset (None) + purple_ai_query timeout_seconds default 90
#      (90s was only the ConversationFeed wait; login/MFA/nav + save-password
#      overlay made Cursor MCP clients hit JSON-RPC -32001).
# New: 600s FastMCP fail_after budget; inner ConversationFeed wait is
#      PURPLE_ASK_TIMEOUT (240s, was 90s).
PURPLE_MCP_TOOL_TIMEOUT = 600

@mcp.tool(
    description=(
        "Ask SentinelOne Purple AI a natural-language query. "
        "Uses Playwright headful; reuses browser session across calls."
    ),
    timeout=PURPLE_MCP_TOOL_TIMEOUT,
)
async def purple_ai_query(
    query: str,
    tenant: str | None = None,
    timeout_seconds: int = PURPLE_ASK_TIMEOUT,
) -> dict[str, Any]:
    if not query.strip():
        return {"error": "query must not be empty"}
    try:
        result = await asyncio.to_thread(
            ask_purple_ai, query.strip(), tenant, timeout_seconds
        )
        return {"success": True, **result}
    except asyncio.CancelledError:
        # FastMCP/stdio timeout: the worker thread may still hold Chromium.
        logger.warning("purple_ai_query cancelled; force-closing Purple Chromium")
        try:
            await asyncio.to_thread(force_close_owned_profiles)
        except Exception:
            logger.exception("force-close after purple_ai_query cancel failed")
        raise


@mcp.tool(description="Reset cached Purple AI browser session (forces re-login on next query).")
async def purple_ai_reset() -> dict[str, Any]:
    await asyncio.to_thread(reset_purple_session)
    return {"success": True, "message": "Purple AI session reset"}


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )
    atexit.register(force_close_owned_profiles)
    start_watch_thread()
    mcp.run()


if __name__ == "__main__":
    main()
