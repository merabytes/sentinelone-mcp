"""Background poller: last-24h OPEN (unresolved) non-FP threats -> webhook s1-new-threat-dfir."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_PATH = os.environ.get("S1_WATCH_CONFIG", "/home/box/sentinelone-mcp/s1-watch.json")
KEYS_PATH = os.environ.get("WAKE_KEYS", "/home/box/sand-data/webhook-keys.json")
STATE_PATH = os.environ.get("S1_WATCH_STATE", "/tmp/s1-watch-last-ids.json")
DROP_DIR = os.environ.get("S1_WAKE_DIR", "/workspace/s1-wake")
QUEUE_PATH = os.environ.get("S1_QUEUE_FILE", "/workspace/s1-wake/open.json")
AGENT_ID = "a575d381-ff59-43bc-bde6-ed964285e9be"
LOCAL_ID = "s1-new-threat-dfir"
BACKEND = os.environ.get("SAND_BACKEND_URL") or os.environ.get("CURSOR_API_BASE_URL") or "https://api2.cursor.sh"
MADRID_TZ = ZoneInfo("Europe/Madrid")
SLEEP_HOURS = "22:00-07:00 Europe/Madrid"

DEFAULTS = {"poll_seconds": 60, "hours_back": 24, "tenant": "MERABYTES", "notify_on_same_set": False, "open_only": True, "drop_files": False}

_started = False


def _cfg() -> dict:
    cfg = dict(DEFAULTS)
    try:
        cfg.update(json.loads(Path(CONFIG_PATH).read_text()))
    except FileNotFoundError:
        pass
    if os.environ.get("S1_POLL_SECONDS"):
        cfg["poll_seconds"] = int(os.environ["S1_POLL_SECONDS"])
    cfg["poll_seconds"] = max(15, int(cfg.get("poll_seconds") or 60))
    cfg["hours_back"] = max(1, int(cfg.get("hours_back") or 24))
    cfg["notify_on_same_set"] = bool(cfg.get("notify_on_same_set"))
    cfg["open_only"] = bool(cfg.get("open_only", True))
    cfg["drop_files"] = bool(cfg.get("drop_files"))
    cfg["tenant"] = cfg.get("tenant") or "MERABYTES"
    return cfg


def _hashed_id() -> str:
    hx = hashlib.sha256(f"{AGENT_ID}\0{LOCAL_ID}".encode()).hexdigest()
    variant = format((int(hx[16], 16) & 3) | 8, "x")
    return f"{hx[:8]}-{hx[8:12]}-5{hx[13:16]}-{variant}{hx[17:20]}-{hx[20:32]}"


def _load_keys() -> dict:
    with open(KEYS_PATH) as f:
        return json.load(f).get("keys") or {}


def _resolve_aid() -> str:
    keys = _load_keys()
    for cand in (LOCAL_ID, _hashed_id()):
        if cand in keys:
            return cand
    for k in keys:
        if "s1-new-threat" in k or "fe44ca98" in k:
            return k
    raise RuntimeError("webhook key missing for s1-new-threat-dfir")


def _post_webhook(payload: dict) -> int:
    ids = payload.get("threat_ids") or []
    if not ids:
        logger.info("s1-watch skip webhook: no last-24h non-FP ids")
        return 0
    aid = _resolve_aid()
    key = _load_keys()[aid]
    url = f"{BACKEND.rstrip('/')}/automations/webhook/{aid}"
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "User-Agent": "s1-mcp-watch/1",
        },
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as e:
        return int(e.code)


def _drop_file(payload: dict) -> None:
    Path(DROP_DIR).mkdir(parents=True, exist_ok=True)
    name = f"open-{int(time.time())}.json"
    path = Path(DROP_DIR) / name
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload))
    tmp.replace(path)


def _write_queue(threats: list[dict]) -> None:
    """Canonical open-queue file. Empty when nothing is open. Skip rewrite if unchanged."""
    path = Path(QUEUE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    incidents = []
    ids = []
    for t in threats:
        tid = t.get("id")
        if not tid:
            continue
        ids.append(tid)
        incidents.append({
            "id": tid,
            "name": t.get("threatName"),
            "storyline": t.get("storyline"),
            "status": t.get("incidentStatus"),
            "analyst_verdict": t.get("analystVerdict"),
            "host": t.get("agentComputerName"),
            "user": t.get("processUser"),
        })
    body = {
        "threat_ids": ids,
        "count": len(ids),
        "incidents": incidents,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    new = json.dumps(body, sort_keys=True)
    try:
        if path.exists() and path.read_text() == new:
            return
    except OSError:
        pass
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(new)
    tmp.replace(path)


def _madrid_meta(created_at: str) -> tuple[str, bool]:
    try:
        dt = datetime.fromisoformat((created_at or "").replace("Z", "+00:00")).astimezone(MADRID_TZ)
    except Exception:
        return "", False
    sleep = dt.hour >= 22 or dt.hour < 7
    return dt.isoformat(), sleep


def _sensitive_blob(t: dict) -> bool:
    blob = " ".join(str(t.get(k) or "") for k in (
        "threatName", "maliciousProcessArguments", "originatorProcess",
        "initiatedByDescription", "processUser",
    )).lower()
    needles = (
        "powershell", "pwsh", ".bat", ".cmd", "cmd.exe", "sshd", "failed login",
        "ninja", "teamviewer", "anydesk", "screenconnect", "splashtop",
        "meshagent", "rmm", "rdp",
    )
    return any(n in blob for n in needles)


def _compact(t: dict) -> dict:
    return {k: t.get(k) for k in (
        "id", "threatName", "storyline", "processUser", "agentComputerName",
        "createdAt", "incidentStatus", "analystVerdict", "engines",
        "originatorProcess", "initiatedByDescription", "maliciousProcessArguments",
        "mitigationStatus",
    )}


def _last24h_not_fp(s1, hours: int, open_only: bool = True) -> list[dict]:
    extra = s1.get_threats(limit=100, sort_order="desc") or []
    cut = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = []
    for t in extra:
        tid = t.get("id")
        if not tid:
            continue
        ca = t.get("createdAt") or ""
        try:
            dt = datetime.fromisoformat(ca.replace("Z", "+00:00"))
        except Exception:
            continue
        if dt < cut:
            continue
        verdict = (t.get("analystVerdict") or "").lower()
        status = (t.get("incidentStatus") or "").lower()
        if verdict == "false_positive":
            continue
        if open_only and status != "unresolved":
            continue
        if not verdict and status == "resolved":
            continue
        rows.append(_compact(t))
    return rows


def _tick(cfg: dict, last_ids: tuple[str, ...]) -> tuple[str, ...]:
    from helpers.s1_factory import resolve_s1_helper

    s1 = resolve_s1_helper(cfg["tenant"])
    all_threats = _last24h_not_fp(s1, cfg["hours_back"], open_only=cfg.get("open_only", True))
    open_ids = tuple(sorted(t["id"] for t in all_threats if t.get("id")))
    try:
        _write_queue(all_threats)
    except Exception:
        logger.exception("s1-watch queue file write failed")
    if not all_threats:
        logger.info("s1-watch empty")
        Path(STATE_PATH).write_text("[]")
        return ()
    new_ids = [i for i in open_ids if i not in set(last_ids)]
    if not new_ids and not cfg.get("notify_on_same_set"):
        logger.info("s1-watch no new ids count=%s", len(all_threats))
        Path(STATE_PATH).write_text(json.dumps(list(open_ids)))
        return open_ids
    threats = [t for t in all_threats if t.get("id") in set(new_ids)]
    ids = tuple(sorted(new_ids))
    incidents = []
    lines = []
    for t in threats:
        madrid, sleep = _madrid_meta(t.get("createdAt") or "")
        sensitive = _sensitive_blob(t)
        inc = {
            "id": t.get("id"),
            "name": t.get("threatName"),
            "storyline": t.get("storyline"),
            "status": t.get("incidentStatus"),
            "analyst_verdict": t.get("analystVerdict"),
            "host": t.get("agentComputerName"),
            "user": t.get("processUser"),
            "mitigation": t.get("mitigationStatus"),
            "engines": t.get("engines"),
            "cmdline": t.get("maliciousProcessArguments"),
            "parent": t.get("originatorProcess"),
            "initiated_by": t.get("initiatedByDescription"),
            "created_at": t.get("createdAt"),
            "created_at_madrid": madrid,
            "sleep_hours": sleep,
            "sleep_hours_window": SLEEP_HOURS,
            "sensitive_rmm_ps_batch_sshd": sensitive,
            "auto_fp_blocked": bool(sleep and sensitive),
        }
        incidents.append(inc)
        lines.append(
            "New incident id={id} name={name} storyline={storyline} status={status} "
            "verdict={analyst_verdict} host={host} user={user} created_at={created_at} "
            "created_at_madrid={created_at_madrid} sleep_hours={sleep_hours} "
            "auto_fp_blocked={auto_fp_blocked} "
            "(do not auto-FP RMM/PowerShell/batch/sshd when sleep_hours is true, "
            "22:00-07:00 Europe/Madrid on incident created_at, not wall clock now)".format(**inc)
        )
    payload = {
        "source": "s1-mcp-watch",
        "event": "s1_last24h_not_false_positive",
        "hours_back": cfg["hours_back"],
        "count": len(threats),
        "threat_ids": list(ids),
        "incidents": incidents,
        "message": "\n".join(lines),
        "threats": threats,
    }
    if cfg.get("drop_files"):
        try:
            _drop_file(payload)
        except Exception:
            logger.exception("s1-watch drop failed")
    Path(STATE_PATH).write_text(json.dumps(list(open_ids)))
    status = _post_webhook(payload)
    logger.info("s1-watch webhook status=%s new=%s open=%s", status, list(ids), list(open_ids))
    return open_ids


def _loop() -> None:
    last: tuple[str, ...] = ()
    try:
        last = tuple(json.loads(Path(STATE_PATH).read_text()))
    except Exception:
        last = ()
    logger.info("s1-watch thread start config=%s", CONFIG_PATH)
    while True:
        cfg = _cfg()
        try:
            last = _tick(cfg, last)
        except Exception:
            logger.exception("s1-watch tick error")
        time.sleep(cfg["poll_seconds"])


def start_watch_thread() -> None:
    global _started
    if _started:
        return
    _started = True
    t = threading.Thread(target=_loop, name="s1-watch", daemon=True)
    t.start()
    logger.info("s1-watch daemon thread started")
