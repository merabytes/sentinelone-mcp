#!/usr/bin/env python3
"""
purple_ai.py — SentinelOne Purple AI via Playwright (headful, playwright-core).
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import select
import shutil
import subprocess
import signal
import sys
import threading
import time
import uuid
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
PURPLE_DISPLAY = ":6"
PURPLE_XAUTHORITY = "/tmp/s1_xauth_display6"
SESSION_SEED_DIR = "/tmp/s1_purple_merabytes"
# Inner ConversationFeed wait after send (login/MFA/nav is extra).
# Old: 90s default — too tight once the save-password overlay stalled headed fill/send.
# New: 240s inner wait so fill/send + Purple generation can finish under headed Chrome.
PURPLE_ASK_TIMEOUT = 240
CHROME_PW_DISABLE_ARGS = [
    "--disable-save-password-bubble",
    "--password-store=basic",
    "--disable-features=PasswordManager,PasswordLeakDetection,PasswordManagerOnboarding,PasswordCheck,PasswordImport",
]

# Unique profile dirs: /tmp/s1_purple_{slug}_{mcp_pid}_{uuid8}
# Must still die if FastMCP cancels, stdio EOF, or the MCP process is SIGKILL'd.
_stdio_watchdog_started = False
_close_lock = threading.Lock()
_orig_parent_pid = os.getppid()
_signal_prev: dict[int, object] = {}


def _is_chrome_cmd(cmd: str) -> bool:
    low = cmd.lower()
    if "chrome" not in low and "chromium" not in low:
        return False
    # Never match the killer's own shell / python wrappers.
    first = (cmd.split("\0")[0] if "\0" in cmd else cmd).strip()
    base = os.path.basename(first.split()[0]) if first.split() else ""
    if base in {"bash", "sh", "python", "python3", "rg", "lsof"}:
        return False
    return True


def chrome_pids_for_profile(user_data_dir: str) -> list[int]:
    """PIDs of Chromium using this exact --user-data-dir (not box-chrome / Xvfb)."""
    marker = f"--user-data-dir={user_data_dir}"
    found: list[int] = []
    try:
        proc_root = Path("/proc")
        for ent in proc_root.iterdir():
            if not ent.name.isdigit():
                continue
            try:
                raw = (ent / "cmdline").read_bytes()
            except (OSError, PermissionError):
                continue
            cmd = raw.replace(b"\0", b" ").decode("utf-8", "replace")
            if marker not in cmd:
                continue
            if not _is_chrome_cmd(cmd):
                continue
            found.append(int(ent.name))
    except OSError:
        pass
    return found


def _cdp_browser_close(context, page) -> None:
    """Ask Chromium to exit via CDP so headed windows do not outlive Playwright."""
    if context is None:
        return
    try:
        target = page
        if target is None and getattr(context, "pages", None):
            target = context.pages[0] if context.pages else None
        if target is None:
            return
        session = context.new_cdp_session(target)
        session.send("Browser.close")
        logger.info("CDP Browser.close sent")
    except Exception as e:
        logger.warning("CDP Browser.close failed: %s", e)


def kill_profile_chrome(user_data_dir: str, wait_s: float = 3.0) -> list[int]:
    """SIGTERM then SIGKILL Chromium bound to a unique Purple profile."""
    if not user_data_dir or user_data_dir.rstrip("/") == SESSION_SEED_DIR.rstrip("/"):
        return []
    pids = chrome_pids_for_profile(user_data_dir)
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + wait_s
    while time.time() < deadline:
        alive = chrome_pids_for_profile(user_data_dir)
        if not alive:
            return pids
        time.sleep(0.15)
    leftover = chrome_pids_for_profile(user_data_dir)
    for pid in leftover:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return pids


def _rmtree_unique_profile(user_data_dir: str) -> None:
    if not user_data_dir:
        return
    path = Path(user_data_dir)
    seed = Path(SESSION_SEED_DIR)
    try:
        if path.resolve() == seed.resolve():
            return
    except OSError:
        return
    if path.parent != Path("/tmp"):
        return
    if not path.name.startswith("s1_purple_"):
        return
    # Seed is s1_purple_merabytes; unique runs have _{pid}_{uuid} suffix.
    if path.name == "s1_purple_merabytes":
        return
    shutil.rmtree(path, ignore_errors=True)


def _owned_unique_profiles(owner_pid: int) -> list[Path]:
    needle = f"_{owner_pid}_"
    out: list[Path] = []
    try:
        for d in Path("/tmp").iterdir():
            if not d.is_dir():
                continue
            if not d.name.startswith("s1_purple_"):
                continue
            if needle not in d.name:
                continue
            if d.name == "s1_purple_merabytes":
                continue
            out.append(d)
    except OSError:
        pass
    return out


def force_close_owned_profiles(owner_pid: int | None = None) -> None:
    """Close Playwright session and kill any unique-profile Chromium for this MCP pid."""
    owner_pid = owner_pid or os.getpid()
    with _close_lock:
        sess = globals().get("_session")
        if sess is not None:
            try:
                sess.close()
            except Exception:
                logger.warning("force_close: session.close failed", exc_info=True)
            globals()["_session"] = None
            globals()["_session_tenant"] = None
        for d in _owned_unique_profiles(owner_pid):
            kill_profile_chrome(str(d))
            _rmtree_unique_profile(str(d))


_REAPER_PY = r"""
import os, shutil, signal, sys, time
from pathlib import Path

owner_pid = int(sys.argv[1])
user_data_dir = sys.argv[2]
seed = sys.argv[3]
marker = "--user-data-dir=" + user_data_dir


def chrome_pids():
    found = []
    try:
        for ent in Path("/proc").iterdir():
            if not ent.name.isdigit():
                continue
            try:
                raw = (ent / "cmdline").read_bytes()
            except (OSError, PermissionError):
                continue
            cmd = raw.replace(b"\0", b" ").decode("utf-8", "replace")
            if marker not in cmd:
                continue
            low = cmd.lower()
            if "chrome" not in low and "chromium" not in low:
                continue
            first = cmd.strip().split()[:1]
            base = os.path.basename(first[0]) if first else ""
            if base in {"bash", "sh", "python", "python3", "rg", "lsof"}:
                continue
            found.append(int(ent.name))
    except OSError:
        pass
    return found


def kill_all():
    pids = chrome_pids()
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + 3
    while time.time() < deadline and chrome_pids():
        time.sleep(0.15)
    for pid in chrome_pids():
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def rmtree_unique():
    path = Path(user_data_dir)
    try:
        if path.resolve() == Path(seed).resolve():
            return
    except OSError:
        return
    if path.parent != Path("/tmp") or not path.name.startswith("s1_purple_"):
        return
    if path.name == "s1_purple_merabytes":
        return
    shutil.rmtree(path, ignore_errors=True)


seen = False
while True:
    try:
        os.kill(owner_pid, 0)
        alive = True
    except OSError:
        alive = False
    chrome = chrome_pids()
    if chrome:
        seen = True
    if not alive:
        kill_all()
        rmtree_unique()
        break
    if seen and not chrome:
        break
    time.sleep(1)
"""


def spawn_orphan_reaper(owner_pid: int, user_data_dir: str) -> int:
    """Detached helper: if this MCP pid dies, still kill unique-profile Chromium."""
    helper = Path(__file__).resolve().parent / "helpers" / "purple_orphan_reaper.py"
    if helper.is_file():
        argv = [sys.executable, str(helper), str(owner_pid), user_data_dir]
    else:
        argv = [sys.executable, "-c", _REAPER_PY, str(owner_pid), user_data_dir, SESSION_SEED_DIR]
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        return proc.pid
    except OSError as e:
        logger.warning("orphan reaper spawn failed: %s", e)
        return -1


def _stdio_watchdog_loop() -> None:
    try:
        fd = sys.stdin.fileno()
    except Exception:
        return
    poller = select.poll()
    try:
        poller.register(fd, select.POLLHUP | select.POLLERR | select.POLLNVAL)
    except Exception:
        return
    while True:
        try:
            ev = poller.poll(1000)
        except Exception:
            break
        if not ev:
            continue
        logger.warning("MCP stdio hung up; force-closing Purple Chromium")
        try:
            force_close_owned_profiles()
        except Exception:
            logger.warning("stdio watchdog close failed", exc_info=True)
        break


def _prctl_parent_death_signal(sig: int = signal.SIGTERM) -> None:
    """Kernel: signal this MCP process if the stdio client/parent dies."""
    try:
        import ctypes
        import ctypes.util

        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return
        libc = ctypes.CDLL(libc_name, use_errno=True)
        PR_SET_PDEATHSIG = 1
        libc.prctl(PR_SET_PDEATHSIG, sig)
        if os.getppid() == 1:
            os.kill(os.getpid(), sig)
    except Exception:
        logger.debug("PR_SET_PDEATHSIG unavailable", exc_info=True)


def _on_orphan_signal(signum, frame) -> None:
    logger.warning("orphan-close signal %s — closing Purple Chromium", signum)
    try:
        force_close_owned_profiles()
    except Exception:
        pass
    prev = _signal_prev.get(signum)
    if callable(prev):
        try:
            prev(signum, frame)
            return
        except Exception:
            pass
    if signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        raise SystemExit(128 + int(signum))


def _parent_death_watchdog() -> None:
    while True:
        time.sleep(0.5)
        try:
            ppid = os.getppid()
        except Exception:
            ppid = 1
        if ppid == 1 or ppid != _orig_parent_pid:
            logger.warning(
                "MCP parent died (ppid=%s orig=%s) — closing Purple Chromium",
                ppid,
                _orig_parent_pid,
            )
            try:
                force_close_owned_profiles()
            except Exception:
                pass
            os._exit(0)


def _ensure_stdio_watchdog() -> None:
    global _stdio_watchdog_started
    if _stdio_watchdog_started:
        return
    _stdio_watchdog_started = True
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        try:
            _signal_prev[sig] = signal.getsignal(sig)
            signal.signal(sig, _on_orphan_signal)
        except Exception:
            logger.debug("cannot trap %s", sig, exc_info=True)
    _prctl_parent_death_signal()
    threading.Thread(
        target=_stdio_watchdog_loop,
        name="purple-stdio-watch",
        daemon=True,
    ).start()
    threading.Thread(
        target=_parent_death_watchdog,
        name="purple-parent-watch",
        daemon=True,
    ).start()
    logger.info("Purple orphan-close guards: atexit/stdio/parent-death/CDP")


def _atexit_close_purple() -> None:
    try:
        force_close_owned_profiles()
    except Exception:
        pass


atexit.register(_atexit_close_purple)


def _install_death_signals() -> None:
    """SIGTERM/HUP/INT + Linux parent-death: close Chromium even if FastMCP is gone."""
    def _on_signal(signum, _frame):
        logger.warning("Purple AI signal %s — force-closing Chromium", signum)
        try:
            force_close_owned_profiles()
        except Exception:
            pass
        raise SystemExit(128 + int(signum))

    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        try:
            signal.signal(sig, _on_signal)
        except Exception:
            pass
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(1, int(signal.SIGTERM))  # PR_SET_PDEATHSIG
        if os.getppid() == 1:
            force_close_owned_profiles()
    except Exception:
        pass


_install_death_signals()

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



def write_password_manager_off(user_data_dir: str) -> None:
    """Disable Chrome password manager in a unique profile *before* headed launch.

    Stops the "Save password?" overlay from covering Purple AI (fill/send).
    Merges into existing Default/Preferences (e.g. after seed copy).
    """
    root = Path(user_data_dir)
    default_dir = root / "Default"
    default_dir.mkdir(parents=True, exist_ok=True)

    def _merge(path: Path, updates: dict) -> None:
        data: dict = {}
        if path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8") or "{}")
                if isinstance(loaded, dict):
                    data = loaded
            except Exception:
                data = {}
        def deep(dst: dict, src: dict) -> dict:
            for k, v in src.items():
                if isinstance(v, dict) and isinstance(dst.get(k), dict):
                    deep(dst[k], v)
                else:
                    dst[k] = v
            return dst
        deep(data, updates)
        # Seed copies include HMAC macs; stale macs make Chrome discard our prefs.
        prot = data.get("protection")
        if isinstance(prot, dict):
            prot.pop("macs", None)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    prefs_updates = {
        "credentials_enable_service": False,
        "credentials_enable_autosignin": False,
        "profile": {
            "password_manager_enabled": False,
            "password_manager_leak_detection": False,
        },
        "password_manager": {
            "enable_saving": False,
            "saving_enabled2": False,
        },
        "autofill": {
            "profile_enabled": False,
            "credit_card_enabled": False,
        },
        "signin": {"allowed": False},
        "safebrowsing": {"enabled": False},
        "translate": {"enabled": False},
        "default_apps": "noinstall",
        "session": {"restore_on_startup": 5},
    }
    _merge(default_dir / "Preferences", prefs_updates)
    _merge(default_dir / "Secure Preferences", prefs_updates)
    # Master prefs Chromium also reads from Local State.
    _merge(
        root / "Local State",
        {
            "credentials_enable_service": False,
            "password_manager": {"enable_saving": False},
            "profile": {"password_manager_enabled": False},
        },
    )
    policy_dir = root / "policies" / "managed"
    policy_dir.mkdir(parents=True, exist_ok=True)
    (policy_dir / "s1_password_manager.json").write_text(
        json.dumps(
            {
                "PasswordManagerEnabled": False,
                "PasswordLeakDetectionEnabled": False,
                "AutofillAddressEnabled": False,
                "AutofillCreditCardEnabled": False,
                "BrowserSignin": 0,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    first_run = root / "First Run"
    if not first_run.exists():
        first_run.write_text("", encoding="utf-8")


def pin_purple_display() -> None:
    """Lock headed Chromium to SOC L2 desktop (:6)."""
    os.environ["DISPLAY"] = PURPLE_DISPLAY
    if Path(PURPLE_XAUTHORITY).exists():
        os.environ["XAUTHORITY"] = PURPLE_XAUTHORITY
    os.environ.setdefault("XDG_RUNTIME_DIR", "/tmp/xdg-runtime-box-6")


def format_purple_response(data: dict[str, Any]) -> str:
    if data.get("loading"):
        return ""
    if not (data.get("rowCount") or data.get("summary") or data.get("query")):
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
    """One-shot Playwright headful session for Purple AI (unique profile per run)."""

    def __init__(self, tenant_cfg: dict):
        self.tenant_cfg = tenant_cfg
        name = tenant_cfg.get("name", "unknown")
        creds = resolve_login(name)
        self.email = creds["email"]
        self.password = creds["password"]
        self.totp_secret = creds.get("totp", "")
        self.login_url = creds["url"]
        slug = name.lower().replace(" ", "_")
        run_id = f"{os.getpid()}_{uuid.uuid4().hex[:8]}"
        self.user_data_dir = f"/tmp/s1_purple_{slug}_{run_id}"
        self.playwright = None
        self.context = None
        self.page = None
        self.feed_count = 0
        self.ready = False
        self._reaper_pid = -1
        self._closed = False
        self._inst_lock = threading.Lock()

    def _seed_profile(self, dest: str) -> None:
        ignore = shutil.ignore_patterns(
            "SingletonLock",
            "SingletonCookie",
            "SingletonSocket",
            "lockfile",
            "DevToolsActivePort",
        )
        src = SESSION_SEED_DIR
        if not os.path.isdir(src):
            slug_src = dest.rsplit("_", 2)[0] if "_" in dest else ""
            if slug_src and os.path.isdir(slug_src) and slug_src != dest:
                src = slug_src
            else:
                os.makedirs(dest, exist_ok=True)
                return
        if os.path.abspath(src) == os.path.abspath(dest):
            os.makedirs(dest, exist_ok=True)
            return
        try:
            shutil.copytree(src, dest, ignore=ignore, dirs_exist_ok=True)
            logger.info("Copied Purple profile seed %s -> %s", src, dest)
        except Exception as e:
            logger.warning("Profile seed copy failed (%s); using empty dir %s", e, dest)
            os.makedirs(dest, exist_ok=True)

    def _user_dir(self) -> str:
        os.makedirs(self.user_data_dir, exist_ok=True)
        return self.user_data_dir

    def _start_browser(self) -> None:
        if self.context is not None:
            return
        pin_purple_display()
        dest = self.user_data_dir
        if not os.path.isdir(dest) or not os.listdir(dest):
            self._seed_profile(dest)
        write_password_manager_off(dest)
        _ensure_stdio_watchdog()
        owner = os.getpid()
        try:
            (Path(dest) / ".s1_purple_owner").write_text(str(owner), encoding="utf-8")
        except OSError as e:
            logger.warning("Could not write owner pid file: %s", e)
        # Reaper before launch so SIGKILL during launch still kills Chromium.
        self._reaper_pid = spawn_orphan_reaper(owner, dest)
        logger.info(
            "Launching Playwright (headful) DISPLAY=%s XAUTHORITY=%s user_data_dir=%s (password manager off)",
            os.environ.get("DISPLAY"),
            os.environ.get("XAUTHORITY"),
            dest,
        )
        self.playwright = sync_playwright().start()
        self.context = self.playwright.chromium.launch_persistent_context(
            user_data_dir=self._user_dir(),
            headless=False,
            no_viewport=True,
            env={
                **os.environ,
                "DISPLAY": PURPLE_DISPLAY,
                "XAUTHORITY": os.environ.get("XAUTHORITY", PURPLE_XAUTHORITY),
            },
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                *CHROME_PW_DISABLE_ARGS,
            ],
        )
        self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
        self._closed = False
        logger.info(
            "Purple Chromium launched; owner_pid=%s chrome_pids=%s reaper=%s",
            owner,
            chrome_pids_for_profile(dest),
            self._reaper_pid,
        )

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
        start = time.time()
        deadline = start + timeout
        status_interval = 5.0
        last_status = start
        logger.info("Procesando consulta con Purple AI...")
        while time.time() < deadline:
            current = self._count_feed_items()
            if current > prev_count:
                data = self._extract_response()
                if not data.get("loading") and (data.get("query") or data.get("summary") or data.get("rowCount")):
                    text = format_purple_response(data)
                    if text:
                        logger.info("Respuesta completada (%.1fs)", time.time() - start)
                        return data, text, current
            now = time.time()
            if now - last_status >= status_interval:
                logger.info(
                    "Procesando... (%ds transcurridos, timeout %ds)",
                    int(now - start),
                    timeout,
                )
                last_status = now
            time.sleep(0.4)

        logger.warning("Timeout (%ds) esperando respuesta de Purple AI", timeout)
        data = self._extract_response()
        text = format_purple_response(data) or "[Sin respuesta tras timeout]"
        return data, text, self._count_feed_items()

    def ensure_ready(self) -> None:
        if self.ready and self.page is not None:
            return
        self._start_browser()
        from helpers.purple_cookies import persist_cookies, try_resume
        if try_resume(self.tenant_cfg, self.context, self.page):
            self.feed_count = self._count_feed_items()
            self.ready = True
            return
        self._login_and_navigate()
        try:
            persist_cookies(self.tenant_cfg, self.context)
        except Exception as e:
            logger.warning("Could not persist Purple cookies: %s", e)

    def ask(self, query: str, timeout: int = PURPLE_ASK_TIMEOUT) -> dict[str, Any]:
        self.ensure_ready()
        assert self.page is not None

        input_el = self.page.locator(INPUT_SEL)
        input_el.wait_for(state="visible", timeout=10000)
        self.feed_count = self._count_feed_items()

        input_el.click()
        input_el.fill(query)

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
            raise RuntimeError("Purple composer send button not found; refusing extra Enter")

        data, text, self.feed_count = self._wait_for_response(self.feed_count, timeout)
        return {"query": query, "response": data, "formatted": text}

    def close(self) -> None:
        with self._inst_lock:
            if self._closed and self.context is None and self.playwright is None:
                kill_profile_chrome(self.user_data_dir)
                _rmtree_unique_profile(self.user_data_dir)
                return
            self._closed = True
            logger.info("Cerrando navegador de Purple AI...")
            try:
                _cdp_browser_close(self.context, self.page)
            except Exception as e:
                logger.warning("CDP close: %s", e)
            if self.context:
                try:
                    self.context.close()
                except Exception as e:
                    logger.warning("context.close: %s", e)
                self.context = None
            if self.playwright:
                try:
                    self.playwright.stop()
                except Exception as e:
                    logger.warning("playwright.stop: %s", e)
                self.playwright = None
            self.page = None
            self.ready = False
            # Playwright close can fail if stdio/CDP is already dead — still SIGTERM the tree.
            leftover = kill_profile_chrome(self.user_data_dir)
            if leftover:
                logger.info("Killed leftover Purple Chromium pids %s for %s", leftover, self.user_data_dir)
            _rmtree_unique_profile(self.user_data_dir)
            logger.info("Navegador cerrado")


_session: PurpleAISession | None = None
_session_tenant: str | None = None


def reset_purple_session() -> None:
    global _session, _session_tenant
    if _session:
        _session.close()
    _session = None
    _session_tenant = None


def ask_purple_ai(query: str, tenant_name: str | None = None, timeout: int = PURPLE_ASK_TIMEOUT) -> dict[str, Any]:
    """One prompt, unique profile, close Chromium as soon as the feed item is complete."""
    global _session, _session_tenant
    reset_purple_session()
    tenant = resolve_tenant(tenant_name)
    name = tenant.get("name", "unknown")
    _session = PurpleAISession(tenant)
    _session_tenant = name
    try:
        return _session.ask(query, timeout=timeout)
    finally:
        # Respuesta recibida (o timeout) — cerrar el navegador automáticamente.
        _session.close()
        _session = None
        _session_tenant = None
