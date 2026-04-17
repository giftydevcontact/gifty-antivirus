"""
Gifty Antivirus — PREMIUM PLAN v4.0
Changelog from v3:
  • Complete UI overhaul — refined dark glassmorphism aesthetic
  • Smooth page slide/fade transitions
  • Toast notification system (non-blocking bottom-right alerts)
  • Animated stat counters (count-up on change)
  • Fixed ToggleSwitch: animations run on EVERY toggle (settings + RT)
  • Autostart on Windows boot (Registry, toggleable in Settings)
  • Desktop shortcut created automatically on first run
  • Ransomware Shield: actively monitors Desktop/Docs for rapid changes & ransom extensions
  • USB Protection: detects new removable drives, auto-scans root
  • Memory Scan: periodically scans process list for suspicious names
  • Download Protection: watches Downloads for ALL file types (broader than file_monitor)
  • Richer PulseShield with particle rings
  • Hover glow on stat cards
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys
import hashlib
import json
import threading
import time
import datetime
import struct
import socket
import math
import subprocess
from pathlib import Path

import winreg
import uuid

# ═══════════════════════════════════════════════════════════════════
#  TELEMETRY  —  anonymous, opt-in, feature-usage only
# ═══════════════════════════════════════════════════════════════════
#
#  WHAT IS COLLECTED  (only when the user has opted in via the
#  first-run consent dialog or Settings → Privacy):
#    • An anonymous install ID (random UUID, NOT tied to hostname or user)
#    • A short-lived per-launch session ID
#    • App version (e.g. "4.0")
#    • Coarse OS family (e.g. "windows-10", "windows-11")
#    • Feature usage events (e.g. "scan_started", "page_visited")
#    • Aggregate scan stats (duration, files scanned, threat count)
#    • Threat category / severity (NOT file paths or names)
#
#  WHAT IS NEVER COLLECTED:
#    • Hostname, username, IP, MAC address
#    • File paths, file names, file contents
#    • Documents, browsing history, personal data
#    • Specific threat file locations
#
#  Users can disable telemetry at any time in Settings → Privacy.
#  Disabling rotates the install ID so the previous identity is severed.
#  Deletion of stored data is handled at the website (see PRIVACY.md).
# ═══════════════════════════════════════════════════════════════════

# NOTE for the developer:
# The Firestore project below MUST have security rules that:
#   1. Allow `create` on /events and /detections only (no read, no delete).
#   2. Allow `create`/`update` on /installs only on documents matching
#      the install_id field (no read, no delete).
# A starter ruleset is shipped in firestore.rules.
_FB_PROJECT  = "giftyantivirus"
_FB_URL      = f"https://firestore.googleapis.com/v1/projects/{_FB_PROJECT}/databases/(default)/documents"
_APP_VERSION = "4.0"
_INSTALL_ID  = None
_SESSION_ID  = None

def _install_id_path():
    return os.path.join(os.path.expanduser("~"), ".gifty_av_install_id")

def _get_install_id():
    """Anonymous, rotatable install ID — NOT tied to hostname or user."""
    global _INSTALL_ID
    if _INSTALL_ID:
        return _INSTALL_ID
    p = _install_id_path()
    try:
        if os.path.exists(p):
            with open(p) as f:
                _INSTALL_ID = f.read().strip()
        if not _INSTALL_ID:
            _INSTALL_ID = uuid.uuid4().hex
            with open(p, "w") as f:
                f.write(_INSTALL_ID)
    except Exception:
        _INSTALL_ID = uuid.uuid4().hex
    return _INSTALL_ID

def reset_install_id():
    """Burn the current anonymous identity. Called when the user revokes
    telemetry consent so a future opt-in starts fresh."""
    global _INSTALL_ID
    _INSTALL_ID = None
    try:
        os.remove(_install_id_path())
    except Exception:
        pass

def _get_session_id():
    global _SESSION_ID
    if _SESSION_ID is None:
        _SESSION_ID = uuid.uuid4().hex[:12]
    return _SESSION_ID

def _os_family():
    """Coarse OS bucket — e.g. 'windows-11'. No build numbers, no locale."""
    if sys.platform != "win32":
        return sys.platform
    try:
        ver = sys.getwindowsversion()
        if ver.major == 10 and ver.build >= 22000:
            return "windows-11"
        if ver.major == 10:
            return "windows-10"
        return f"windows-{ver.major}"
    except Exception:
        return "windows"

# ── Consent gate ──────────────────────────────────────────────────────
# The GiftyAV instance installs a callable that returns the *current*
# value of settings["send_telemetry"]. Until it's installed (or if the
# user hasn't opted in), every send is a no-op.
_CONSENT_GETTER = lambda: False

def set_telemetry_consent_getter(fn):
    global _CONSENT_GETTER
    _CONSENT_GETTER = fn

def _has_consent():
    try:
        return bool(_CONSENT_GETTER())
    except Exception:
        return False

# ── Firestore plumbing ────────────────────────────────────────────────
def _to_fs(v):
    if isinstance(v, bool):  return {"booleanValue": v}
    if isinstance(v, int):   return {"integerValue": str(v)}
    if isinstance(v, float): return {"doubleValue": v}
    if isinstance(v, str):   return {"stringValue": v}
    if isinstance(v, dict):  return {"mapValue": {"fields": {k: _to_fs(vv) for k, vv in v.items()}}}
    if isinstance(v, list):  return {"arrayValue": {"values": [_to_fs(i) for i in v]}}
    return {"stringValue": str(v)}

def _fb_post(collection, doc_id, data):
    """PATCH /collection/doc_id — no-op when consent is missing."""
    if not _has_consent():
        return
    def _do():
        try:
            import urllib.request, json as _json
            fields = {k: _to_fs(v) for k, v in data.items()}
            body = _json.dumps({"fields": fields}).encode()
            url = f"{_FB_URL}/{collection}/{doc_id}"
            req = urllib.request.Request(url, data=body, method="PATCH",
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            pass
    threading.Thread(target=_do, daemon=True).start()

def _fb_add(collection, data):
    """POST /collection (auto-ID) — no-op when consent is missing."""
    if not _has_consent():
        return
    def _do():
        try:
            import urllib.request, json as _json
            fields = {k: _to_fs(v) for k, v in data.items()}
            body = _json.dumps({"fields": fields}).encode()
            url = f"{_FB_URL}/{collection}"
            req = urllib.request.Request(url, data=body, method="POST",
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            pass
    threading.Thread(target=_do, daemon=True).start()

# ── Public telemetry API ──────────────────────────────────────────────
def tel_session_start():
    """Record an app launch + an anonymous install heartbeat."""
    if not _has_consent():
        return
    iid = _get_install_id()
    _fb_post("installs", iid, {
        "install_id": iid,
        "version":    _APP_VERSION,
        "os":         _os_family(),
        "last_seen":  datetime.datetime.now().isoformat(),
    })
    tel_event("session_start")

def tel_event(name, **props):
    """Record a feature-usage event.

    Pass ONLY non-identifying properties (strings/numbers/bools).
    Anything else is silently dropped to keep events safe-by-default."""
    if not _has_consent():
        return
    payload = {
        "install_id": _get_install_id(),
        "session_id": _get_session_id(),
        "event":      name,
        "version":    _APP_VERSION,
        "os":         _os_family(),
        "time":       datetime.datetime.now().isoformat(),
    }
    if props:
        payload["props"] = {k: v for k, v in props.items()
                            if isinstance(v, (str, int, float, bool))}
    _fb_add("events", payload)

def tel_detection(category, severity, source="scan"):
    """Record an aggregate detection — NEVER includes file path or name."""
    if not _has_consent():
        return
    _fb_add("detections", {
        "install_id": _get_install_id(),
        "category":   category,
        "severity":   severity,
        "source":     source,
        "version":    _APP_VERSION,
        "os":         _os_family(),
        "time":       datetime.datetime.now().isoformat(),
    })

# ── Backwards-compatible shims for existing call sites ───────────────
# These intentionally drop the file path / threat name so the change
# can't accidentally regress to leaking PII.
def fb_ping_user():
    tel_session_start()

def fb_report_detection(threat_name, category, severity, filepath, source="scan"):
    tel_detection(category, severity, source)

# ═══════════════════════════════════════════════════════════════════
#  AUTO-UPDATER  —  GitHub Releases
# ═══════════════════════════════════════════════════════════════════
#
#  HOW IT WORKS
#  ------------
#  1. On launch (and on demand from Settings), fetch the latest
#     release JSON from the GitHub REST API.
#  2. If the release tag (e.g. "v4.1") is newer than _APP_VERSION,
#     surface a non-blocking notification.
#  3. When the user accepts, download the new "gifty_av.py" asset
#     to %TEMP%, verify it parses as Python (basic sanity check),
#     and write a small elevated batch script that:
#         a) waits for the current process to exit
#         b) copies the new file over the installed one
#         c) relaunches the app via launcher.vbs
#  4. UAC prompts once (because the install dir is in Program Files).
#
#  HOW TO PUBLISH AN UPDATE  (developer)
#  -------------------------------------
#  1. Bump _APP_VERSION below to the new version (e.g. "4.1").
#  2. git tag v4.1 && git push --tags
#  3. On GitHub: Releases → Draft new release → choose tag v4.1
#     → upload the new gifty_av.py as an attached asset
#     → write a changelog in the body → Publish.
#  4. Existing installs see the update on next launch.
#
#  CONFIGURE THE REPO BELOW.
# ═══════════════════════════════════════════════════════════════════
_GH_REPO         = "giftydevcontact/gifty-antivirus"
_GH_ASSET_NAME   = "gifty_av.py"
_GH_API          = f"https://api.github.com/repos/{_GH_REPO}/releases/latest"
_UPDATE_INTERVAL = 24 * 60 * 60   # seconds between background checks

def _ver_tuple(v):
    """Convert '4.1', 'v4.1.2', '4.1.0-beta' → comparable tuple."""
    if not v: return (0, 0, 0)
    v = str(v).strip().lstrip("vV")
    # Drop any prerelease/build suffix for ordering purposes
    for sep in ("-", "+", " "):
        if sep in v: v = v.split(sep, 1)[0]
    parts = []
    for p in v.split("."):
        try: parts.append(int(p))
        except ValueError: parts.append(0)
    while len(parts) < 3: parts.append(0)
    return tuple(parts[:3])

def _is_newer(remote, local):
    return _ver_tuple(remote) > _ver_tuple(local)

class UpdateError(Exception):
    pass

class GitHubUpdater:
    """Stateless helper — never touches disk until apply() is called."""

    def __init__(self, repo=_GH_REPO, asset=_GH_ASSET_NAME):
        self.repo = repo
        self.asset = asset
        self.api_url = f"https://api.github.com/repos/{repo}/releases/latest"

    def fetch_latest(self, timeout=8):
        """Return dict {version, tag, notes, asset_url, size, published}.

        Raises UpdateError on network/parse failure or missing asset."""
        import urllib.request, json as _json
        try:
            req = urllib.request.Request(self.api_url, headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"GiftyAntivirus/{_APP_VERSION}",
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = _json.loads(r.read().decode("utf-8"))
        except Exception as e:
            raise UpdateError(f"Could not reach GitHub: {e}")

        tag = data.get("tag_name", "")
        if not tag:
            raise UpdateError("Release has no tag.")

        # Find the .py asset
        asset_url = None
        size = 0
        for a in data.get("assets", []) or []:
            if a.get("name") == self.asset:
                asset_url = a.get("browser_download_url")
                size = int(a.get("size", 0))
                break
        if not asset_url:
            raise UpdateError(
                f"Release '{tag}' has no '{self.asset}' asset attached.")

        return {
            "version":   tag.lstrip("vV"),
            "tag":       tag,
            "notes":     data.get("body", "") or "(no release notes)",
            "asset_url": asset_url,
            "size":      size,
            "published": data.get("published_at", ""),
        }

    def download(self, url, dest, progress_cb=None, timeout=30):
        """Stream-download `url` to `dest`. Calls progress_cb(done, total)."""
        import urllib.request
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": f"GiftyAntivirus/{_APP_VERSION}",
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                total = int(r.headers.get("Content-Length", 0) or 0)
                done = 0
                with open(dest, "wb") as f:
                    while True:
                        chunk = r.read(64 * 1024)
                        if not chunk: break
                        f.write(chunk)
                        done += len(chunk)
                        if progress_cb:
                            try: progress_cb(done, total)
                            except Exception: pass
        except Exception as e:
            try: os.remove(dest)
            except Exception: pass
            raise UpdateError(f"Download failed: {e}")

    @staticmethod
    def sanity_check(path):
        """Refuse to install something that isn't a parseable Python file
        or that's suspiciously small."""
        try:
            sz = os.path.getsize(path)
        except OSError as e:
            raise UpdateError(f"Cannot read downloaded file: {e}")
        if sz < 10_000:
            raise UpdateError(
                f"Downloaded file is suspiciously small ({sz} bytes). Aborting.")
        try:
            import ast
            with open(path, "r", encoding="utf-8") as f:
                ast.parse(f.read())
        except SyntaxError as e:
            raise UpdateError(f"Downloaded file is not valid Python: {e}")
        except Exception as e:
            raise UpdateError(f"Could not validate download: {e}")

    @staticmethod
    def file_sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(64 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def apply(staged_path, target_path, launcher_path):
        """Spawn an elevated batch that swaps the file and relaunches.

        The current process must exit shortly after this returns."""
        if not os.path.exists(staged_path):
            raise UpdateError("Staged update missing.")
        if not target_path or not launcher_path:
            raise UpdateError("Target/launcher path unknown.")

        tmp = os.environ.get("TEMP") or os.path.expanduser("~")
        bat = os.path.join(tmp, "gifty_av_update.bat")
        log = os.path.join(tmp, "gifty_av_update.log")

        # Quote everything carefully — paths may contain spaces.
        script = (
            "@echo off\r\n"
            "setlocal\r\n"
            f'echo [%date% %time%] starting update > "{log}"\r\n'
            # Wait for the running app to exit cleanly.
            'timeout /t 2 /nobreak > nul\r\n'
            # Try the copy up to 5 times in case the file is briefly locked.
            "set TRIES=0\r\n"
            ":retry\r\n"
            f'copy /Y "{staged_path}" "{target_path}" >> "{log}" 2>&1\r\n'
            "if %ERRORLEVEL%==0 goto done\r\n"
            "set /a TRIES+=1\r\n"
            "if %TRIES% lss 5 (timeout /t 1 /nobreak > nul & goto retry)\r\n"
            f'echo Update failed after %TRIES% retries. >> "{log}"\r\n'
            "exit /b 1\r\n"
            ":done\r\n"
            f'echo Update applied. >> "{log}"\r\n'
            # Relaunch through the existing VBS launcher (no console window).
            f'start "" "%SystemRoot%\\System32\\wscript.exe" "{launcher_path}"\r\n'
            # Clean up.
            f'del /f /q "{staged_path}" >nul 2>&1\r\n'
            "(goto) 2>nul & del \"%~f0\"\r\n"
        )
        with open(bat, "w", encoding="utf-8") as f:
            f.write(script)

        # Run the batch elevated. The UAC prompt is unavoidable because
        # the install dir is under Program Files.
        try:
            import ctypes
            SW_HIDE = 0
            r = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", bat, None, None, SW_HIDE)
            # ShellExecuteW returns >32 on success per MSDN.
            if int(r) <= 32:
                raise UpdateError(
                    f"Could not launch elevated updater (code {int(r)}). "
                    f"User may have declined the UAC prompt.")
        except UpdateError:
            raise
        except Exception as e:
            raise UpdateError(f"Could not launch updater: {e}")

_NOCONSOLE = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0

try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False

try:
    from watchdog.observers import Observer as WatchdogObserver
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

# ═══════════════════════════════════════════════════════════════════
#  SINGLE INSTANCE
# ═══════════════════════════════════════════════════════════════════
_LOCK_SOCK = None

def acquire_instance():
    global _LOCK_SOCK
    try:
        _LOCK_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _LOCK_SOCK.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        _LOCK_SOCK.bind(("127.0.0.1", 47823))
        return True
    except OSError:
        try: _LOCK_SOCK.close()
        except: pass
        return False

def release_instance():
    global _LOCK_SOCK
    if _LOCK_SOCK:
        try: _LOCK_SOCK.close()
        except: pass

# ═══════════════════════════════════════════════════════════════════
#  SYSTEM — Autostart & Desktop Shortcut
# ═══════════════════════════════════════════════════════════════════
_AUTOSTART_KEY  = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
_AUTOSTART_NAME = "GiftyAntivirus"
_FIRST_RUN_FILE = os.path.join(os.path.expanduser("~"), ".gifty_av_v4_firstrun")

def setup_autostart(enable, exe_path=None):
    if exe_path is None:
        exe_path = sys.executable
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _AUTOSTART_KEY,
                             0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE)
        if enable:
            winreg.SetValueEx(key, _AUTOSTART_NAME, 0, winreg.REG_SZ, f'"{exe_path}"')
        else:
            try: winreg.DeleteValue(key, _AUTOSTART_NAME)
            except FileNotFoundError: pass
        winreg.CloseKey(key)
        return True
    except Exception:
        return False

def is_autostart_enabled():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _AUTOSTART_KEY, 0, winreg.KEY_QUERY_VALUE)
        winreg.QueryValueEx(key, _AUTOSTART_NAME)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False

def create_desktop_shortcut(exe_path=None):
    if exe_path is None:
        exe_path = sys.executable
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    lnk = os.path.join(desktop, "Gifty Antivirus.lnk")
    if os.path.exists(lnk):
        return False
    ps = (
        f'$s=New-Object -ComObject WScript.Shell;'
        f'$sc=$s.CreateShortcut("{lnk}");'
        f'$sc.TargetPath="{exe_path}";'
        f'$sc.Description="Gifty Antivirus PREMIUM";'
        f'$sc.Save()'
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=10, creationflags=_NOCONSOLE)
        return r.returncode == 0
    except Exception:
        return False

def is_first_run():
    return not os.path.exists(_FIRST_RUN_FILE)

def mark_ran():
    try:
        with open(_FIRST_RUN_FILE, "w") as f:
            f.write(datetime.datetime.now().isoformat())
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════
#  THREAT DATABASE
# ═══════════════════════════════════════════════════════════════════
KNOWN_THREAT_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": ("EICAR-Test-File",   "Test Virus",     "High"),
    "aab3238922bcc25a6f606eb525ffdc56": ("Gifty.FakeAV.A",    "Rogue Software", "Critical"),
    "8277e0910d750195b448797616e091ad": ("Gifty.Ransom.B",    "Ransomware",     "Critical"),
    "d3d9446802a44259755d38e6d163e820": ("Gifty.Spyware.X",   "Spyware",        "High"),
}
SCRIPT_EXT    = {".vbs",".bat",".cmd",".scr",".pif",".hta",".wsf",".wsh",".jse",".ps1"}
THREAT_TOKENS = {"keylogger","ransomware","trojan","virus","malware",
                 "exploit","payload","backdoor","rootkit"}
BYTE_SIGS     = [b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"]
SUSP_PE       = {b"VirtualAllocEx",b"WriteProcessMemory",b"CreateRemoteThread",
                 b"NtUnmapViewOfSection",b"QueueUserAPC"}
PE_THRESH     = 3
MONITORED_EXT = {".exe",".dll",".sys",".bat",".cmd",".vbs",".ps1",
                 ".js",".hta",".scr",".pif",".wsf",".jar"}
RANSOM_EXTS   = {".locked",".encrypted",".crypted",".crypt",".enc",".vault",
                 ".satan",".wncry",".zepto",".locky",".cerber",".ryuk",".conti"}
SUSPICIOUS_PROCS = {
    "cryptolocker","wannacry","petya","notpetya","keylogger","rootkit","backdoor",
    "xmrig","monero","coinminer","cryptominer","mimikatz","lazagne","meterpreter",
}

def md5(path):
    try:
        h = hashlib.md5()
        with open(path,"rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
        return h.hexdigest()
    except: return None

def _is_pe(hdr):
    if len(hdr)<64 or hdr[:2]!=b"MZ": return False
    try:
        off = struct.unpack_from("<I",hdr,0x3C)[0]
        return off < len(hdr)-4 and hdr[off:off+4]==b"PE\x00\x00"
    except: return False

def analyze_file(path, deep=False):
    try:
        p = Path(path); ext = p.suffix.lower(); name = p.name.lower()
        size = os.path.getsize(path)
        digest = md5(path)
        if digest and digest in KNOWN_THREAT_HASHES:
            return KNOWN_THREAT_HASHES[digest]
        if ext in RANSOM_EXTS:
            return ("Gifty.Ransom.Ext","Ransomware Extension","Critical")
        if ext in SCRIPT_EXT:
            for tok in THREAT_TOKENS:
                if tok in name:
                    return (f"Gifty.Heuristic.{ext[1:].upper()}","Potentially Unwanted","Medium")
        if size < 1024:
            with open(path,"rb") as f: data = f.read(1024)
            for sig in BYTE_SIGS:
                if sig in data: return ("EICAR-Test-File","Test Virus","High")
        if ext in {".exe",".dll",".sys"} and size < 50_000_000:
            with open(path,"rb") as f: hdr = f.read(min(size,524288))
            if _is_pe(hdr):
                hits = sum(1 for imp in SUSP_PE if imp in hdr)
                if hits >= PE_THRESH:
                    return ("Gifty.Heuristic.Injector","Process Injection","High")
        if deep:
            try:
                with open(path,"rb") as f: data = f.read(512)
                for sig in BYTE_SIGS:
                    if sig in data: return ("EICAR-Test-File","Test Virus","High")
            except: pass
        return None
    except: return None

# ═══════════════════════════════════════════════════════════════════
#  PERSISTENCE
# ═══════════════════════════════════════════════════════════════════
DATA_FILE = os.path.join(os.path.expanduser("~"), ".gifty_av_v4.json")

DEFAULT_RT = {
    "file_monitoring":       True,
    "download_protection":   True,
    "email_scan":            True,
    "ransomware_shield":     True,
    "heuristic_detection":   True,
    "usb_protection":        True,
    "memory_scan":           True,
    "web_threat_blocking":   False,
}

RT_META = {
    "file_monitoring":     ("🔍","File Access Monitor",    "Watches Downloads, Desktop, Documents & Temp for new/modified files",  True),
    "download_protection": ("🌐","Download Protection",    "Deep-scans ALL file types in Downloads on creation",                   True),
    "email_scan":          ("📧","Email Attachment Scan",  "Inspects email attachment temp folders for known threats",              True),
    "ransomware_shield":   ("🔒","Ransomware Shield",      "Monitors Desktop & Documents for mass changes & ransom extensions",    True),
    "heuristic_detection": ("🧠","Heuristic Detection",    "Identifies unknown threats by PE structure and behavioural patterns",  True),
    "usb_protection":      ("💾","USB/Drive Protection",   "Auto-scans removable drives when inserted",                            True),
    "memory_scan":         ("⚡","Memory Scan",            "Periodically scans running processes for suspicious names",            True),
    "web_threat_blocking": ("🕷️","Web Threat Blocking",   "Blocks known malicious URLs — requires proxy integration",            False),
}

def load_data():
    try:
        with open(DATA_FILE) as f: d = json.load(f)
        d.setdefault("rt_protections", DEFAULT_RT.copy())
        d.setdefault("exclusions",     [])
        d.setdefault("rt_events",      [])
        d.setdefault("scheduled_scan", {"enabled":False,"time":"02:00","type":"quick"})
        d.setdefault("settings",       {})
        for k,v in DEFAULT_RT.items():
            d["rt_protections"].setdefault(k, v)
        d["settings"].setdefault("autostart", is_autostart_enabled())
        d["settings"].setdefault("auto_check_updates", True)
        d["settings"].setdefault("skipped_version", "")
        d["settings"].setdefault("last_update_check", 0)
        return d
    except:
        return {
            "quarantine":[],"scan_history":[],"total_scanned":0,"total_threats":0,
            "realtime":True,
            "rt_protections": DEFAULT_RT.copy(),
            "exclusions":[],"rt_events":[],
            "scheduled_scan":{"enabled":False,"time":"02:00","type":"quick"},
            "settings":{
                "scan_archives":False,"heuristic_level":"Medium",
                "auto_quarantine":True,"notifications":True,
                "scan_on_start":False,"minimize_to_tray":True,
                "autostart":is_autostart_enabled(),"send_telemetry":False,"cloud_lookup":True,
                "auto_check_updates":True,"skipped_version":"","last_update_check":0,
            }
        }

def save_data(data):
    try:
        with open(DATA_FILE,"w") as f: json.dump(data,f,indent=2)
    except: pass

# ═══════════════════════════════════════════════════════════════════
#  COLOURS
# ═══════════════════════════════════════════════════════════════════
BG       = "#07090f"
PANEL    = "#0c0f1e"
CARD     = "#101525"
CARD_H   = "#19203e"
BORDER   = "#1a2240"
ACCENT   = "#00e5a0"
ACCENT2  = "#00b8d4"
DANGER   = "#ff4757"
WARNING  = "#ffa502"
GOLD     = "#f0c040"
TEXT     = "#e8eaf6"
TEXT_DIM = "#303860"
TEXT_MID = "#6870a0"
SW       = 228

def _lighter(hx, a):
    try:
        return "#{:02x}{:02x}{:02x}".format(
            min(255,int(hx[1:3],16)+a), min(255,int(hx[3:5],16)+a),
            min(255,int(hx[5:7],16)+a))
    except: return hx

def _lerp_color(c1, c2, t):
    try:
        r1,g1,b1 = int(c1[1:3],16),int(c1[3:5],16),int(c1[5:7],16)
        r2,g2,b2 = int(c2[1:3],16),int(c2[3:5],16),int(c2[5:7],16)
        return "#{:02x}{:02x}{:02x}".format(
            int(r1+(r2-r1)*t), int(g1+(g2-g1)*t), int(b1+(b2-b1)*t))
    except: return c1

# ═══════════════════════════════════════════════════════════════════
#  WIDGET — ConfirmDialog
# ═══════════════════════════════════════════════════════════════════
class ConfirmDialog(tk.Toplevel):
    def __init__(self, parent, title, message, ok="Confirm",
                 cancel="Cancel", danger=False, icon="⚠️"):
        super().__init__(parent)
        self.result = False
        self.title(title)
        self.configure(bg=CARD)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.update_idletasks()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        w, h = 430, 230
        self.geometry(f"{w}x{h}+{px+pw//2-w//2}+{py+ph//2-h//2-20}")
        self.attributes("-alpha", 0.0)
        accent = DANGER if danger else ACCENT
        tk.Frame(self, bg=accent, height=3).pack(fill="x")
        body = tk.Frame(self, bg=CARD); body.pack(fill="both", expand=True, padx=30, pady=18)
        tk.Label(body,text=icon,font=("Segoe UI Emoji",32),bg=CARD,fg=accent).pack()
        tk.Label(body,text=title,font=("Segoe UI",13,"bold"),bg=CARD,fg=TEXT).pack(pady=(4,0))
        tk.Label(body,text=message,font=("Segoe UI",9),bg=CARD,fg=TEXT_MID,
                 wraplength=360,justify="center").pack(pady=(6,18))
        bf = tk.Frame(body, bg=CARD); bf.pack()
        def mkbtn(text, cmd, bg, fg):
            b = tk.Button(bf,text=text,command=cmd,bg=bg,fg=fg,relief="flat",cursor="hand2",
                          bd=0,font=("Segoe UI",10,"bold"),padx=22,pady=8,
                          activebackground=_lighter(bg,20),activeforeground=fg)
            b.pack(side="left",padx=5)
        mkbtn(cancel, self._no,  BORDER, TEXT)
        mkbtn(ok,     self._yes, accent, "#fff" if danger else BG)
        self._fade(0.0)
        self.wait_window()

    def _fade(self, a):
        if a < 1.0:
            self.attributes("-alpha", a)
            self.after(18, lambda: self._fade(min(1.0, a+0.14)))

    def _yes(self): self.result=True;  self.destroy()
    def _no(self):  self.result=False; self.destroy()

# ═══════════════════════════════════════════════════════════════════
#  WIDGET — InfoDialog (single-button, informational)
# ═══════════════════════════════════════════════════════════════════
class InfoDialog(tk.Toplevel):
    def __init__(self, parent, title, message, icon="ℹ️", color=ACCENT):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=CARD)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.update_idletasks()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        w, h = 420, 220
        self.geometry(f"{w}x{h}+{px+pw//2-w//2}+{py+ph//2-h//2-20}")
        self.attributes("-alpha", 0.0)
        tk.Frame(self, bg=color, height=3).pack(fill="x")
        body = tk.Frame(self, bg=CARD); body.pack(fill="both", expand=True, padx=30, pady=18)
        tk.Label(body, text=icon, font=("Segoe UI Emoji", 32), bg=CARD, fg=color).pack()
        tk.Label(body, text=title, font=("Segoe UI", 13, "bold"), bg=CARD, fg=TEXT).pack(pady=(4, 0))
        tk.Label(body, text=message, font=("Segoe UI", 9), bg=CARD, fg=TEXT_MID,
                 wraplength=360, justify="center").pack(pady=(6, 18))
        ok_btn = tk.Button(body, text="OK", command=self.destroy,
                           bg=color, fg=BG, relief="flat", cursor="hand2",
                           bd=0, font=("Segoe UI", 10, "bold"), padx=28, pady=8,
                           activebackground=_lighter(color, 20), activeforeground=BG)
        ok_btn.pack()
        self._fade(0.0)
        self.wait_window()

    def _fade(self, a):
        if a < 1.0:
            self.attributes("-alpha", a)
            self.after(18, lambda: self._fade(min(1.0, a + 0.14)))

# ═══════════════════════════════════════════════════════════════════
#  WIDGET — Toast Notification
# ═══════════════════════════════════════════════════════════════════
# Module-level registry so toasts can see each other and stack properly
_ACTIVE_TOASTS = []
_TOAST_GAP = 8  # px gap between stacked toasts

class ToastNotification(tk.Toplevel):
    def __init__(self, parent, title, message, icon="✅", color=ACCENT, duration=4000):
        super().__init__(parent)
        self.overrideredirect(True)
        self.configure(bg=CARD)
        self.attributes("-topmost", True)
        self.attributes("-alpha", 0.0)
        tk.Frame(self, bg=color, width=4).pack(side="left", fill="y")
        body = tk.Frame(self, bg=CARD); body.pack(side="left", fill="both", expand=True, padx=14, pady=12)
        top = tk.Frame(body, bg=CARD); top.pack(fill="x")
        tk.Label(top,text=icon,font=("Segoe UI Emoji",14),bg=CARD,fg=color).pack(side="left")
        tk.Label(top,text=f"  {title}",font=("Segoe UI",10,"bold"),bg=CARD,fg=TEXT).pack(side="left")
        tk.Button(top,text="✕",command=self._dismiss,bg=CARD,fg=TEXT_DIM,
                  relief="flat",bd=0,cursor="hand2",font=("Segoe UI",8),
                  activebackground=CARD,activeforeground=TEXT).pack(side="right")
        tk.Label(body,text=message,font=("Segoe UI",8),bg=CARD,fg=TEXT_MID,
                 wraplength=280,justify="left").pack(anchor="w",pady=(4,0))
        self._pb = tk.Frame(self, bg=color, height=2)
        self._pb.pack(fill="x", side="bottom")
        self.update_idletasks()
        w = 320; h = self.winfo_reqheight()
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        self._x = sw - w - 18
        self._h = h
        # Shift all existing toasts up to make room for the new one
        shift = h + _TOAST_GAP
        for t in _ACTIVE_TOASTS:
            t._y1 -= shift
            try: t.geometry(f"+{t._x}+{t._y1}")
            except: pass
        _ACTIVE_TOASTS.append(self)
        self._y0 = sh - 80
        self._y1 = sh - h - 60
        self.geometry(f"{w}x{h}+{self._x}+{self._y0}")
        self._alive = True
        self._duration = duration
        self._slide(0)

    def _slide(self, step):
        total = 12
        if step <= total:
            t = step/total
            y = int(self._y0+(self._y1-self._y0)*(1-(1-t)**2))
            self.geometry(f"+{self._x}+{y}")
            self.attributes("-alpha", min(1.0, step/total*1.4))
            self.after(18, lambda: self._slide(step+1))
        else:
            self._start = time.time()
            self._shrink(); self.after(self._duration, self._dismiss)

    def _shrink(self):
        if not self._alive: return
        frac = max(0.0, 1.0-(time.time()-self._start)/(self._duration/1000))
        try:
            self._pb.config(width=int(320*frac))
            if frac > 0: self.after(50, self._shrink)
        except: pass

    def _dismiss(self):
        if not self._alive: return
        self._alive = False
        # Shift toasts that are stacked above this one back down
        if self in _ACTIVE_TOASTS:
            idx = _ACTIVE_TOASTS.index(self)
            shift = self._h + _TOAST_GAP
            for t in _ACTIVE_TOASTS[:idx]:   # toasts above this one have smaller y values
                t._y1 += shift
                try: t.geometry(f"+{t._x}+{t._y1}")
                except: pass
            _ACTIVE_TOASTS.remove(self)
        self._fadeout(1.0)

    def _fadeout(self, a):
        if a > 0:
            try: self.attributes("-alpha", a); self.after(28, lambda: self._fadeout(round(a-0.14,2)))
            except: pass
        else:
            try: self.destroy()
            except: pass

# ═══════════════════════════════════════════════════════════════════
#  WIDGET — ScrollableFrame
# ═══════════════════════════════════════════════════════════════════
class ScrollableFrame(tk.Frame):
    def __init__(self, parent, bg=BG, **kw):
        super().__init__(parent, bg=bg, **kw)
        self._cv = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self._sb = DarkScrollbar(self, orient="vertical", command=self._cv.yview)
        self.inner = tk.Frame(self._cv, bg=bg)
        self.inner.bind("<Configure>", lambda e: self._cv.configure(scrollregion=self._cv.bbox("all")))
        self._cv.bind("<Configure>", lambda e: self._cv.itemconfigure(self._win, width=e.width))
        self._win = self._cv.create_window((0,0), window=self.inner, anchor="nw")
        self._cv.configure(yscrollcommand=self._sb.set)
        self._sb.pack(side="right", fill="y", padx=(0,1))
        self._cv.pack(side="left", fill="both", expand=True)
        self._cv.bind("<Enter>", lambda e: self._cv.bind_all("<MouseWheel>", self._wheel))
        self._cv.bind("<Leave>", lambda e: self._cv.unbind_all("<MouseWheel>"))

    def _wheel(self, e): self._cv.yview_scroll(int(-1*(e.delta/120)),"units")

# ═══════════════════════════════════════════════════════════════════
#  WIDGET — CustomSelect (dark dropdown replaces ttk.Combobox everywhere)
# ═══════════════════════════════════════════════════════════════════
class CustomSelect(tk.Frame):
    def __init__(self, parent, variable, values, width=130, bg=CARD, on_change=None, **kw):
        super().__init__(parent, bg=bg, highlightbackground=BORDER,
                         highlightthickness=1, cursor="hand2", **kw)
        self._var=variable; self._values=values; self._bg=bg
        self._on_change=on_change; self._dropdown=None; self._width=width
        inner = tk.Frame(self, bg=bg); inner.pack(fill="x")
        self._lbl = tk.Label(inner, textvariable=variable, font=("Segoe UI",9),
                             bg=bg, fg=TEXT, width=width//8, anchor="w")
        self._lbl.pack(side="left", padx=(12,4), pady=7)
        self._arr = tk.Label(inner, text="▾", font=("Segoe UI",9,"bold"), bg=bg, fg=ACCENT2)
        self._arr.pack(side="right", padx=(4,10))
        for w in (self, inner, self._lbl, self._arr):
            w.bind("<Button-1>", self._toggle)
            w.bind("<Enter>", lambda e: self.config(highlightbackground=ACCENT2))
            w.bind("<Leave>", lambda e: self.config(highlightbackground=BORDER))

    def _toggle(self, e=None):
        if self._dropdown:
            try:
                if self._dropdown.winfo_exists(): self._dropdown.destroy(); self._dropdown=None; return
            except: pass
        self._show_dropdown()

    def _show_dropdown(self):
        self.update_idletasks()
        x=self.winfo_rootx(); y=self.winfo_rooty()+self.winfo_height()
        w=max(self.winfo_width(), self._width)
        total_h=min(len(self._values)*32, 260)
        dd=tk.Toplevel(self); dd.overrideredirect(True)
        dd.configure(bg=PANEL); dd.geometry(f"{w}x{total_h}+{x}+{y}")
        dd.attributes("-topmost", True)
        cv=tk.Canvas(dd,bg=PANEL,highlightthickness=0); cv.pack(fill="both",expand=True)
        lf=tk.Frame(cv,bg=PANEL)
        cw=cv.create_window((0,0),window=lf,anchor="nw")
        lf.bind("<Configure>",lambda e:cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>",lambda e:cv.itemconfig(cw,width=e.width))
        def _w(e): cv.yview_scroll(int(-1*(e.delta/120)),"units")
        cv.bind("<MouseWheel>",_w); lf.bind("<MouseWheel>",_w)
        for val in self._values:
            is_active=(val==self._var.get())
            btn=tk.Label(lf,text=val,font=("Segoe UI",9),
                         bg=BORDER if is_active else PANEL,
                         fg=ACCENT if is_active else TEXT,
                         cursor="hand2",anchor="w",padx=14,pady=6)
            btn.pack(fill="x")
            def _sel(v=val):
                self._var.set(v)
                if self._on_change: self._on_change(v)
                try: dd.destroy()
                except: pass
                self._dropdown=None
            btn.bind("<Button-1>",lambda e,fn=_sel:fn())
            btn.bind("<Enter>",lambda e,b=btn:b.config(bg=CARD_H,fg=ACCENT))
            btn.bind("<Leave>",lambda e,b=btn,v=val:b.config(
                bg=BORDER if v==self._var.get() else PANEL,
                fg=ACCENT if v==self._var.get() else TEXT))
        dd.bind("<FocusOut>",lambda e:(dd.destroy(),setattr(self,"_dropdown",None)))
        dd.focus_set(); self._dropdown=dd


# ═══════════════════════════════════════════════════════════════════
#  WIDGET — DarkScrollbar (replaces default Windows scrollbar look)
# ═══════════════════════════════════════════════════════════════════
class DarkScrollbar(tk.Canvas):
    """Minimal flat dark scrollbar that replaces ttk.Scrollbar."""
    def __init__(self, parent, orient="vertical", command=None, **kw):
        w, h = (12, 200) if orient=="vertical" else (200, 12)
        super().__init__(parent, width=w, height=h, bg=PANEL,
                         highlightthickness=0, **kw)
        self._orient  = orient
        self._command = command
        self._lo, self._hi = 0.0, 1.0
        self._drag_start = None
        self.bind("<ButtonPress-1>",   self._press)
        self.bind("<B1-Motion>",       self._drag)
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<Configure>",       lambda e: self._draw())

    def set(self, lo, hi):
        self._lo, self._hi = float(lo), float(hi)
        self._draw()

    def _draw(self):
        self.delete("all")
        W, H = self.winfo_width(), self.winfo_height()
        if W < 2 or H < 2: return
        # track
        self.create_rectangle(0, 0, W, H, fill=PANEL, outline="")
        # thumb
        if self._orient == "vertical":
            y1 = int(H * self._lo); y2 = int(H * self._hi)
            if y2-y1 < 20: y2 = y1+20
            self.create_rectangle(2, y1, W-2, y2, fill=BORDER, outline="", tags="thumb")
        else:
            x1 = int(W * self._lo); x2 = int(W * self._hi)
            if x2-x1 < 20: x2 = x1+20
            self.create_rectangle(x1, 2, x2, H-2, fill=BORDER, outline="", tags="thumb")
        self.tag_bind("thumb", "<Enter>",  lambda e: self.itemconfig("thumb", fill=TEXT_MID))
        self.tag_bind("thumb", "<Leave>",  lambda e: self.itemconfig("thumb", fill=BORDER))

    def _press(self, e):
        self._drag_start = e.y if self._orient=="vertical" else e.x

    def _drag(self, e):
        if self._drag_start is None: return
        pos = e.y if self._orient=="vertical" else e.x
        size = self.winfo_height() if self._orient=="vertical" else self.winfo_width()
        delta = (pos - self._drag_start) / max(size, 1)
        self._drag_start = pos
        if self._command:
            self._command("moveto", self._lo + delta)

    def _release(self, e): self._drag_start = None


# ═══════════════════════════════════════════════════════════════════
#  WIDGET — AnimatedProgressBar
# ═══════════════════════════════════════════════════════════════════
class AnimatedProgressBar(tk.Canvas):
    def __init__(self, parent, height=8, fill=ACCENT, bg=BG, **kw):
        super().__init__(parent, height=height, bg=bg, highlightthickness=0, **kw)
        self._fill, self._value, self._pulse = fill, 0.0, 0
        self.bind("<Configure>", self._draw)
        self._tick()

    def set(self, v):
        self._value = max(0., min(1., v)); self._draw()

    def _draw(self, e=None):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 2: return
        r = h // 2
        self._rr(0, 0, w, h, r, BORDER)
        fw = int(w * self._value)
        if fw > r*2:
            self._rr(0, 0, fw, h, r, self._fill)
            sx = (self._pulse % (fw+100)) - 50
            shine = _lighter(self._fill, 55)
            if sx+50 > 0 and sx < fw:
                x1 = max(r, sx); x2 = min(fw, sx+50)
                if x2 > x1:
                    self.create_rectangle(x1,2,x2,h-2,fill=shine,outline="",stipple="gray50")

    def _rr(self, x1, y1, x2, y2, r, color):
        self.create_arc(x1,y1,x1+2*r,y1+2*r,start=90, extent=90,fill=color,outline="")
        self.create_arc(x2-2*r,y1,x2,y1+2*r,start=0,  extent=90,fill=color,outline="")
        self.create_arc(x1,y2-2*r,x1+2*r,y2,start=180,extent=90,fill=color,outline="")
        self.create_arc(x2-2*r,y2-2*r,x2,y2,start=270,extent=90,fill=color,outline="")
        self.create_rectangle(x1+r,y1,x2-r,y2,fill=color,outline="")
        self.create_rectangle(x1,y1+r,x2,y2-r,fill=color,outline="")

    def _tick(self):
        self._pulse += 6
        if 0 < self._value < 1: self._draw()
        try: self.after(35, self._tick)
        except: pass

# ═══════════════════════════════════════════════════════════════════
#  WIDGET — ToggleSwitch (FIXED: always animates regardless of on_toggle)
# ═══════════════════════════════════════════════════════════════════
class ToggleSwitch(tk.Canvas):
    def __init__(self, parent, variable, on_toggle=None, bg=CARD, **kw):
        super().__init__(parent, width=54, height=28, bg=bg,
                         highlightthickness=0, cursor="hand2", **kw)
        self._var = variable
        self._on_toggle = on_toggle
        self._phase = 1.0 if variable.get() else 0.0
        self._target = self._phase
        self._animating = False
        self.bind("<Button-1>", self._clicked)
        self._draw()

    def _clicked(self, e=None):
        new_val = not self._var.get()
        # Always animate immediately for instant visual feedback
        self._set_value(new_val)
        # Then notify the callback (which may revert via force_value)
        if self._on_toggle:
            self._on_toggle(new_val)

    def _set_value(self, val):
        self._var.set(val)
        self._target = 1.0 if val else 0.0
        if not self._animating:
            self._animating = True
            self._animate()

    def force_value(self, val):
        self._var.set(val)
        self._phase = 1.0 if val else 0.0
        self._target = self._phase
        self._animating = False
        self._draw()

    def _animate(self):
        diff = self._target - self._phase
        if abs(diff) < 0.025:
            self._phase = self._target
            self._animating = False
            self._draw()
            return
        self._phase += diff * 0.30
        self._draw()
        try: self.after(14, self._animate)
        except: pass

    def _draw(self):
        self.delete("all")
        W, H = 54, 28
        track = _lerp_color("#1e2545", ACCENT, self._phase)
        r = H // 2
        self.create_arc(0,0,H,H,      start=90, extent=90, fill=track,outline="")
        self.create_arc(W-H,0,W,H,    start=0,  extent=90, fill=track,outline="")
        self.create_arc(0,0,H,H,      start=180,extent=90, fill=track,outline="")
        self.create_arc(W-H,0,W,H,    start=270,extent=90, fill=track,outline="")
        self.create_rectangle(r,0,W-r,H,fill=track,outline="")
        mg = 3
        kx = mg + (W-H)*self._phase
        self.create_oval(kx,mg,kx+H-mg*2,H-mg,fill="white",outline="")

# ═══════════════════════════════════════════════════════════════════
#  WIDGET — PulseShield (enhanced with particles)
# ═══════════════════════════════════════════════════════════════════
class PulseShield(tk.Canvas):
    def __init__(self, parent, size=120, bg=BG, **kw):
        super().__init__(parent, width=size, height=size, bg=bg,
                         highlightthickness=0, **kw)
        self._sz = size
        self._bg = bg
        self._phase = 0.0
        self._ok = True
        self._particles = [(i*1.047, 0.35+(i%3)*0.15) for i in range(6)]
        self._tick()

    def set_ok(self, ok): self._ok = ok

    def _tick(self):
        if getattr(self, '_animate', True):
            self._phase += 0.04
        self._draw()
        try: self.after(38, self._tick)
        except: pass

    def _draw(self):
        self.delete("all")
        S = self._sz
        c = ACCENT if self._ok else DANGER
        bg = self._bg
        pulse = 0.93 + math.sin(self._phase)*0.07
        cx, cy = S/2, S/2
        for frac, stip in [(0.48,"gray12"),(0.42,"gray25"),(0.36,"gray50")]:
            r = S*frac*pulse
            self.create_oval(cx-r,cy-r,cx+r,cy+r,outline=c,width=1,stipple=stip)
        for idx,(ao,rf) in enumerate(self._particles):
            ang = self._phase*(1.3 if idx%2==0 else -0.9)+ao
            pr = S*rf*0.44
            px = cx+math.cos(ang)*pr; py = cy+math.sin(ang)*pr
            dr = 2+(idx%2)
            self.create_oval(px-dr,py-dr,px+dr,py+dr,fill=c,outline="",
                             stipple="gray50" if idx%3==2 else "")
        sc = pulse*S/120
        def pt(dx,dy): return cx+dx*sc, cy+dy*sc
        shield = [pt(-28,-40),pt(28,-40),pt(38,-20),pt(38,10),pt(0,50),pt(-38,10),pt(-38,-20)]
        self.create_polygon(shield,fill=c,outline="",smooth=True)
        inner  = [pt(-18,-28),pt(18,-28),pt(25,-14),pt(25,5),pt(0,34),pt(-25,5),pt(-25,-14)]
        self.create_polygon(inner,fill=bg,outline="",smooth=True)
        if self._ok:
            self.create_line(pt(-10,2),pt(-2,12),pt(14,-8),
                             fill=c,width=max(2,int(3.5*pulse)),capstyle="round",joinstyle="round")
        else:
            self.create_line(pt(-10,-10),pt(10,10),fill=c,width=3,capstyle="round")
            self.create_line(pt(10,-10),pt(-10,10),fill=c,width=3,capstyle="round")

# ═══════════════════════════════════════════════════════════════════
#  WIDGET — StatCard with animated counter
# ═══════════════════════════════════════════════════════════════════
class StatCard(tk.Frame):
    def __init__(self, parent, title, value, icon, color=ACCENT, **kw):
        super().__init__(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1, **kw)
        self._color = color
        self._cur = 0
        tk.Frame(self, bg=color, height=2).pack(fill="x")
        top = tk.Frame(self, bg=CARD); top.pack(fill="x", padx=16, pady=(12,0))
        tk.Label(top,text=icon,font=("Segoe UI Emoji",22),bg=CARD,fg=color).pack(side="left")
        self._val = tk.Label(self, text=str(value),
                              font=("Consolas",28,"bold"),bg=CARD,fg=color)
        self._val.pack(anchor="w",padx=16,pady=(4,0))
        tk.Label(self,text=title,font=("Segoe UI",9),bg=CARD,fg=TEXT_MID
                 ).pack(anchor="w",padx=16,pady=(3,14))
        for w in [self]+list(self.winfo_children()):
            try: w.bind("<Enter>",self._hov); w.bind("<Leave>",self._lea)
            except: pass

    def _hov(self,e=None):
        self.config(bg=CARD_H,highlightbackground=self._color)
        for w in self.winfo_children():
            try: w.config(bg=CARD_H)
            except: pass

    def _lea(self,e=None):
        self.config(bg=CARD,highlightbackground=BORDER)
        for w in self.winfo_children():
            try: w.config(bg=CARD)
            except: pass

    def update_value(self, v):
        try:
            new = int(str(v).replace(",",""))
            if new != self._cur:
                self._count(self._cur, new, 0, 14)
        except: self._val.config(text=str(v))

    def _count(self, start, end, step, steps):
        if step > steps:
            self._cur = end
            self._val.config(text=f"{end:,}")
            return
        t = step/steps
        cur = int(start+(end-start)*(1-(1-t)**2))
        self._val.config(text=f"{cur:,}")
        self.after(28, lambda: self._count(start,end,step+1,steps))

# ═══════════════════════════════════════════════════════════════════
#  WIDGET — SidebarButton
# ═══════════════════════════════════════════════════════════════════
class SidebarButton(tk.Frame):
    def __init__(self, parent, icon, label, command, **kw):
        super().__init__(parent, bg=PANEL, cursor="hand2", **kw)
        self._active, self._cmd = False, command
        self._bar = tk.Frame(self, bg=PANEL, width=3)
        self._bar.pack(side="left", fill="y")
        self._ic = tk.Label(self,text=icon,font=("Segoe UI Emoji",14),bg=PANEL,fg=TEXT_DIM,width=3)
        self._ic.pack(side="left", pady=13)
        self._tx = tk.Label(self,text=label,font=("Segoe UI",10,"bold"),bg=PANEL,fg=TEXT_DIM,anchor="w")
        self._tx.pack(side="left",fill="x",expand=True,padx=(0,8))
        for w in (self,self._ic,self._tx,self._bar):
            w.bind("<Button-1>", lambda e: self._cmd())
            w.bind("<Enter>",    self._hov)
            w.bind("<Leave>",    self._lea)

    def _hov(self,e=None):
        if not self._active:
            for w in (self,self._ic,self._tx,self._bar): w.config(bg=CARD_H)
    def _lea(self,e=None):
        if not self._active:
            for w in (self,self._ic,self._tx,self._bar): w.config(bg=PANEL)

    def set_active(self, on):
        self._active = on
        bg = "#0f1830" if on else PANEL
        for w in (self,self._ic,self._tx): w.config(bg=bg)
        self._bar.config(bg=ACCENT if on else PANEL)
        self._ic.config(fg=ACCENT if on else TEXT_DIM)
        self._tx.config(fg=TEXT if on else TEXT_DIM)

# ═══════════════════════════════════════════════════════════════════
#  FILE MONITOR (functional RT file scanning)
# ═══════════════════════════════════════════════════════════════════
class FileMonitor:
    def __init__(self, on_threat, data_getter):
        self._on_threat = on_threat
        self._data = data_getter
        self._running = False
        self._observer = None
        self._known = {}
        self._cooldown = set()

    def _watch_dirs(self):
        home = os.path.expanduser("~")
        dirs = []
        for sub in ("Downloads","Desktop","Documents","AppData/Local/Temp"):
            p = os.path.join(home,sub)
            if os.path.exists(p): dirs.append(p)
        tmp = os.environ.get("TEMP","")
        if tmp and os.path.exists(tmp) and tmp not in dirs: dirs.append(tmp)
        return dirs

    def start(self):
        if self._running: return
        self._running = True
        if HAS_WATCHDOG: self._start_watchdog()
        else: threading.Thread(target=self._poll_loop,daemon=True).start()

    def stop(self):
        self._running = False
        if self._observer:
            try: self._observer.stop(); self._observer.join(2)
            except: pass

    def _start_watchdog(self):
        mon = self
        class _H(FileSystemEventHandler):
            def on_created(self,e):
                if not e.is_directory: mon._event(e.src_path)
            def on_modified(self,e):
                if not e.is_directory: mon._event(e.src_path)
        self._observer = WatchdogObserver()
        for d in self._watch_dirs():
            try: self._observer.schedule(_H(),d,recursive=False)
            except: pass
        self._observer.start()

    def _poll_loop(self):
        for d in self._watch_dirs():
            try:
                for fn in os.listdir(d):
                    fp = os.path.join(d,fn)
                    if os.path.isfile(fp):
                        try: self._known[fp] = os.path.getmtime(fp)
                        except: pass
            except: pass
        while self._running:
            time.sleep(4)
            for d in self._watch_dirs():
                try:
                    for fn in os.listdir(d):
                        fp = os.path.join(d,fn)
                        if not os.path.isfile(fp): continue
                        try:
                            mt = os.path.getmtime(fp)
                            if self._known.get(fp) != mt:
                                self._known[fp] = mt
                                self._event(fp)
                        except: pass
                except: pass

    def _event(self, fp):
        if fp in self._cooldown: return
        data = self._data()
        rtp  = data.get("rt_protections",{})
        if not data.get("realtime",True): return
        home_dl = os.path.join(os.path.expanduser("~"),"Downloads")
        in_dl = fp.startswith(home_dl)
        if in_dl and not rtp.get("download_protection",True): return
        if not in_dl and not rtp.get("file_monitoring",True): return
        for ex in data.get("exclusions",[]):
            if fp.startswith(ex) or fp==ex: return
        self._cooldown.add(fp)
        deep = in_dl and rtp.get("download_protection",True)
        threading.Thread(target=self._scan_file,args=(fp,deep),daemon=True).start()
        def _rm(): time.sleep(30); self._cooldown.discard(fp)
        threading.Thread(target=_rm,daemon=True).start()

    def _scan_file(self, fp, deep=False):
        time.sleep(0.8)
        try:
            r = analyze_file(fp,deep=deep)
            if r: self._on_threat(fp,r)
        except: pass

# ═══════════════════════════════════════════════════════════════════
#  RANSOMWARE SHIELD (functional: mass-change detection + ransom ext)
# ═══════════════════════════════════════════════════════════════════
class RansomwareShield:
    def __init__(self, on_threat, on_warning, data_getter):
        self._on_threat  = on_threat
        self._on_warning = on_warning
        self._data       = data_getter
        self._running    = False

    def start(self):
        if self._running: return
        self._running = True
        threading.Thread(target=self._loop,daemon=True).start()

    def stop(self): self._running = False

    def _loop(self):
        home = os.path.expanduser("~")
        watch = [os.path.join(home,sub) for sub in ("Desktop","Documents","Pictures")
                 if os.path.exists(os.path.join(home,sub))]
        file_exts = {}
        changes   = []
        alerted_ext = set()
        alerted_mass = False
        for d in watch:
            try:
                for fn in os.listdir(d):
                    fp = os.path.join(d,fn)
                    if os.path.isfile(fp): file_exts[fp] = Path(fp).suffix.lower()
            except: pass
        while self._running:
            time.sleep(3)
            data = self._data()
            if not data.get("realtime",True): continue
            if not data["rt_protections"].get("ransomware_shield",True): continue
            now = time.time()
            changes = [t for t in changes if now-t < 12]
            for d in watch:
                try:
                    for fn in os.listdir(d):
                        fp = os.path.join(d,fn)
                        if not os.path.isfile(fp): continue
                        ext = Path(fp).suffix.lower()
                        if ext in RANSOM_EXTS and fp not in alerted_ext:
                            alerted_ext.add(fp)
                            self._on_threat(fp,("Gifty.Ransom.Shield","Ransomware Extension","Critical"))
                        prev = file_exts.get(fp)
                        if prev is None:
                            file_exts[fp] = ext; changes.append(now)
                        elif prev != ext:
                            file_exts[fp] = ext; changes.append(now)
                except: pass
            if len(changes) >= 8 and not alerted_mass:
                alerted_mass = True
                self._on_warning(
                    f"Mass file changes: {len(changes)} files modified in 12s — possible ransomware!")
            if len(changes) < 3: alerted_mass = False

# ═══════════════════════════════════════════════════════════════════
#  USB MONITOR (functional: detects new removable drives)
# ═══════════════════════════════════════════════════════════════════
class USBMonitor:
    def __init__(self, on_drive, on_threat, data_getter):
        self._on_drive  = on_drive
        self._on_threat = on_threat
        self._data      = data_getter
        self._running   = False

    def start(self):
        if self._running: return
        self._running = True
        threading.Thread(target=self._loop,daemon=True).start()

    def stop(self): self._running = False

    def _get_removable(self):
        drives = set()
        try:
            import ctypes
            bm = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bm & (1<<i):
                    letter = chr(ord('A')+i)+":\\"
                    dtype  = ctypes.windll.kernel32.GetDriveTypeW(letter)
                    if dtype == 2: drives.add(letter)
        except: pass
        return drives

    def _loop(self):
        known = self._get_removable()
        while self._running:
            time.sleep(6)
            data = self._data()
            if not data.get("realtime",True): continue
            if not data["rt_protections"].get("usb_protection",True): continue
            current = self._get_removable()
            for drive in current - known:
                self._on_drive(drive)
                threading.Thread(target=self._scan_drive,args=(drive,),daemon=True).start()
            known = current

    def _scan_drive(self, drive):
        time.sleep(1.5)
        try:
            for fn in os.listdir(drive):
                fp = os.path.join(drive,fn)
                if os.path.isfile(fp):
                    r = analyze_file(fp)
                    if r: self._on_threat(fp,r)
        except: pass

# ═══════════════════════════════════════════════════════════════════
#  MEMORY SCANNER (functional: scans process names)
# ═══════════════════════════════════════════════════════════════════
class MemoryScanner:
    def __init__(self, on_threat, data_getter):
        self._on_threat = on_threat
        self._data      = data_getter
        self._running   = False
        self._alerted   = set()

    def start(self):
        if self._running: return
        self._running = True
        threading.Thread(target=self._loop,daemon=True).start()

    def stop(self): self._running = False

    def _loop(self):
        time.sleep(25)
        while self._running:
            data = self._data()
            if data.get("realtime",True) and data["rt_protections"].get("memory_scan",True):
                try:
                    result = subprocess.run(["tasklist","/FO","CSV","/NH"],
                                            capture_output=True,text=True,timeout=12, creationflags=_NOCONSOLE)
                    for line in result.stdout.splitlines():
                        parts = line.strip('"').split('","')
                        if not parts: continue
                        name = parts[0].lower().replace(".exe","")
                        pid  = parts[1] if len(parts)>1 else "?"
                        key  = f"{name}:{pid}"
                        for s in SUSPICIOUS_PROCS:
                            if s in name and key not in self._alerted:
                                self._alerted.add(key)
                                self._on_threat(f"[Process] {parts[0]} (PID:{pid})",
                                    (f"Gifty.Memory.{name.title()}","Suspicious Process","High"))
                                # Fire a toast directly from here via Tk.after scheduling
                                _nm = parts[0]; _pd = pid
                                try:
                                    import tkinter as _tk
                                    for w in _tk._default_root.winfo_children(): pass
                                    _tk._default_root.after(0, lambda n=_nm,p=_pd:
                                        ToastNotification(_tk._default_root,
                                            "Suspicious Process Detected",
                                            f"{n} (PID {p}) matches known threat signatures",
                                            "⚡", WARNING, 6000))
                                except: pass
                except: pass
            time.sleep(30)

# ═══════════════════════════════════════════════════════════════════
#  MAIN APP
# ═══════════════════════════════════════════════════════════════════
class GiftyAV(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Gifty Antivirus — PREMIUM PLAN")
        self.geometry("1200x760")
        self.minsize(1000,640)
        self.configure(bg=BG)
        self._set_app_icon()

        self.data = load_data()
        # Wire telemetry to read the live "send_telemetry" setting on every send.
        # Until the user opts in, every telemetry call is a no-op.
        set_telemetry_consent_getter(
            lambda: bool(self.data.get("settings", {}).get("send_telemetry", False)))
        self._scan_running = self._scan_cancel = False
        self._rt_running = False
        self._hidden = self._really_exit = False
        self._tray = None
        self._rt_toggle_vars    = {}
        self._rt_toggle_widgets = {}
        self._current_page = None

        self._build_ui()
        self._show_page("dashboard", animate=False)
        self._update_stats()
        self._tick_clock()
        self._setup_tree_styles()

        # Protection workers
        self._file_monitor  = FileMonitor(self._rt_threat_detected, lambda: self.data)
        self._ransom_shield = RansomwareShield(
            self._rt_threat_detected,
            lambda m: self.after(0, lambda msg=m: (self._log_rt("WARNING",msg),self._show_toast("Ransomware Alert",msg,"🔒",DANGER,8000))),
            lambda: self.data)
        self._usb_monitor   = USBMonitor(
            lambda d: self.after(0, lambda dr=d: self._on_usb_insert(dr)),
            self._rt_threat_detected, lambda: self.data)
        self._mem_scanner   = MemoryScanner(self._rt_threat_detected, lambda: self.data)

        if self.data.get("realtime",True):
            self._start_realtime()
        if self.data["settings"].get("scan_on_start"):
            self.after(2200, lambda: self._quick_action("quick"))

        # First run: create shortcut + offer autostart
        if is_first_run():
            mark_ran()
            self.after(1800, self._first_run_setup)

        self.after(500, self._setup_tray)
        self.after(100, self._apply_dark_titlebar)
        # Background update check — throttled to once per 24h, gated by setting.
        self.after(8000, self._maybe_check_updates_on_launch)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _set_app_icon(self):
        dirs = [os.path.dirname(os.path.abspath(sys.argv[0])),
                os.path.dirname(os.path.abspath(__file__)),
                os.getcwd()]
        ico = None
        for d in dirs:
            if os.path.exists(os.path.join(d,"GiftAntivirusIcon.ico")):
                ico = os.path.join(d,"GiftAntivirusIcon.ico"); break
        if ico is None:
            for d in dirs:
                png = os.path.join(d,"GiftAntivirusIcon.png")
                if os.path.exists(png):
                    try:
                        from PIL import Image as _I
                        img = _I.open(png).convert("RGBA")
                        px = img.load()
                        for y in range(img.height):
                            for x in range(img.width):
                                r,g,b,a = px[x,y]
                                if r<35 and g<35 and b<35: px[x,y]=(0,0,0,0)
                        tmp = os.path.join(os.environ.get("TEMP",d),"_gifty_av.ico")
                        img.save(tmp,"ICO",sizes=[(16,16),(32,32),(48,48),(64,64),(256,256)])
                        ico = tmp
                    except: pass
                    break
        if ico is None: return

        # Always set via iconbitmap (title bar + Alt-Tab)
        try: self.iconbitmap(default=ico)
        except: pass

        # Also force-set via WM_SETICON so taskbar picks it up
        def _force_taskbar():
            try:
                import ctypes
                WM_SETICON=0x80; IMAGE_ICON=1
                LR_FILE=0x10; LR_SIZE=0x40
                hwnd = ctypes.windll.user32.GetParent(self.winfo_id()) or self.winfo_id()
                big   = ctypes.windll.user32.LoadImageW(None,ico,IMAGE_ICON, 0, 0,LR_FILE|LR_SIZE)
                small = ctypes.windll.user32.LoadImageW(None,ico,IMAGE_ICON,16,16,LR_FILE)
                if big:   ctypes.windll.user32.SendMessageW(hwnd,WM_SETICON,1,big)
                if small: ctypes.windll.user32.SendMessageW(hwnd,WM_SETICON,0,small)
                try: self.iconbitmap(default=ico)
                except: pass
            except: pass
        self.after(300, _force_taskbar)
        self.after(1200, _force_taskbar)  # retry after window fully drawn


    def _apply_dark_titlebar(self):
        try:
            import ctypes
            DWMWA_DARK = 20
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id()) or self.winfo_id()
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_DARK, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int))
        except: pass

    def _first_run_setup(self):
        created = create_desktop_shortcut(sys.executable)
        if created:
            self._show_toast("Shortcut Created","Gifty Antivirus shortcut added to Desktop.","🖥️",ACCENT2,5000)

        # ── Telemetry consent (separate from EULA, default OFF) ─────
        consent = ConfirmDialog(self, "Help Improve Gifty Antivirus?",
            "We'd like to collect anonymous usage data to improve detection\n"
            "and figure out which features people actually use.\n\n"
            "WHAT WE COLLECT (only if you say yes):\n"
            "  • An anonymous install ID (no name, no hostname)\n"
            "  • App version and OS family (e.g. Windows 11)\n"
            "  • Which features you use and which pages you open\n"
            "  • Aggregate scan stats and threat categories\n\n"
            "WHAT WE NEVER COLLECT:\n"
            "  • File names, file paths, or file contents\n"
            "  • Your username, hostname, IP, or any personal data\n\n"
            "You can change this anytime in Settings → Privacy.",
            ok="Yes, share usage data", cancel="No thanks", icon="📊")
        self.data["settings"]["send_telemetry"] = bool(consent.result)
        save_data(self.data)
        if hasattr(self, "_svars") and "send_telemetry" in self._svars:
            self._svars["send_telemetry"].set(bool(consent.result))
        if consent.result:
            self._show_toast("Telemetry Enabled",
                "Thanks for helping improve Gifty Antivirus.","📊",ACCENT,4500)
            # Fire the first heartbeat now that consent exists.
            threading.Thread(target=tel_session_start, daemon=True).start()

        dlg = ConfirmDialog(self,"Launch at Startup?",
            "Would you like Gifty Antivirus to start automatically with Windows?",
            ok="Enable Autostart",cancel="Not Now",icon="🛡️")
        if dlg.result:
            if setup_autostart(True,sys.executable):
                self.data["settings"]["autostart"] = True
                save_data(self.data)
                if hasattr(self,"_svars") and "autostart" in self._svars:
                    self._svars["autostart"].set(True)
                self._show_toast("Autostart Enabled","Gifty Antivirus will launch at every boot.","✅",ACCENT)

    # ─── LAYOUT ────────────────────────────────────────────────────
    def _build_ui(self):
        self.sidebar = tk.Frame(self, bg=PANEL, width=SW)
        self.sidebar.pack(side="left",fill="y")
        self.sidebar.pack_propagate(False)

        logo = tk.Frame(self.sidebar,bg=PANEL)
        logo.pack(fill="x",pady=(22,8))
        _logo_shown = False
        try:
            from PIL import Image as _PILImg, ImageTk as _PILTk
            _icon_search = [
                os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "GiftAntivirusIcon.png"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)),   "GiftAntivirusIcon.png"),
                os.path.join(os.getcwd(), "GiftAntivirusIcon.png"),
            ]
            for _ip in _icon_search:
                if os.path.exists(_ip):
                    _pil = _PILImg.open(_ip).convert("RGBA")
                    _px = _pil.load()
                    for _yy in range(_pil.height):
                        for _xx in range(_pil.width):
                            r2,g2,b2,a2 = _px[_xx,_yy]
                            if r2 < 35 and g2 < 35 and b2 < 35:
                                _px[_xx,_yy] = (0,0,0,0)
                    _pil = _pil.resize((62,62), _PILImg.LANCZOS)
                    self._sidebar_logo_photo = _PILTk.PhotoImage(_pil)
                    tk.Label(logo, image=self._sidebar_logo_photo, bg=PANEL).pack(pady=(0,4))
                    _logo_shown = True
                    break
        except: pass
        if not _logo_shown:
            tk.Label(logo,text="🎁",font=("Segoe UI Emoji",34),bg=PANEL,fg=ACCENT).pack()
        tk.Label(logo,text="Gifty Antivirus",font=("Consolas",13,"bold"),bg=PANEL,fg=TEXT).pack(pady=(2,0))
        pf = tk.Frame(logo, bg=PANEL); pf.pack(pady=(2,0))
        tk.Label(pf,text="✦ PREMIUM",font=("Segoe UI",8,"bold"),bg=PANEL,fg=GOLD).pack(side="left")
        tk.Label(pf,text="  v4.0",font=("Segoe UI",7),bg=PANEL,fg=TEXT_DIM).pack(side="left")
        tk.Frame(self.sidebar,bg=BORDER,height=1).pack(fill="x",padx=16,pady=10)

        self._nav_btns = {}
        nav = [
            ("dashboard",  "📊","Dashboard"),
            ("scan",       "🔍","Scan"),
            ("quarantine", "🔒","Quarantine"),
            ("history",    "📋","History"),
            ("realtime",   "⚡","Real-Time"),
            ("network",    "🌐","Network"),
            ("startup",    "🚀","Startup"),
            ("schedule",   "⏰","Schedule"),
            ("exclusions", "🚫","Exclusions"),
            ("plans",      "💎","Plans"),
            ("vulnscan",   "🔬","Vulnerability"),
            ("cleaner",    "🧹","Cleaner"),
            ("tools",      "🛠️","Tools"),
            ("settings",   "⚙️","Settings"),
        ]
        _nav_canvas = tk.Canvas(self.sidebar, bg=PANEL, highlightthickness=0, bd=0)
        _nav_canvas.pack(fill="both", expand=True, pady=2)
        bf = tk.Frame(_nav_canvas, bg=PANEL)
        _nav_win = _nav_canvas.create_window((0,0), window=bf, anchor="nw")
        bf.bind("<Configure>", lambda e: _nav_canvas.configure(scrollregion=_nav_canvas.bbox("all")))
        _nav_canvas.bind("<Configure>", lambda e: _nav_canvas.itemconfig(_nav_win, width=e.width))
        def _nw(e): _nav_canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        _nav_canvas.bind("<Enter>", lambda e: _nav_canvas.bind_all("<MouseWheel>", _nw))
        _nav_canvas.bind("<Leave>", lambda e: _nav_canvas.unbind_all("<MouseWheel>"))
        for page,icon,label in nav:
            b = SidebarButton(bf,icon,label,lambda p=page: self._show_page(p))
            b.pack(fill="x")
            self._nav_btns[page] = b

        self._rt_ind = tk.Label(self.sidebar,text="● REAL-TIME ACTIVE",
                                font=("Segoe UI",7,"bold"),bg=PANEL,fg=ACCENT)
        self._rt_ind.pack(pady=(0,6))

        sc_f = tk.Frame(self.sidebar,bg=PANEL); sc_f.pack(fill="x",padx=12,pady=(0,16))
        hr = tk.Frame(sc_f,bg=PANEL); hr.pack(fill="x")
        tk.Label(hr,text="Protection Score",font=("Segoe UI",7,"bold"),bg=PANEL,fg=TEXT_DIM).pack(side="left")
        self._score_pct_lbl = tk.Label(hr,text="",font=("Consolas",7,"bold"),bg=PANEL,fg=ACCENT)
        self._score_pct_lbl.pack(side="right")
        self._score_bar = AnimatedProgressBar(sc_f,height=5,fill=ACCENT,bg=PANEL)
        self._score_bar.pack(fill="x",pady=(3,0))

        self.content = tk.Frame(self,bg=BG)
        self.content.pack(side="left",fill="both",expand=True)
        self._pages = {}
        for n in ("dashboard","scan","quarantine","history","realtime","network","startup","schedule","vulnscan","cleaner","tools","exclusions","plans","settings"):
            f = tk.Frame(self.content,bg=BG); f.place(relwidth=1,relheight=1)
            self._pages[n] = f

        self._build_dashboard()
        self._build_scan()
        self._build_quarantine()
        self._build_history()
        self._build_realtime()
        self._build_network()
        self._build_startup()
        self._build_schedule()
        self._build_exclusions()
        self._build_plans()
        self._build_vulnscan()
        self._build_cleaner()
        self._build_tools()
        self._build_settings()

    def _show_page(self, name, animate=True):
        if name == self._current_page: return
        for k,btn in self._nav_btns.items(): btn.set_active(k==name)
        self._pages[name].lift()
        self._current_page = name
        self.content.update_idletasks()
        tel_event("page_visited", page=name)
        if name=="quarantine":  self._refresh_quarantine()
        elif name=="history":   self._refresh_history()
        elif name=="realtime":  self._refresh_rt_ui()
        elif name=="network":   self._refresh_network()
        elif name=="startup":   self._refresh_startup()
        elif name=="schedule":   self._refresh_schedule()
        elif name=="vulnscan":   self.after(50, self._run_vulnscan)
        elif name=="cleaner":    self.after(50, self._refresh_cleaner)

    def _page_fade(self):
        # Cancel any lingering overlay from a previous transition
        if hasattr(self, '_fade_ov') and self._fade_ov:
            try: self._fade_ov.destroy()
            except: pass
            self._fade_ov = None

        ov = tk.Canvas(self.content, bg=BG, highlightthickness=0)
        ov.place(relwidth=1, relheight=1)
        ov.lift()
        self._fade_ov = ov
        stips = ["gray75", "gray50", "gray25", "gray12", ""]

        def step(i):
            try:
                if not ov.winfo_exists():
                    return
            except Exception:
                return

            if i >= len(stips):
                try: ov.destroy()
                except: pass
                self._fade_ov = None
                return

            try:
                ov.delete("all")
                if stips[i]:
                    w = self.content.winfo_width()
                    h = self.content.winfo_height()
                    if w > 0 and h > 0:
                        ov.create_rectangle(0, 0, w, h, fill=BG, stipple=stips[i], outline="")
            except Exception:
                try: ov.destroy()
                except: pass
                self._fade_ov = None
                return

            ov.after(32, lambda: step(i + 1))

        step(0)

    # ─── HELPERS ───────────────────────────────────────────────────
    def _show_toast(self, title, msg, icon="✅", color=ACCENT, duration=4000):
        try: ToastNotification(self,title,msg,icon,color,duration)
        except: pass

    def _btn(self, parent, text, bg, fg, cmd, **kw):
        b = tk.Button(parent,text=text,command=cmd,bg=bg,fg=fg,
                      relief="flat",cursor="hand2",bd=0,
                      font=("Segoe UI",10,"bold"),padx=18,pady=8,
                      activebackground=_lighter(bg,18),activeforeground=fg,**kw)
        b.bind("<Enter>",lambda e: b.config(bg=_lighter(bg,18)))
        b.bind("<Leave>",lambda e: b.config(bg=bg))
        return b

    def _page_hdr(self, parent, title, subtitle=None):
        wrap = tk.Frame(parent, bg=BG); wrap.pack(fill="x", padx=28, pady=(28, 0))
        f = tk.Frame(wrap, bg=BG); f.pack(fill="x")
        tk.Label(f, text=title, font=("Consolas",22,"bold"), bg=BG, fg=TEXT).pack(side="left")
        if subtitle:
            tk.Label(f, text=subtitle, font=("Segoe UI",9), bg=BG, fg=TEXT_DIM).pack(side="right")
        tk.Frame(wrap, bg=BORDER, height=1).pack(fill="x", pady=(10, 14))
        return f

    def _tick_clock(self):
        try: self._dash_time.config(text=datetime.datetime.now().strftime("%a, %d %b %Y   %H:%M:%S"))
        except: pass
        self.after(1000,self._tick_clock)

    def _update_stats(self):
        try:
            self._stat_cards["files"].update_value(self.data["total_scanned"])
            self._stat_cards["threats"].update_value(self.data["total_threats"])
            self._stat_cards["quar"].update_value(len(self.data["quarantine"]))
            self._stat_cards["scans"].update_value(len(self.data["scan_history"]))
        except: pass
        self._update_score()

    def _update_score(self):
        rtp   = self.data.get("rt_protections",{})
        total = len(DEFAULT_RT)
        active= sum(1 for k,v in rtp.items() if v)
        rt_on = self.data.get("realtime",True)
        score = int((active/total)*70+(30 if rt_on else 0))
        color = ACCENT if score>=80 else WARNING if score>=50 else DANGER
        try:
            self._score_bar._fill = color
            self._score_bar.set(score/100)
            self._score_pct_lbl.config(text=f"{score}%",fg=color)
        except: pass
        try: self._dash_score.config(text=f"{score}%",fg=color)
        except: pass
        return score

    def _update_protection_status(self, ok):
        try:
            self._shield.set_ok(ok)
            self._status_title.config(
                text="Your device is protected" if ok else "⚠️  Not fully protected",fg=TEXT)
            self._status_sub.config(
                text="All protections active  •  PREMIUM" if ok else "Real-time protection is disabled",
                fg=TEXT_MID)
        except: pass
        self._update_tray(ok)

    # ─── DASHBOARD ────────────────────────────────────────────────
    def _build_dashboard(self):
        p = self._pages["dashboard"]
        sf = ScrollableFrame(p); sf.pack(fill="both", expand=True)
        inner = sf.inner

        # ── Hero status card ───────────────────────────────────────
        hero = tk.Frame(inner, bg="#0b1428"); hero.pack(fill="x", padx=0, pady=0)
        tk.Frame(hero, bg=ACCENT, height=3).pack(fill="x")
        hi = tk.Frame(hero, bg="#0b1428"); hi.pack(fill="x", padx=36, pady=(24,24))

        self._shield = PulseShield(hi, size=124, bg="#0b1428")
        self._shield.pack(side="left", padx=(0,28))

        ht = tk.Frame(hi, bg="#0b1428"); ht.pack(side="left", fill="x", expand=True)
        self._status_title = tk.Label(ht, text="Your Device is Protected",
            font=("Segoe UI",20,"bold"), bg="#0b1428", fg=TEXT)
        self._status_title.pack(anchor="w")
        self._status_sub = tk.Label(ht, text="All shields active  •  Real-time monitoring ON",
            font=("Segoe UI",10), bg="#0b1428", fg=TEXT_MID)
        self._status_sub.pack(anchor="w", pady=(4,12))
        sc_row = tk.Frame(ht, bg="#0b1428"); sc_row.pack(anchor="w")
        tk.Label(sc_row, text="PROTECTION SCORE", font=("Segoe UI",7,"bold"),
                 bg="#0b1428", fg=TEXT_DIM).pack(side="left", pady=(0,1))
        self._dash_score = tk.Label(sc_row, text="100%",
            font=("Consolas",22,"bold"), bg="#0b1428", fg=ACCENT)
        self._dash_score.pack(side="left", padx=(10,0))
        self._dash_time = tk.Label(sc_row, text="",
            font=("Segoe UI",8), bg="#0b1428", fg=TEXT_DIM)
        self._dash_time.pack(side="left", padx=(20,0))

        # Quick action buttons in hero
        qbf = tk.Frame(hi, bg="#0b1428"); qbf.pack(side="right", anchor="center")
        self._btn(qbf,"⚡  Quick Scan",ACCENT,BG,
                  lambda: self._quick_action("quick")).pack(fill="x",pady=(0,8))
        self._btn(qbf,"🔍  Full Scan",ACCENT2,BG,
                  lambda: self._quick_action("full")).pack(fill="x",pady=(0,8))
        self._btn(qbf,"📁  Custom Scan","#1a2240",TEXT,
                  lambda: self._quick_action("custom")).pack(fill="x")

        tk.Frame(hero, bg=BORDER, height=1).pack(fill="x")

        # ── Stat cards ─────────────────────────────────────────────
        cards = tk.Frame(inner, bg=BG); cards.pack(fill="x", padx=20, pady=(18,0))
        self._stat_cards = {}
        for i,(k,t,v,ic,c) in enumerate([
            ("files",  "Files Scanned",           self.data["total_scanned"],    "📁", ACCENT2),
            ("threats","Threats Detected",          self.data["total_threats"],    "🦠", DANGER),
            ("quar",   "In Quarantine",             len(self.data["quarantine"]),  "🔒", WARNING),
            ("scans",  "Total Scans",               len(self.data["scan_history"]),"🔍", ACCENT),
        ]):
            sc = StatCard(cards, t, v, ic, c)
            sc.grid(row=0, column=i, padx=6, pady=0, sticky="nsew")
            cards.columnconfigure(i, weight=1)
            self._stat_cards[k] = sc

        # ── Two-column lower section ────────────────────────────────
        lower = tk.Frame(inner, bg=BG); lower.pack(fill="x", padx=20, pady=(14,0))
        lower.columnconfigure(0, weight=3); lower.columnconfigure(1, weight=2)

        # Recent events (left)
        ev_card = tk.Frame(lower, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        ev_card.grid(row=0, column=0, padx=(6,5), sticky="nsew")
        tk.Frame(ev_card, bg=ACCENT, height=2).pack(fill="x")
        eh = tk.Frame(ev_card, bg=CARD); eh.pack(fill="x", padx=16, pady=(10,6))
        tk.Label(eh, text="Recent Threat Events",
                 font=("Segoe UI",10,"bold"), bg=CARD, fg=TEXT).pack(side="left")
        tk.Label(eh, text="last 6", font=("Segoe UI",7),
                 bg=CARD, fg=TEXT_DIM).pack(side="right")
        self._rt_feed = tk.Frame(ev_card, bg=CARD)
        self._rt_feed.pack(fill="x", padx=0, pady=(0,10))
        self._refresh_rt_feed()

        # Status panel (right)
        st_card = tk.Frame(lower, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        st_card.grid(row=0, column=1, padx=(5,6), sticky="nsew")
        tk.Frame(st_card, bg=ACCENT2, height=2).pack(fill="x")
        tk.Label(st_card, text="Protection Status",
                 font=("Segoe UI",10,"bold"), bg=CARD, fg=TEXT
                 ).pack(anchor="w", padx=16, pady=(12,8))
        rtp = self.data.get("rt_protections",{})
        for key,(icon,title,_,__) in RT_META.items():
            on = rtp.get(key, True)
            row = tk.Frame(st_card, bg=CARD); row.pack(fill="x", padx=14, pady=2)
            dot_c = ACCENT if on else "#2a2a40"
            tk.Label(row, text="●", font=("Segoe UI",8), bg=CARD, fg=dot_c).pack(side="left")
            tk.Label(row, text=f"  {title}", font=("Segoe UI",8),
                     bg=CARD, fg=TEXT_MID if on else TEXT_DIM).pack(side="left")
            tk.Label(row, text="ON" if on else "OFF",
                     font=("Segoe UI",7,"bold"), bg=CARD,
                     fg=ACCENT if on else DANGER).pack(side="right")
        tk.Frame(st_card, bg=CARD, height=12).pack()

        tk.Frame(inner, bg=BG, height=24).pack()  # bottom padding

    def _refresh_rt_feed(self):
        for w in self._rt_feed.winfo_children(): w.destroy()
        events = self.data.get("rt_events",[])[-6:]
        if not events:
            tk.Label(self._rt_feed, text="No events yet  ✅",
                     font=("Segoe UI",9), bg=CARD, fg=TEXT_DIM).pack(pady=20, padx=16, anchor="w")
            return
        for ev in reversed(events):
            sev = ev.get("severity","")
            c = DANGER if sev=="Critical" else WARNING if sev=="High" else GOLD
            row = tk.Frame(self._rt_feed, bg=CARD); row.pack(fill="x")
            tk.Frame(row, bg=c, width=3).pack(side="left", fill="y")
            body = tk.Frame(row, bg=CARD); body.pack(side="left", fill="x", expand=True, padx=12, pady=8)
            top2 = tk.Frame(body, bg=CARD); top2.pack(fill="x")
            tk.Label(top2, text=ev.get("name",""), font=("Segoe UI",9,"bold"),
                     bg=CARD, fg=c).pack(side="left")
            tk.Label(top2, text=ev.get("date",""), font=("Segoe UI",7),
                     bg=CARD, fg=TEXT_DIM).pack(side="right")
            fp = ev.get("file",""); short = ("…"+fp[-42:]) if len(fp)>45 else fp
            tk.Label(body, text=short, font=("Segoe UI",8),
                     bg=CARD, fg=TEXT_MID).pack(anchor="w")
            tk.Frame(self._rt_feed, bg=BORDER, height=1).pack(fill="x")

    def _quick_action(self, st):
        tel_event("scan_started", scan_type=st)
        self._show_page("scan")
        self.after(120, lambda: self._start_scan(st))

    # ─── SCAN ─────────────────────────────────────────────────────
    def _build_scan(self):
        p = self._pages["scan"]
        # TOP: fixed controls section; BOTTOM: results expand
        top = tk.Frame(p, bg=BG); top.pack(fill="x", side="top")
        self._page_hdr(top, "Virus Scanner")

        tf = tk.Frame(top,bg=BG); tf.pack(fill="x",padx=28)
        self._scan_type = tk.StringVar(value="quick")
        self._type_frames = {}
        for i,(k,ic,t,d,c) in enumerate([
            ("quick","⚡","Quick Scan","Common threat locations\n~1–2 min",ACCENT),
            ("full","🔍","Full Scan","Deep system scan\nMay take a while",ACCENT2),
            ("custom","📁","Custom Scan","Choose a specific\nfile or folder",WARNING),
        ]):
            fr = tk.Frame(tf,bg=CARD,highlightbackground=BORDER,highlightthickness=2,cursor="hand2")
            fr.grid(row=0,column=i,padx=6,sticky="nsew")
            tf.columnconfigure(i,weight=1)
            tk.Label(fr,text=ic,font=("Segoe UI Emoji",30),bg=CARD,fg=c).pack(pady=(18,4))
            tk.Label(fr,text=t,font=("Segoe UI",12,"bold"),bg=CARD,fg=TEXT).pack()
            tk.Label(fr,text=d,font=("Segoe UI",8),bg=CARD,fg=TEXT_DIM,justify="center").pack(pady=(4,18))
            self._type_frames[k] = (fr,c)
            for w in [fr]+list(fr.winfo_children()):
                w.bind("<Button-1>",lambda e,kk=k: self._sel_type(kk))

        # Custom path lives inside TOP so it never gets pushed below results
        self._custom_frame = tk.Frame(top, bg=BG)
        self._custom_path = tk.StringVar(value="")
        _path_lbl_row = tk.Frame(self._custom_frame, bg=BG)
        _path_lbl_row.pack(fill="x", pady=(8,3), padx=28)
        tk.Label(_path_lbl_row, text="📂  Scan target",
                 font=("Segoe UI",9,"bold"), bg=BG, fg=TEXT_MID).pack(side="left")
        tk.Label(_path_lbl_row, text="Enter a path manually, or use the buttons",
                 font=("Segoe UI",8), bg=BG, fg=TEXT_DIM).pack(side="left", padx=(10,0))
        pr = tk.Frame(self._custom_frame, bg=CARD, highlightbackground=ACCENT2, highlightthickness=1)
        pr.pack(fill="x", padx=28)
        self._path_entry = tk.Entry(pr, textvariable=self._custom_path,
                 bg=CARD, fg=TEXT_DIM, insertbackground=TEXT, relief="flat",
                 font=("Segoe UI",10), highlightthickness=0)
        self._path_entry.pack(side="left", fill="x", expand=True, ipady=9, padx=(12,4))
        _PH = "Type a path, e.g.  C:\\Users\\You\\Downloads"
        self._path_entry.insert(0, _PH)
        def _in(e):
            if self._path_entry.get()==_PH:
                self._path_entry.delete(0,"end"); self._path_entry.config(fg=TEXT)
        def _out(e):
            if not self._path_entry.get().strip():
                self._custom_path.set(""); self._path_entry.config(fg=TEXT_DIM)
                self._path_entry.delete(0,"end"); self._path_entry.insert(0,_PH)
        self._path_entry.bind("<FocusIn>",_in); self._path_entry.bind("<FocusOut>",_out)
        bb2 = tk.Frame(self._custom_frame, bg=BG)
        bb2.pack(fill="x", padx=28, pady=(6,0))
        self._btn(bb2,"📁  Browse Folder",ACCENT2,BG,self._browse_folder).pack(side="left",padx=(0,8))
        self._btn(bb2,"📄  Browse File",BORDER,TEXT,self._browse_file).pack(side="left")
        self._sel_type("quick")

        ctrl = tk.Frame(top,bg=BG); ctrl.pack(fill="x",padx=28,pady=10)
        self._scan_btn = self._btn(ctrl,"▶  Start Scan",ACCENT,BG,self._start_scan)
        self._scan_btn.pack(side="left")
        self._cancel_btn = self._btn(ctrl,"⏹  Cancel",DANGER,"#fff",self._cancel_scan)
        self._cancel_btn.pack(side="left",padx=8)
        self._cancel_btn.config(state="disabled")

        pf = tk.Frame(top,bg=BG); pf.pack(fill="x",padx=28,pady=(0,6))
        self._scan_lbl = tk.Label(pf,text="Ready to scan",font=("Segoe UI",10),bg=BG,fg=TEXT_DIM)
        self._scan_lbl.pack(anchor="w")
        self._scan_bar = AnimatedProgressBar(pf,height=8)
        self._scan_bar.pack(fill="x",pady=(4,0))
        self._scan_pct = tk.Label(pf,text="",font=("Consolas",9),bg=BG,fg=ACCENT)
        self._scan_pct.pack(anchor="e")

        # Results fill remaining space
        res = tk.Frame(p,bg=BG); res.pack(fill="both",expand=True,padx=28,pady=(0,4))
        rh = tk.Frame(res,bg=BG); rh.pack(fill="x")
        tk.Label(rh,text="Scan Results",font=("Segoe UI",11,"bold"),bg=BG,fg=TEXT).pack(side="left")
        self._res_cnt = tk.Label(rh,text="",font=("Segoe UI",9),bg=BG,fg=TEXT_DIM)
        self._res_cnt.pack(side="right")
        # Pack action bar FIRST so it claims space before treeview expands
        ar = tk.Frame(res,bg=BG); ar.pack(fill="x",pady=(6,10),side="bottom")
        tk.Frame(res,bg=BORDER,height=1).pack(fill="x",side="bottom")
        self._btn(ar,"🔒  Quarantine",WARNING,BG,self._quar_sel).pack(side="left",padx=(0,8))
        self._btn(ar,"🗑️  Delete",DANGER,"#fff",self._del_sel).pack(side="left",padx=(0,8))
        self._btn(ar,"✅  Ignore",BORDER,TEXT,self._ign_sel).pack(side="left")
        self._btn(ar,"🚫  Add Exclusion",BORDER,TEXT,self._excl_sel).pack(side="right")
        # Now treeview fills remaining space
        trf = tk.Frame(res,bg=BG); trf.pack(fill="both",expand=True,pady=(4,0))
        self._res_tree = ttk.Treeview(trf,
            columns=("file","threat","category","severity","action"),
            show="headings",style="Gifty.Treeview")
        for col,w,lbl in [("file",310,"File"),("threat",150,"Threat"),
                           ("category",110,"Category"),("severity",80,"Severity"),("action",110,"Action")]:
            self._res_tree.heading(col,text=lbl); self._res_tree.column(col,width=w,minwidth=60)
        vs = DarkScrollbar(trf,orient="vertical",command=self._res_tree.yview)
        self._res_tree.configure(yscrollcommand=vs.set)
        vs.pack(side="right",fill="y"); self._res_tree.pack(fill="both",expand=True)
        self._res_tree.bind("<Button-3>",self._scan_ctx)

    def _setup_tree_styles(self):
        s = ttk.Style(); s.theme_use("clam")
        # ── Treeviews ──
        for n in ("Gifty.Treeview","Q.Treeview","H.Treeview","Excl.Treeview","Net.Treeview","Startup.Treeview"):
            s.configure(n, background=CARD, fieldbackground=CARD,
                        foreground=TEXT, rowheight=32, font=("Segoe UI",9),
                        borderwidth=0, relief="flat")
            s.configure(f"{n}.Heading", background="#0d1228", foreground=ACCENT2,
                        font=("Segoe UI",9,"bold"), relief="flat",
                        borderwidth=0, padding=(10,8))
            s.map(n,
                background=[("selected","#1e2a50")],
                foreground=[("selected",ACCENT)])
            s.map(f"{n}.Heading",
                background=[("active","#111830")],
                relief=[("active","flat")])
        # ── Scrollbars — kill the default look entirely ──
        for sb in ("Vertical.TScrollbar","Horizontal.TScrollbar","TScrollbar"):
            s.configure(sb,
                background=BORDER, troughcolor=PANEL,
                arrowcolor=TEXT_DIM, bordercolor=PANEL,
                lightcolor=BORDER, darkcolor=BORDER, relief="flat",
                arrowsize=10, width=10)
            s.map(sb,
                background=[("active",TEXT_MID),("pressed",ACCENT)],
                arrowcolor=[("active",ACCENT)])
        # ── Combobox ──
        s.configure("TCombobox",
            fieldbackground=CARD, background=CARD,
            foreground=TEXT, selectbackground=BORDER,
            selectforeground=ACCENT, arrowcolor=TEXT_MID,
            bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
            relief="flat", padding=(8,6))
        s.map("TCombobox",
            fieldbackground=[("readonly",CARD)],
            foreground=[("readonly",TEXT)])
        # ── Separator ──
        s.configure("TSeparator", background=BORDER)
        # ── Notebook (if used) ──
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=PANEL, foreground=TEXT_DIM,
                    padding=(14,6), font=("Segoe UI",9))
        s.map("TNotebook.Tab",
            background=[("selected",CARD)],
            foreground=[("selected",ACCENT)])

    def _sel_type(self, k):
        self._scan_type.set(k)
        for kk,(f,c) in self._type_frames.items():
            f.config(highlightbackground=c if kk==k else BORDER,
                     highlightthickness=2 if kk==k else 1)
        if k=="custom": self._custom_frame.pack(fill="x",pady=(4,0))
        else:           self._custom_frame.pack_forget()

    def _browse_folder(self):
        p = filedialog.askdirectory(title="Select folder to scan")
        if p:
            self._custom_path.set(p)
            self._path_entry.config(fg=TEXT)

    def _browse_file(self):
        p = filedialog.askopenfilename(
            title="Select file to scan",
            filetypes=[
                ("All files",        "*.*"),
                ("Executables",      "*.exe;*.dll;*.bat;*.cmd;*.ps1;*.vbs"),
                ("Scripts",          "*.py;*.js;*.hta;*.wsf"),
            ])
        if p:
            self._custom_path.set(p)
            self._path_entry.config(fg=TEXT)

    def _browse(self):
        self._browse_folder()

    def _start_scan(self, st=None):
        if self._scan_running: return
        if st: self._sel_type(st)
        st = self._scan_type.get()
        if st=="custom":
            p = self._custom_path.get().strip()
            _PLACEHOLDER2 = "Type a path here, e.g.  C:\\Users\\You\\Downloads"
            if not p or p == _PLACEHOLDER2:
                self._show_toast("No Path Selected",
                    "Use 'Browse Folder' or 'Browse File' — or type a path in the box.",
                    "📂", WARNING, 5000)
                return
            if not os.path.exists(p):
                self._show_toast("Path Not Found",
                    f"Cannot find: {p}\nCheck the path and try again.",
                    "❌", DANGER, 5000)
                return
            targets = [p]
        elif st=="quick":
            home = os.path.expanduser("~")
            targets = [os.path.join(home,d) for d in ("Downloads","Desktop","Documents")
                       if os.path.exists(os.path.join(home,d))]
            for ev in ("TEMP","TMP"):
                v = os.environ.get(ev,"")
                if v and os.path.exists(v): targets.append(v)
        else:
            targets = [os.path.expanduser("~")]

        for r in self._res_tree.get_children(): self._res_tree.delete(r)
        self._res_cnt.config(text="")
        self._scan_bar.set(0)
        self._scan_lbl.config(text="Initializing…",fg=ACCENT)
        self._scan_btn.config(state="disabled")
        self._cancel_btn.config(state="normal")
        self._scan_running = True; self._scan_cancel = False
        self._scan_started_at = time.time()
        threading.Thread(target=self._run_scan,args=(targets,st),daemon=True).start()

    def _run_scan(self, targets, stype):
        files=[]; exclusions=self.data.get("exclusions",[])
        for t in targets:
            if os.path.isfile(t): files.append(t)
            else:
                for root,dirs,fns in os.walk(t,onerror=lambda e:None):
                    dirs[:] = [d for d in dirs if os.path.join(root,d) not in exclusions]
                    files.extend(os.path.join(root,fn) for fn in fns)
                    if stype=="quick":
                        dirs[:] = [d for d in dirs if not d.startswith(".")
                                   and d not in {"node_modules","__pycache__",".git","venv",".venv"}]
        total=max(len(files),1); threats=[]; scanned=0
        for fp in files:
            if self._scan_cancel: break
            scanned+=1
            if any(fp.startswith(ex) for ex in exclusions): continue
            pct=scanned/total
            disp = fp if len(fp)<60 else "…"+fp[-57:]
            self.after(0,lambda d=disp: self._scan_lbl.config(text=f"Scanning: {d}"))
            self.after(0,lambda p=pct: self._scan_bar.set(p))
            self.after(0,lambda s=scanned,t=total: self._scan_pct.config(text=f"{s:,} / {t:,}"))
            r = analyze_file(fp)
            if r:
                tn,cat,sev=r; threats.append((fp,tn,cat,sev))
                act="Auto-Quarantined" if self.data["settings"].get("auto_quarantine") else "Detected"
                self.after(0, lambda f2=fp,t2=tn,c2=cat,s2=sev,a2=act:
                    self._add_res(f2,t2,c2,s2,a2))
                if self.data["settings"].get("auto_quarantine"):
                    self._do_quar(fp,tn,cat,sev)
                fb_report_detection(tn, cat, sev, fp, source="scan")
        self.after(0, lambda: self._scan_done(scanned,threats,stype))

    def _add_res(self, fp, tn, cat, sev, act):
        tag = {"Critical":"crit","High":"high","Medium":"med","Low":"low"}.get(sev,"")
        iid = self._res_tree.insert("","end",values=(fp,tn,cat,sev,act),tags=(tag,))
        self._res_tree.tag_configure("crit",foreground=DANGER)
        self._res_tree.tag_configure("high",foreground=WARNING)
        self._res_tree.tag_configure("med", foreground=GOLD)
        self._res_tree.tag_configure("low", foreground=ACCENT)

    def _scan_done(self, scanned, threats, stype):
        self._scan_running = False
        duration = int(time.time() - getattr(self, "_scan_started_at", time.time()))
        tel_event("scan_completed",
                  scan_type=stype,
                  files_scanned=int(scanned),
                  threats_found=len(threats),
                  duration_sec=duration,
                  cancelled=bool(self._scan_cancel))
        self._scan_btn.config(state="normal")
        self._cancel_btn.config(state="disabled")
        self._scan_bar.set(1)
        entry = {
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "scan_type": stype, "files_scanned": scanned,
            "threats_found": len(threats),
            "threats": [{"file":t[0],"name":t[1],"cat":t[2],"sev":t[3]} for t in threats],
        }
        self.data["scan_history"].append(entry)
        self.data["total_scanned"] += scanned
        self.data["total_threats"] += len(threats)
        save_data(self.data); self._update_stats()
        fg = DANGER if threats else ACCENT
        self._scan_lbl.config(
            text=f"✅ Complete — {scanned:,} files, {len(threats)} threat(s)", fg=fg)
        if not threats:
            self._show_toast("Scan Complete — All Clear",
                f"✅  {scanned:,} files scanned, no threats detected",
                "✅", ACCENT, 5000)
        self._res_cnt.config(text=f"{len(threats)} threat(s) in {scanned:,} files")
        if threats:
            self._show_toast("Threats Detected",
                f"⚠️  {len(threats)} threat(s) found in {scanned:,} files",
                "🦠", DANGER, 7000)
            InfoDialog(self, "Threats Detected!",
                       f"⚠️  {len(threats)} threat(s) found!\nReview the list and take action.",
                       "🦠", DANGER)

    def _cancel_scan(self):
        self._scan_cancel = True
        self._scan_lbl.config(text="Cancelling…", fg=WARNING)

    def _scan_ctx(self, event):
        if not self._res_tree.selection(): return
        m = tk.Menu(self, tearoff=0, bg=CARD, fg=TEXT,
                    activebackground=BORDER, activeforeground=ACCENT)
        m.add_command(label="🔒  Quarantine",  command=self._quar_sel)
        m.add_command(label="🗑️  Delete",      command=self._del_sel)
        m.add_command(label="✅  Ignore",       command=self._ign_sel)
        m.add_command(label="🚫  Add Exclusion",command=self._excl_sel)
        m.post(event.x_root, event.y_root)

    def _quar_sel(self):
        for iid in self._res_tree.selection():
            v = self._res_tree.item(iid,"values")
            self._do_quar(v[0],v[1],v[2],v[3])
            self._res_tree.set(iid,"action","Quarantined")

    def _do_quar(self, fp, tn, cat, sev):
        if not any(q["file"]==fp for q in self.data["quarantine"]):
            self.data["quarantine"].append({
                "file":fp,"name":tn,"category":cat,"severity":sev,
                "date":datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                "status":"quarantined"})
            save_data(self.data)
            self._update_stats()

    def _del_sel(self):
        sel = self._res_tree.selection()
        if not sel: return
        dlg = ConfirmDialog(self,"Delete Files","Permanently delete selected file(s)? This cannot be undone.",
                            ok="Delete", danger=True, icon="🗑️")
        if dlg.result:
            for iid in sel:
                try: os.remove(self._res_tree.item(iid,"values")[0])
                except: pass
                self._res_tree.set(iid,"action","Deleted")

    def _ign_sel(self):
        for iid in self._res_tree.selection():
            self._res_tree.set(iid,"action","Ignored")

    def _excl_sel(self):
        for iid in self._res_tree.selection():
            fp = self._res_tree.item(iid,"values")[0]
            if fp not in self.data["exclusions"]:
                self.data["exclusions"].append(fp)
                save_data(self.data)
                self._res_tree.set(iid,"action","Excluded")
        self._refresh_exclusions()

    # ──────────────────────────────────────────────────────────────
    # QUARANTINE
    # ──────────────────────────────────────────────────────────────
    def _build_quarantine(self):
        p = self._pages["quarantine"]
        self._page_hdr(p,"Quarantine Vault")
        info = tk.Frame(p, bg="#150e00", highlightbackground=WARNING, highlightthickness=1)
        info.pack(fill="x", padx=28, pady=(0,10))
        tk.Label(info, text="⚠️  Quarantined files are isolated and cannot harm your system.",
                 font=("Segoe UI",9), bg="#150e00", fg=WARNING).pack(anchor="w", padx=12, pady=8)

        hdr2 = tk.Frame(p, bg=BG); hdr2.pack(fill="x", padx=28)
        tk.Label(hdr2, text="Quarantined items:", font=("Segoe UI",9),
                 bg=BG, fg=TEXT_DIM).pack(side="left")
        self._q_cnt = tk.Label(hdr2, text="", font=("Segoe UI",9,"bold"),
                                bg=BG, fg=WARNING)
        self._q_cnt.pack(side="left", padx=6)

        trf = tk.Frame(p, bg=BG); trf.pack(fill="both", expand=True, padx=28, pady=8)
        self._q_tree = ttk.Treeview(trf,
            columns=("file","name","category","severity","date","status"),
            show="headings", style="Q.Treeview")
        for col,w,lbl in [("file",290,"File"),("name",140,"Threat"),
                           ("category",100,"Category"),("severity",80,"Severity"),
                           ("date",120,"Date"),("status",90,"Status")]:
            self._q_tree.heading(col,text=lbl); self._q_tree.column(col,width=w,minwidth=60)
        qs = DarkScrollbar(trf,orient="vertical",command=self._q_tree.yview)
        self._q_tree.configure(yscrollcommand=qs.set)
        qs.pack(side="right",fill="y"); self._q_tree.pack(fill="both",expand=True)

        ar = tk.Frame(p, bg=BG); ar.pack(fill="x", padx=28, pady=14)
        self._btn(ar,"♻️  Restore",ACCENT,BG,    self._restore_q).pack(side="left",padx=(0,8))
        self._btn(ar,"🗑️  Delete", DANGER,"#fff", self._del_q).pack(side="left",padx=(0,8))
        self._btn(ar,"🗑️  Clear All",BORDER,TEXT, self._clear_q).pack(side="right")

    def _refresh_quarantine(self):
        for r in self._q_tree.get_children(): self._q_tree.delete(r)
        for q in self.data["quarantine"]:
            self._q_tree.insert("","end",values=(
                q["file"],q["name"],q["category"],q["severity"],q["date"],q["status"]))
        self._q_cnt.config(text=f'{len(self.data["quarantine"])} item(s)')
        self._update_stats()

    def _restore_q(self):
        sel = self._q_tree.selection()
        if not sel: return
        dlg = ConfirmDialog(self,"Restore Files","Restore selected items from quarantine?",
                            ok="Restore", icon="♻️")
        if dlg.result:
            fs = {self._q_tree.item(i,"values")[0] for i in sel}
            self.data["quarantine"] = [q for q in self.data["quarantine"] if q["file"] not in fs]
            save_data(self.data); self._refresh_quarantine()

    def _del_q(self):
        sel = self._q_tree.selection()
        if not sel: return
        dlg = ConfirmDialog(self,"Delete Files","Permanently delete selected quarantined file(s)?",
                            ok="Delete", danger=True, icon="🗑️")
        if dlg.result:
            for i in sel:
                try: os.remove(self._q_tree.item(i,"values")[0])
                except: pass
            fs = {self._q_tree.item(i,"values")[0] for i in sel}
            self.data["quarantine"] = [q for q in self.data["quarantine"] if q["file"] not in fs]
            save_data(self.data); self._refresh_quarantine()

    def _clear_q(self):
        dlg = ConfirmDialog(self,"Clear Quarantine","Remove all items from the quarantine vault?",
                            ok="Clear All", danger=True, icon="🗑️")
        if dlg.result:
            self.data["quarantine"]=[]; save_data(self.data); self._refresh_quarantine()

    # ──────────────────────────────────────────────────────────────
    # HISTORY
    # ──────────────────────────────────────────────────────────────
    def _build_history(self):
        p = self._pages["history"]
        hdr = self._page_hdr(p,"Scan History")
        self._btn(hdr,"🗑️  Clear History",BORDER,TEXT,self._clear_hist).pack(side="right")
        self._btn(hdr,"⬇️  Export CSV",ACCENT2,BG,self._export_history_csv).pack(side="right", padx=(0,8))

        trf = tk.Frame(p, bg=BG); trf.pack(fill="both", expand=True, padx=28, pady=(0,16))
        self._h_tree = ttk.Treeview(trf,
            columns=("date","type","scanned","threats"),
            show="headings", style="H.Treeview")
        for col,w,lbl in [("date",170,"Date & Time"),("type",130,"Scan Type"),
                           ("scanned",160,"Files Scanned"),("threats",130,"Threats Found")]:
            self._h_tree.heading(col,text=lbl); self._h_tree.column(col,width=w,minwidth=80)
        hs = DarkScrollbar(trf,orient="vertical",command=self._h_tree.yview)
        self._h_tree.configure(yscrollcommand=hs.set)
        hs.pack(side="right",fill="y"); self._h_tree.pack(fill="both",expand=True)

    def _refresh_history(self):
        for r in self._h_tree.get_children(): self._h_tree.delete(r)
        for h in reversed(self.data["scan_history"]):
            t = h.get("threats_found",0)
            self._h_tree.insert("","end",values=(
                h["date"],h["scan_type"].title(),f'{h["files_scanned"]:,}',
                t if t else "✅ None"), tags=("threat",) if t else ())
        self._h_tree.tag_configure("threat", foreground=DANGER)

    def _clear_hist(self):
        dlg = ConfirmDialog(self,"Clear History","Clear all scan history records?",
                            ok="Clear", danger=True, icon="🗑️")
        if dlg.result:
            self.data["scan_history"]=[]; save_data(self.data)
            self._refresh_history(); self._update_stats()
            tel_event("history_cleared")

    def _export_history_csv(self):
        if not self.data["scan_history"]:
            self._show_toast("Nothing to Export",
                "Run a scan first — then come back and export.",
                "📭", WARNING, 4500)
            return
        default = f"gifty-scan-history-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}.csv"
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".csv",
            initialfile=default,
            filetypes=[("CSV (Comma-Separated Values)", "*.csv"), ("All files", "*.*")],
            title="Export Scan History to CSV")
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Date","Scan Type","Files Scanned","Threats Found",
                            "Threat Names","Threat Categories","Threat Severities"])
                for h in self.data["scan_history"]:
                    threats = h.get("threats", []) or []
                    names = "; ".join(t.get("name","") for t in threats)
                    cats  = "; ".join(t.get("cat","")  for t in threats)
                    sevs  = "; ".join(t.get("sev","")  for t in threats)
                    w.writerow([
                        h.get("date",""),
                        h.get("scan_type",""),
                        h.get("files_scanned",0),
                        h.get("threats_found",0),
                        names, cats, sevs,
                    ])
            self._show_toast("Export Complete",
                f"{len(self.data['scan_history'])} scan(s) exported.",
                "✅", ACCENT, 5000)
            tel_event("history_exported", rows=len(self.data["scan_history"]))
        except Exception as e:
            self._show_toast("Export Failed", str(e), "❌", DANGER, 6000)

    # ──────────────────────────────────────────────────────────────
    # REAL-TIME PROTECTION
    # ──────────────────────────────────────────────────────────────
    def _build_realtime(self):
        p = self._pages["realtime"]
        sf = ScrollableFrame(p); sf.pack(fill="both", expand=True)
        inner = sf.inner
        self._page_hdr(inner, "Real-Time Protection")

        # Master toggle card
        tc = tk.Frame(inner, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        tc.pack(fill="x", padx=28, pady=(0,14))
        row = tk.Frame(tc, bg=CARD); row.pack(fill="x", padx=20, pady=18)

        self._rt_shield_icon = tk.Label(row, text="🛡️", font=("Segoe UI Emoji",36),
                                         bg=CARD, fg=ACCENT)
        self._rt_shield_icon.pack(side="left", padx=(0,18))
        ic = tk.Frame(row, bg=CARD); ic.pack(side="left", fill="x", expand=True)
        self._rt_title = tk.Label(ic, text="Real-Time Protection Active",
                                   font=("Segoe UI",14,"bold"), bg=CARD, fg=ACCENT)
        self._rt_title.pack(anchor="w")
        self._rt_sub = tk.Label(ic, text="Monitoring your system continuously for threats",
                                 font=("Segoe UI",9), bg=CARD, fg=TEXT_DIM)
        self._rt_sub.pack(anchor="w", pady=(4,0))

        # Master toggle
        self._master_rt_var = tk.BooleanVar(value=self.data.get("realtime",True))
        self._master_toggle = ToggleSwitch(row, self._master_rt_var,
                                            on_toggle=self._toggle_master_rt, bg=CARD)
        self._master_toggle.pack(side="right")

        # Separator
        tk.Frame(tc, bg=BORDER, height=1).pack(fill="x", padx=20)

        # Stats row in RT card
        sr = tk.Frame(tc, bg=CARD); sr.pack(fill="x", padx=20, pady=10)
        self._rt_events_count = tk.Label(sr, text="0 events today",
                                          font=("Segoe UI",9), bg=CARD, fg=TEXT_MID)
        self._rt_events_count.pack(side="left")
        engine_lbl = "watchdog engine" if HAS_WATCHDOG else "polling engine"
        tk.Label(sr, text=f"Engine: {engine_lbl}", font=("Segoe UI",8),
                 bg=CARD, fg=TEXT_DIM).pack(side="right")

        # Individual protection rows
        tk.Label(inner, text="Individual Protections", font=("Segoe UI",12,"bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", padx=28, pady=(0,6))

        self._prot_rows = {}
        for key, (icon, title, desc, default) in RT_META.items():
            self._prot_rows[key] = self._build_prot_row(inner, key, icon, title, desc)

        # Activity log
        tk.Label(inner, text="Activity Log", font=("Segoe UI",12,"bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", padx=28, pady=(14,6))
        lc = tk.Frame(inner, bg=BG); lc.pack(fill="x", padx=28, pady=(0,28))
        self._rt_log = tk.Text(lc, bg=CARD, fg=ACCENT, font=("Consolas",8),
                                relief="flat", state="disabled", wrap="word", height=10,
                                highlightbackground=BORDER, highlightthickness=1)
        logbar = DarkScrollbar(lc, orient="vertical", command=self._rt_log.yview)
        self._rt_log.configure(yscrollcommand=logbar.set)
        logbar.pack(side="right", fill="y")
        self._rt_log.pack(fill="x", side="left", expand=True)

        log_btns = tk.Frame(inner, bg=BG); log_btns.pack(fill="x", padx=28, pady=(0,8))
        self._btn(log_btns,"🗑️  Clear Log",BORDER,TEXT,self._clear_rt_log).pack(side="right")

        self._log_rt("System","Gifty Antivirus v3 started. Real-time protection initializing.")

    def _build_prot_row(self, parent, key, icon, title, desc):
        enabled = self.data["rt_protections"].get(key, DEFAULT_RT.get(key, True))
        var = tk.BooleanVar(value=enabled)
        self._rt_toggle_vars[key] = var

        r = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        r.pack(fill="x", padx=28, pady=2)

        # Status indicator dot
        dot = tk.Label(r, text="●", font=("Segoe UI",10),
                       bg=CARD, fg=ACCENT if enabled else TEXT_DIM)
        dot.pack(side="left", padx=(12,6), pady=10)

        tk.Label(r, text=icon, font=("Segoe UI Emoji",14), bg=CARD,
                 fg=ACCENT if enabled else TEXT_DIM).pack(side="left", padx=(0,8), pady=10)

        content = tk.Frame(r, bg=CARD); content.pack(side="left", fill="x", expand=True, pady=8)
        title_lbl = tk.Label(content, text=title, font=("Segoe UI",10,"bold"),
                              bg=CARD, fg=TEXT if enabled else TEXT_DIM)
        title_lbl.pack(anchor="w")
        tk.Label(content, text=desc, font=("Segoe UI",8), bg=CARD, fg=TEXT_DIM).pack(anchor="w")

        ts = ToggleSwitch(r, var, on_toggle=lambda v, k=key: self._toggle_protection(k, v), bg=CARD)
        ts.pack(side="right", padx=16)
        self._rt_toggle_widgets[key] = ts

        return {"frame":r, "dot":dot, "title_lbl":title_lbl, "var":var, "toggle":ts}

    def _toggle_protection(self, key, new_val):
        if not new_val:
            # Turning OFF — show confirmation
            _, title, _, _ = RT_META[key]
            dlg = ConfirmDialog(self,
                f"Disable {title}?",
                f"Are you sure you want to disable {title}?\n"
                "Your system may be less protected.",
                ok="Disable", cancel="Keep Enabled",
                danger=True, icon="⚠️")
            if not dlg.result:
                # User cancelled — snap toggle back to ON visually
                self._rt_toggle_widgets[key].force_value(True)
                return
        # Apply the change
        self.data["rt_protections"][key] = new_val
        save_data(self.data)
        tel_event("protection_toggled", protection=str(key), on=bool(new_val))
        row = self._prot_rows.get(key, {})
        try:
            row["dot"].config(fg=ACCENT if new_val else TEXT_DIM)
            row["title_lbl"].config(fg=TEXT if new_val else TEXT_DIM)
            row["toggle"].force_value(new_val)
        except: pass
        self._log_rt(
            "INFO" if new_val else "WARNING",
            f"{RT_META[key][1]} {'enabled' if new_val else 'DISABLED'}.")
        self._update_score()

    def _toggle_master_rt(self, new_val):
        if not new_val:
            dlg = ConfirmDialog(self,
                "Disable Real-Time Protection?",
                "This will disable ALL real-time monitoring.\n"
                "Your system will be significantly less protected.",
                ok="Disable All", cancel="Keep Active",
                danger=True, icon="🛡️")
            if not dlg.result:
                # User cancelled — snap master toggle back to ON visually
                self._master_toggle.force_value(True)
                return
        self.data["realtime"] = new_val
        save_data(self.data)
        tel_event("realtime_toggled", on=bool(new_val))
        self._master_rt_var.set(new_val)
        self._master_toggle.force_value(new_val)
        if new_val:
            self._start_realtime()
            self._rt_title.config(text="Real-Time Protection Active", fg=ACCENT)
            self._rt_sub.config(text="Monitoring your system continuously for threats")
            self._rt_shield_icon.config(fg=ACCENT)
            self._rt_ind.config(text="● REAL-TIME ACTIVE", fg=ACCENT)
            self._log_rt("INFO","Real-time protection ENABLED.")
        else:
            self._rt_running = False
            self._file_monitor.stop()
            self._rt_title.config(text="Real-Time Protection Disabled", fg=DANGER)
            self._rt_sub.config(text="⚠️  Your system is not fully protected")
            self._rt_shield_icon.config(fg=DANGER)
            self._rt_ind.config(text="○ REAL-TIME OFF", fg=DANGER)
            self._log_rt("WARNING","Real-time protection DISABLED.")
        self._update_protection_status(new_val)
        self._update_score()

    def _refresh_rt_ui(self):
        rt_on = self.data.get("realtime", True)
        self._master_rt_var.set(rt_on)
        self._master_toggle.force_value(rt_on)
        for key, row in self._prot_rows.items():
            val = self.data["rt_protections"].get(key, DEFAULT_RT.get(key, True))
            row["var"].set(val)
            row["toggle"].force_value(val)
            color = ACCENT if val else TEXT_DIM
            try:
                row["dot"].config(fg=color)
                row["title_lbl"].config(fg=TEXT if val else TEXT_DIM)
            except: pass
        today_events = sum(1 for e in self.data.get("rt_events",[])
                           if e.get("date","").startswith(datetime.date.today().isoformat()))
        try: self._rt_events_count.config(text=f"{today_events} events today")
        except: pass

    def _rt_registry_watch(self):
        """Poll startup registry keys for new/changed entries."""
        def _snapshot():
            snap = {}
            for hive, keypath, label in GiftyAV._STARTUP_KEYS:
                try:
                    key = winreg.OpenKey(hive, keypath, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(key, i); i += 1
                            snap[f"{label}::{name}"] = val
                        except OSError: break
                    winreg.CloseKey(key)
                except: pass
            return snap
        known = _snapshot()
        while self._rt_running:
            time.sleep(20)
            if not self.data.get("realtime",True): continue
            if not self.data["settings"].get("startup_notify", False): continue
            current = _snapshot()
            for k, v in current.items():
                if k not in known:
                    label, name = k.split("::",1)
                    self.after(0, lambda n=name, vv=v: (
                        self._log_rt("WARNING", f"New startup entry: {n} — {vv[:60]}"),
                        self._show_toast("New Startup Entry",
                            f"'{n}' registered itself to run at boot.\n{vv[:50]}",
                            "🚀", WARNING, 7000)
                    ))
            known = current

    def _on_usb_insert(self, drive):
        self._log_rt("INFO", f"USB drive inserted: {drive}  — scanning root…")
        self._show_toast("Removable Drive Connected",
                         f"Scanning {drive} for threats…",
                         "💾", ACCENT2, 5000)
        # notify when scan finishes
        threading.Thread(target=self._usb_scan_and_notify,
                         args=(drive,), daemon=True).start()

    def _usb_scan_and_notify(self, drive):
        import time as _t; _t.sleep(1.5)
        threats = []
        try:
            for fn in os.listdir(drive):
                fp = os.path.join(drive, fn)
                if os.path.isfile(fp):
                    r = analyze_file(fp)
                    if r: threats.append((fp, r))
        except: pass
        if threats:
            names = ", ".join(t[1][0] for t in threats[:3])
            self.after(0, lambda: self._show_toast(
                "⚠️ Threats on USB Drive",
                f"{len(threats)} threat(s) found on {drive}\n{names}",
                "🦠", DANGER, 8000))
            for fp, (tn, cat, sev) in threats:
                self._rt_threat_detected(fp, (tn, cat, sev))
        else:
            self.after(0, lambda: self._show_toast(
                "USB Drive Clean",
                f"No threats found on {drive}",
                "✅", ACCENT, 4000))

    def _start_realtime(self):
        if self._rt_running: return
        self._rt_running = True
        self._file_monitor.start()
        self._ransom_shield.start()
        self._usb_monitor.start()
        self._mem_scanner.start()
        threading.Thread(target=self._rt_heartbeat, daemon=True).start()
        threading.Thread(target=self._rt_registry_watch, daemon=True).start()

    def _rt_heartbeat(self):
        msgs = [
            "Monitoring Downloads, Desktop, Documents…",
            "Scanning process activity…",
            "Checking system integrity…",
            "Verifying startup entries…",
            "Memory scan in progress…",
            "USB device check…",
            "Threat signature database current.",
        ]
        i = 0
        while self._rt_running:
            time.sleep(10)
            if self._rt_running:
                self.after(0, lambda m=msgs[i % len(msgs)]: self._log_rt("INFO", m))
                i += 1

    def _rt_threat_detected(self, filepath, threat_info):
        tn, cat, sev = threat_info
        ev = {
            "file": filepath, "name": tn, "category": cat,
            "severity": sev,
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.data["rt_events"].append(ev)
        if len(self.data["rt_events"]) > 100:
            self.data["rt_events"] = self.data["rt_events"][-100:]
        self.data["total_threats"] += 1

        if self.data["settings"].get("auto_quarantine"):
            self._do_quar(filepath, tn, cat, sev)

        save_data(self.data)
        fb_report_detection(tn, cat, sev, filepath, source="realtime")
        self.after(0, lambda: self._on_rt_threat(filepath, tn, cat, sev))

    def _on_rt_threat(self, fp, tn, cat, sev):
        self._log_rt("THREAT", f"Detected: {tn} ({sev}) — {Path(fp).name}")
        self._update_stats()
        try: self._refresh_rt_feed()
        except: pass
        if self.data["settings"].get("notifications"):
            InfoDialog(self, "⚠️ Threat Detected!",
                       f"Real-time scan found:\n{tn} ({sev})\n\n{Path(fp).name}",
                       "🦠", DANGER)

    def _log_rt(self, level, msg):
        try:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            colors = {"THREAT":DANGER,"WARNING":WARNING,"INFO":ACCENT,"System":TEXT_MID}
            c = colors.get(level, ACCENT)
            self._rt_log.config(state="normal")
            self._rt_log.insert("end", f"[{ts}]  ", "ts")
            self._rt_log.insert("end", f"[{level}]  ", level)
            self._rt_log.insert("end", f"{msg}\n", "msg")
            self._rt_log.tag_configure("ts",    foreground=TEXT_DIM)
            self._rt_log.tag_configure(level,   foreground=c)
            self._rt_log.tag_configure("msg",   foreground=TEXT_MID)
            self._rt_log.see("end")
            self._rt_log.config(state="disabled")
        except: pass

    def _clear_rt_log(self):
        try:
            self._rt_log.config(state="normal")
            self._rt_log.delete("1.0","end")
            self._rt_log.config(state="disabled")
        except: pass

    # ──────────────────────────────────────────────────────────────
    # EXCLUSIONS
    # ──────────────────────────────────────────────────────────────
    def _build_exclusions(self):
        p = self._pages["exclusions"]
        self._page_hdr(p,"Exclusion List")

        info = tk.Frame(p, bg="#0a1020", highlightbackground=ACCENT2, highlightthickness=1)
        info.pack(fill="x", padx=28, pady=(0,12))
        tk.Label(info,
                 text="ℹ️  Excluded paths are skipped during all scans and real-time monitoring.",
                 font=("Segoe UI",9), bg="#0a1020", fg=ACCENT2).pack(anchor="w", padx=12, pady=8)

        add_f = tk.Frame(p, bg=BG); add_f.pack(fill="x", padx=28, pady=(0,12))
        self._excl_entry = tk.Entry(add_f, bg=CARD, fg=TEXT, insertbackground=TEXT,
                                     relief="flat", font=("Segoe UI",10),
                                     highlightbackground=BORDER, highlightthickness=1)
        self._excl_entry.pack(side="left", fill="x", expand=True, ipady=7, padx=(0,8))
        self._btn(add_f,"📁 Browse", BORDER, TEXT, self._browse_excl).pack(side="left",padx=(0,8))
        self._btn(add_f,"➕ Add",    ACCENT2, BG,  self._add_excl).pack(side="left")

        trf = tk.Frame(p, bg=BG); trf.pack(fill="both", expand=True, padx=28, pady=(0,8))
        self._excl_tree = ttk.Treeview(trf, columns=("path","type"),
                                        show="headings", style="Excl.Treeview")
        self._excl_tree.heading("path",text="Excluded Path")
        self._excl_tree.heading("type",text="Type")
        self._excl_tree.column("path",width=500)
        self._excl_tree.column("type",width=100)
        es = DarkScrollbar(trf,orient="vertical",command=self._excl_tree.yview)
        self._excl_tree.configure(yscrollcommand=es.set)
        es.pack(side="right",fill="y"); self._excl_tree.pack(fill="both",expand=True)

        ar = tk.Frame(p, bg=BG); ar.pack(fill="x", padx=28, pady=14)
        self._btn(ar,"🗑️  Remove Selected",DANGER,"#fff",self._remove_excl).pack(side="left",padx=(0,8))
        self._btn(ar,"🗑️  Clear All",      BORDER,TEXT,  self._clear_excl).pack(side="right")
        self._refresh_exclusions()

    def _browse_excl(self):
        p = filedialog.askdirectory(title="Select folder to exclude")
        if not p:
            p = filedialog.askopenfilename(
                title="Select file to exclude",
                filetypes=[("All files", "*.*"), ("Executables", "*.exe;*.dll;*.bat;*.cmd;*.ps1")])
        if p:
            self._excl_entry.delete(0, "end")
            self._excl_entry.insert(0, p)

    def _add_excl(self):
        path = self._excl_entry.get().strip()
        if not path: return
        if path not in self.data["exclusions"]:
            self.data["exclusions"].append(path)
            save_data(self.data)
            self._refresh_exclusions()
        self._excl_entry.delete(0,"end")

    def _remove_excl(self):
        sel = self._excl_tree.selection()
        if not sel: return
        paths = {self._excl_tree.item(i,"values")[0] for i in sel}
        self.data["exclusions"] = [e for e in self.data["exclusions"] if e not in paths]
        save_data(self.data); self._refresh_exclusions()

    def _clear_excl(self):
        dlg = ConfirmDialog(self,"Clear Exclusions","Remove all exclusions?",
                            ok="Clear All", danger=True)
        if dlg.result:
            self.data["exclusions"]=[]; save_data(self.data); self._refresh_exclusions()

    def _refresh_exclusions(self):
        try:
            for r in self._excl_tree.get_children(): self._excl_tree.delete(r)
            for e in self.data.get("exclusions",[]):
                t = "Folder" if os.path.isdir(e) else "File"
                self._excl_tree.insert("","end",values=(e,t))
        except: pass

    # ──────────────────────────────────────────────────────────────
    # PLANS
    # ──────────────────────────────────────────────────────────────
    def _build_plans(self):
        p = self._pages["plans"]
        sf = ScrollableFrame(p); sf.pack(fill="both", expand=True)
        inner = sf.inner
        self._page_hdr(inner,"Plans & Subscription")

        badge = tk.Frame(inner, bg="#102018", highlightbackground=ACCENT, highlightthickness=1)
        badge.pack(anchor="w", padx=28, pady=(0,16))
        tk.Label(badge,text="✦  PREMIUM PLAN activated — all features unlocked",
                 font=("Segoe UI",11,"bold"), bg="#102018", fg=ACCENT).pack(padx=16,pady=8)

        cr = tk.Frame(inner, bg=BG); cr.pack(fill="x", padx=28, pady=(0,20))
        self._plan_card(cr,"FREE PLAN","$0 / forever",[
            ("Basic signature scanning",True),("Manual scans only",True),
            ("Quarantine vault",True),("Scan history",True),
            ("Real-time protection",False),("Heuristic analysis",False),
            ("Ransomware shield",False),("Individual protection toggles",False),
            ("System tray monitoring",False),("Exclusion list",False),
        ],color=TEXT_DIM).pack(side="left",fill="both",expand=True,padx=(0,8))

        self._plan_card(cr,"PREMIUM PLAN","$4.99 / month",[
            ("Basic signature scanning",True),("Manual & scheduled scans",True),
            ("Quarantine vault",True),("Full scan history",True),
            ("Real-time protection",True),("Heuristic analysis engine",True),
            ("Ransomware shield",True),("Individual protection toggles",True),
            ("System tray monitoring",True),("Exclusion list",True),
        ],active=True,color=ACCENT,badge="★  CURRENT PLAN"
        ).pack(side="left",fill="both",expand=True,padx=(8,0))

    def _plan_card(self, parent, title, price, features, active=False,
                   color=TEXT_DIM, badge=None):
        f = tk.Frame(parent, bg=CARD, highlightthickness=2,
                     highlightbackground=color if active else BORDER)
        if badge:
            bb = tk.Frame(f, bg=color); bb.pack(fill="x")
            tk.Label(bb,text=badge,font=("Segoe UI",9,"bold"),bg=color,fg=BG).pack(pady=4)
        tk.Label(f,text=title,font=("Segoe UI",16,"bold"),
                 bg=CARD,fg=color if active else TEXT_MID).pack(pady=(18,4))
        tk.Label(f,text=price,font=("Consolas",20,"bold"),bg=CARD,fg=TEXT).pack()
        tk.Frame(f,bg=BORDER,height=1).pack(fill="x",padx=20,pady=12)
        for feat,ok in features:
            r = tk.Frame(f,bg=CARD); r.pack(fill="x",padx=20,pady=2)
            tk.Label(r,text="✅" if ok else "❌",font=("Segoe UI",10),
                     bg=CARD).pack(side="left")
            tk.Label(r,text=f"  {feat}",font=("Segoe UI",9),
                     bg=CARD,fg=TEXT if ok else TEXT_DIM,anchor="w").pack(side="left")
        tk.Frame(f,bg=CARD,height=18).pack()
        return f

    # ──────────────────────────────────────────────────────────────
    # SETTINGS
    # ──────────────────────────────────────────────────────────────
    def _build_settings(self):
        p = self._pages["settings"]
        self._page_hdr(p,"Settings")
        sf = ScrollableFrame(p); sf.pack(fill="both", expand=True)
        inner = sf.inner
        self._svars = {}

        def section(t):
            f = tk.Frame(inner, bg=BG); f.pack(fill="x", padx=28, pady=(16,6))
            tk.Label(f,text=t,font=("Segoe UI",11,"bold"),bg=BG,fg=ACCENT).pack(anchor="w")
            ttk.Separator(f).pack(fill="x",pady=(4,0))

        def tog(key, lbl, desc, default=False):
            v = tk.BooleanVar(value=self.data["settings"].get(key,default))
            self._svars[key] = v
            r = tk.Frame(inner,bg=CARD,highlightbackground=BORDER,highlightthickness=1)
            r.pack(fill="x",padx=28,pady=2)
            c = tk.Frame(r,bg=CARD); c.pack(side="left",fill="x",expand=True,padx=16,pady=10)
            tk.Label(c,text=lbl,font=("Segoe UI",10,"bold"),bg=CARD,fg=TEXT).pack(anchor="w")
            tk.Label(c,text=desc,font=("Segoe UI",8),bg=CARD,fg=TEXT_DIM).pack(anchor="w")
            ts = ToggleSwitch(r, v, on_toggle=lambda val, k=key, vr=v: (vr.set(val), self._save_s()), bg=CARD)
            ts.pack(side="right",padx=16)

        def combo(key, lbl, desc, choices, default):
            v = tk.StringVar(value=self.data["settings"].get(key,default))
            self._svars[key] = v
            r = tk.Frame(inner,bg=CARD,highlightbackground=BORDER,highlightthickness=1)
            r.pack(fill="x",padx=28,pady=2)
            c = tk.Frame(r,bg=CARD); c.pack(side="left",fill="x",expand=True,padx=16,pady=10)
            tk.Label(c,text=lbl,font=("Segoe UI",10,"bold"),bg=CARD,fg=TEXT).pack(anchor="w")
            tk.Label(c,text=desc,font=("Segoe UI",8),bg=CARD,fg=TEXT_DIM).pack(anchor="w")
            CustomSelect(r, v, choices, width=160, bg=CARD,
                         on_change=lambda val: self._save_s()).pack(side="right",padx=16,pady=8)

        section("🔍  Scan")
        tog("scan_archives",  "Scan Archives",          "Include .zip, .rar and other archives")
        tog("auto_quarantine","Auto-Quarantine Threats", "Automatically quarantine detected threats", True)
        combo("heuristic_level","Heuristic Sensitivity","Higher = more sensitive but more false positives",
              ["Low","Medium","High","Paranoid"],"Medium")

        section("🛡️  Protection")
        tog("notifications",  "Threat Notifications",   "Show alerts when threats are detected", True)
        tog("scan_on_start",  "Scan on Startup",         "Run a quick scan when the app launches")
        tog("minimize_to_tray","Minimize to System Tray","Keep running in background when closed",True)

        section("🔒  Privacy")
        tog("send_telemetry",   "Anonymous Usage Data",
            "Help improve detection by sharing anonymous feature-usage stats")
        tog("cloud_lookup",     "Cloud Threat Lookup",         "Check hashes against cloud database",      True)

        # ── Privacy info / data deletion buttons ──────────────────────
        prow = tk.Frame(inner, bg=BG); prow.pack(fill="x", padx=28, pady=(2,0))
        self._btn(prow, "👁️  View Exactly What's Collected", BORDER, TEXT,
                  self._show_telemetry_info).pack(side="left", padx=(0,6))
        self._btn(prow, "🌐  Request Data Deletion", BORDER, TEXT,
                  self._open_deletion_site).pack(side="left")

        section("🎨  Interface")
        tog("compact_sidebar",  "Compact Sidebar",            "Show only icons in the sidebar")
        tog("show_file_paths",  "Show Full File Paths",       "Display full paths in scan results instead of short names")
        tog("animate_shield",   "Animate Dashboard Shield",   "Disable to save CPU on low-end machines",  True)

        section("🌐  Network")
        tog("block_c2",        "Block Known C2 Servers",      "Refuse connections to known malware command-and-control IPs")
        tog("dns_protection",  "DNS Protection",              "Warn when apps query suspicious domains")
        tog("net_monitor_auto","Auto-refresh Network Monitor","Refresh the network connections list every 10 s", True)

        section("🚀  Startup")
        tog("startup_scan",    "Scan Startup Entries",        "Flag suspicious entries in the Startup Manager automatically", True)
        tog("startup_notify",  "Notify on New Startup Entry", "Alert when a new program registers itself to run at boot")

        section("⬆️  Updates")
        tog("auto_check_updates",
            "Check for Updates Automatically",
            "Look for new versions on GitHub once per day", True)

        section("ℹ️  About")
        ab = tk.Frame(inner,bg=CARD,highlightbackground=BORDER,highlightthickness=1)
        ab.pack(fill="x",padx=28,pady=2)
        tk.Label(ab,text="Gifty Antivirus — PREMIUM PLAN",
                 font=("Consolas",15,"bold"),bg=CARD,fg=ACCENT).pack(anchor="w",padx=16,pady=(14,0))
        for l in [f"Version {_APP_VERSION}  •  PREMIUM PLAN",
                  f"Update channel: {_GH_REPO}",
                  f"Engine: Gifty Engine v3 | Heuristic v3 | {'watchdog' if HAS_WATCHDOG else 'polling'} monitor"]:
            tk.Label(ab,text=l,font=("Segoe UI",9),bg=CARD,fg=TEXT_DIM).pack(anchor="w",padx=16)
        tk.Frame(ab,bg=CARD,height=14).pack()

        bf = tk.Frame(inner,bg=BG); bf.pack(fill="x",padx=28,pady=(16,28))
        self._btn(bf,"🔄  Check for Updates", ACCENT2,BG,   self._upd_defs).pack(fill="x",pady=(0,4))
        self._btn(bf,"🗑️  Reset All Settings",BORDER,TEXT,  self._reset_s).pack(fill="x")

    def _save_s(self):
        prev_telemetry = bool(self.data["settings"].get("send_telemetry", False))
        for k,v in self._svars.items():
            self.data["settings"][k] = v.get()
        save_data(self.data)
        new_telemetry = bool(self.data["settings"].get("send_telemetry", False))
        if prev_telemetry and not new_telemetry:
            # Consent revoked — sever the anonymous identity so a future
            # opt-in starts as a brand-new install.
            reset_install_id()
        elif not prev_telemetry and new_telemetry:
            # Consent newly granted — fire a session ping so the install
            # appears in the dashboard immediately.
            threading.Thread(target=tel_session_start, daemon=True).start()
        # Apply live settings
        try:
            self._shield._animate = self.data["settings"].get("animate_shield", True)
        except: pass

    def _show_telemetry_info(self):
        on = bool(self.data["settings"].get("send_telemetry", False))
        status = "● ENABLED" if on else "○ DISABLED"
        InfoDialog(self, "What Gets Collected",
            f"Telemetry is currently: {status}\n\n"
            f"Your anonymous install ID:\n  {_get_install_id()}\n\n"
            "WHEN ENABLED, EACH EVENT INCLUDES:\n"
            "  • Anonymous install ID (no name, no hostname)\n"
            "  • Per-launch session ID\n"
            "  • App version (e.g. 4.0)\n"
            "  • OS family (e.g. windows-11)\n"
            "  • Event name (e.g. scan_started, page_visited)\n"
            "  • Aggregate counts (files scanned, threats found)\n\n"
            "NEVER COLLECTED, EVEN WHEN ENABLED:\n"
            "  • File names, file paths, or file contents\n"
            "  • Username, hostname, IP, MAC address\n"
            "  • Browsing history or document contents\n\n"
            "Toggling 'Anonymous Usage Data' off rotates your install ID,\n"
            "so a future opt-in starts a brand-new anonymous identity.",
            "🔒", ACCENT2)

    def _open_deletion_site(self):
        # Until a dedicated privacy site is up, deletion requests go
        # through GitHub Issues so they're trackable.
        url = "https://github.com/giftydevcontact/gifty-antivirus/issues/new?title=Data+deletion+request"
        try:
            import webbrowser
            webbrowser.open(url)
            self._show_toast("Opening Browser",
                "Open a GitHub issue including your install ID.", "🌐", ACCENT2, 5000)
        except Exception:
            InfoDialog(self, "Request Data Deletion",
                f"To request deletion of telemetry data tied to your\n"
                f"install ID, open an issue at:\n\n{url}\n\n"
                f"Include your install ID:\n{_get_install_id()}",
                "🌐", ACCENT2)

    def _upd_defs(self):
        """Manual 'Check for Updates' button — runs in background thread,
        always shows a toast/dialog with the result."""
        self._show_toast("Checking for Updates",
            f"Contacting GitHub ({_GH_REPO})…", "🔄", ACCENT2, 3000)
        tel_event("update_check", manual=True)
        threading.Thread(
            target=self._update_check_thread, args=(True,), daemon=True).start()

    # ──────────────────────────────────────────────────────────────
    # AUTO-UPDATER
    # ──────────────────────────────────────────────────────────────
    def _maybe_check_updates_on_launch(self):
        """Background check, throttled to once per _UPDATE_INTERVAL."""
        if not self.data["settings"].get("auto_check_updates", True):
            return
        last = float(self.data["settings"].get("last_update_check", 0) or 0)
        if (time.time() - last) < _UPDATE_INTERVAL:
            return
        tel_event("update_check", manual=False)
        threading.Thread(
            target=self._update_check_thread, args=(False,), daemon=True).start()

    def _update_check_thread(self, manual):
        """Runs off the UI thread. Posts results back via self.after()."""
        try:
            info = GitHubUpdater().fetch_latest()
        except UpdateError as e:
            if manual:
                self.after(0, lambda msg=str(e): self._show_toast(
                    "Update Check Failed", msg, "❌", DANGER, 6000))
            return

        # Stamp the check time regardless of result.
        self.data["settings"]["last_update_check"] = int(time.time())
        save_data(self.data)

        if not _is_newer(info["version"], _APP_VERSION):
            if manual:
                self.after(0, lambda v=info["version"]: InfoDialog(self,
                    "You're Up To Date",
                    f"Gifty Antivirus {_APP_VERSION} is the latest version.\n"
                    f"(GitHub latest: {v})",
                    "✅", ACCENT))
            return

        # Suppressed by user?
        if (not manual and
            self.data["settings"].get("skipped_version", "") == info["version"]):
            return

        tel_event("update_found",
                  from_version=_APP_VERSION, to_version=info["version"])
        self.after(0, lambda i=info: self._show_update_dialog(i))

    def _show_update_dialog(self, info):
        """Confirm dialog showing version + size + truncated changelog."""
        size_mb = info["size"] / (1024 * 1024) if info["size"] else 0
        notes = (info["notes"] or "").strip()
        if len(notes) > 600:
            notes = notes[:600].rstrip() + "\n…"
        msg = (f"A new version is available!\n\n"
               f"  Current:  {_APP_VERSION}\n"
               f"  Latest:   {info['version']}\n"
               f"  Size:     {size_mb:.2f} MB\n\n"
               f"What's new:\n{notes}\n\n"
               f"Installing will close the app, swap the program file\n"
               f"(UAC prompt required), and relaunch it automatically.")
        dlg = ConfirmDialog(self, "Update Available", msg,
            ok="Install Now", cancel="Later", icon="⬆️")
        if dlg.result:
            self._begin_update_download(info)
        else:
            # Offer to skip this specific version on next background check.
            skip = ConfirmDialog(self, "Skip This Version?",
                f"Don't notify me again about version {info['version']}?\n"
                f"(Manual checks in Settings will still find it.)",
                ok="Skip This Version", cancel="Remind Me Tomorrow",
                icon="🔕")
            if skip.result:
                self.data["settings"]["skipped_version"] = info["version"]
                save_data(self.data)
                tel_event("update_skipped", version=info["version"])

    def _begin_update_download(self, info):
        """Stage the download in a background thread, then prompt to apply."""
        tmp = os.environ.get("TEMP") or os.path.expanduser("~")
        staged = os.path.join(tmp, "gifty_av_update.py")
        size_kb = max(1, info["size"] // 1024) if info["size"] else 0
        size_str = f"{size_kb} KB" if size_kb < 1024 else f"{size_kb/1024:.1f} MB"
        self._show_toast("Downloading Update",
            f"Fetching version {info['version']} ({size_str})…",
            "⬇️", ACCENT2, 4500)

        def _do():
            try:
                GitHubUpdater().download(info["asset_url"], staged)
                GitHubUpdater.sanity_check(staged)
                sha = GitHubUpdater.file_sha256(staged)
            except UpdateError as e:
                self.after(0, lambda msg=str(e): self._show_toast(
                    "Update Failed", msg, "❌", DANGER, 7000))
                return
            self.after(0, lambda: self._confirm_and_apply_update(info, staged, sha))

        threading.Thread(target=_do, daemon=True).start()

    def _confirm_and_apply_update(self, info, staged_path, sha):
        msg = (f"Downloaded version {info['version']}.\n\n"
               f"  SHA-256:  {sha[:16]}…{sha[-8:]}\n\n"
               f"Applying the update will:\n"
               f"  1. Show a UAC prompt (admin required)\n"
               f"  2. Close Gifty Antivirus\n"
               f"  3. Replace the program file\n"
               f"  4. Relaunch the app automatically\n\n"
               f"Continue?")
        dlg = ConfirmDialog(self, "Apply Update?", msg,
            ok="Apply & Restart", cancel="Cancel", icon="⬆️")
        if not dlg.result:
            try: os.remove(staged_path)
            except Exception: pass
            return

        # Locate the live install paths.
        target = os.path.abspath(__file__)
        install_dir = os.path.dirname(target)
        launcher = os.path.join(install_dir, "Launch-Gifty-Antivirus.vbs")
        if not os.path.exists(launcher):
            # Fall back to the dev filename.
            alt = os.path.join(install_dir, "launcher.vbs")
            if os.path.exists(alt):
                launcher = alt

        try:
            GitHubUpdater.apply(staged_path, target, launcher)
        except UpdateError as e:
            self._show_toast("Update Failed", str(e), "❌", DANGER, 8000)
            return

        tel_event("update_installed",
                  from_version=_APP_VERSION, to_version=info["version"])
        # Clear the skipped-version pin since the user accepted this one.
        self.data["settings"]["skipped_version"] = ""
        save_data(self.data)

        InfoDialog(self, "Update Starting",
            "The app will close in a moment and reopen automatically\n"
            "after the update is applied.\n\n"
            "If it doesn't reopen, launch Gifty Antivirus from your\n"
            "Start Menu or desktop shortcut.",
            "✅", ACCENT)
        # Give the dialog a beat, then exit so the batch can swap the file.
        self.after(1500, self._force_quit)

    def _reset_s(self):
        dlg = ConfirmDialog(self,"Reset Settings","Reset all settings to defaults?",
                            ok="Reset", danger=True)
        if dlg.result:
            # Preserve the user's telemetry decision across reset — never
            # silently re-enable data sharing the user previously turned off.
            keep_telemetry = bool(self.data["settings"].get("send_telemetry", False))
            self.data["settings"] = {
                "scan_archives":False,"heuristic_level":"Medium",
                "auto_quarantine":True,"notifications":True,
                "scan_on_start":False,"minimize_to_tray":True,
                "send_telemetry": keep_telemetry,
                "cloud_lookup": True,
            }
            save_data(self.data)
            InfoDialog(self,"Settings Reset","Settings have been reset to defaults.",
                       "✅", ACCENT)


    # ──────────────────────────────────────────────────────────────
    # NETWORK MONITOR
    # ──────────────────────────────────────────────────────────────
    def _build_network(self):
        p = self._pages["network"]
        # status bar first (bottom anchor before treeview expands)
        _net_bot = tk.Frame(p, bg=BG); _net_bot.pack(fill="x", padx=28, pady=(4,8), side="bottom")
        self._net_status = tk.Label(_net_bot, text="", font=("Segoe UI",8), bg=BG, fg=TEXT_DIM)
        self._net_status.pack(side="left")
        self._net_auto_after = None

        hdr = self._page_hdr(p, "Network Monitor", "Active connections & suspicious traffic")
        self._btn(hdr, "🔄  Refresh", ACCENT2, BG, self._refresh_network).pack(side="right")

        summary = tk.Frame(p, bg=BG); summary.pack(fill="x", padx=28, pady=(0,10))
        self._net_cards = {}
        for i,(k,t,ic,c) in enumerate([
            ("total",    "Connections",    "🔗", ACCENT2),
            ("listening","Listening",      "👂", ACCENT),
            ("suspect",  "Suspicious",     "⚠️", DANGER),
            ("blocked",  "Blocked (today)","🚫", WARNING),
        ]):
            sc = StatCard(summary, t, 0, ic, c)
            sc.grid(row=0, column=i, padx=5, sticky="nsew")
            summary.columnconfigure(i, weight=1)
            self._net_cards[k] = sc

        trf = tk.Frame(p, bg=BG); trf.pack(fill="both", expand=True, padx=28, pady=(0,4))
        self._net_tree = ttk.Treeview(trf,
            columns=("proto","local","remote","state","pid","process","risk"),
            show="headings", style="Net.Treeview")
        cols = [("proto",55,"Proto"),("local",155,"Local Address"),("remote",175,"Remote Address"),
                ("state",90,"State"),("pid",55,"PID"),("process",130,"Process"),("risk",70,"Risk")]
        for col,w,lbl in cols:
            self._net_tree.heading(col,text=lbl); self._net_tree.column(col,width=w,minwidth=40)
        ns = DarkScrollbar(trf, orient="vertical", command=self._net_tree.yview)
        self._net_tree.configure(yscrollcommand=ns.set)
        ns.pack(side="right", fill="y"); self._net_tree.pack(fill="both", expand=True)
        self._net_tree.tag_configure("danger", foreground=DANGER)
        self._net_tree.tag_configure("warn",   foreground=WARNING)
        self._net_tree.tag_configure("ok",     foreground=TEXT_MID)

        self._refresh_network()

    _SUSPECT_PORTS = {4444,1337,31337,6666,6667,6668,6669,
                      8888,9999,12345,27374,31338,54321}
    _SUSPECT_PROC  = {"ncat","nc","netcat","meterpreter","mimikatz","ngrok",
                      "frpc","frps","revshell","payload","beacon"}

    def _refresh_network(self):
        try: self._net_status.config(text="⟳  Refreshing…", fg=ACCENT2)
        except: pass
        if self._net_auto_after:
            try: self.after_cancel(self._net_auto_after)
            except: pass
        threading.Thread(target=self._refresh_network_bg, daemon=True).start()

    def _refresh_network_bg(self):
        rows = []; total = 0; listening = 0; suspect = 0
        try:
            result = subprocess.run(["netstat","-ano"], capture_output=True,
                                    text=True, timeout=8, creationflags=_NOCONSOLE)
            proc_map = self._get_proc_map()
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4 or parts[0] not in ("TCP","UDP"): continue
                proto = parts[0]; local = parts[1]
                remote = parts[2] if len(parts)>2 else "*"
                state  = parts[3] if proto=="TCP" and len(parts)>3 else "-"
                pid    = parts[-1] if parts[-1].isdigit() else "?"
                pname  = proc_map.get(pid, "")
                total += 1
                if state == "LISTENING": listening += 1
                risk = "—"; tag = "ok"
                try:
                    rport = int(remote.rsplit(":",1)[-1])
                    if rport in self._SUSPECT_PORTS: risk = "HIGH"; tag = "danger"; suspect += 1
                except: pass
                if any(s in pname.lower() for s in self._SUSPECT_PROC):
                    risk = "HIGH"; tag = "danger"; suspect += 1
                if risk == "—" and state == "ESTABLISHED": risk = "LOW"
                rows.append((proto, local, remote, state, pid, pname, risk, tag))
        except Exception as e:
            self.after(0, lambda err=str(e): self._net_status.config(text=f"Error: {err}", fg=DANGER))
            return
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.after(0, lambda: self._update_network_ui(rows, total, listening, suspect, ts))

    def _update_network_ui(self, rows, total, listening, suspect, ts):
        try:
            for r in self._net_tree.get_children(): self._net_tree.delete(r)
            for proto, local, remote, state, pid, pname, risk, tag in rows:
                self._net_tree.insert("","end",
                    values=(proto,local,remote,state,pid,pname,risk), tags=(tag,))
            color = DANGER if suspect else TEXT_DIM
            self._net_status.config(
                text=f"✓  {ts}  •  {total} connections  •  {suspect} suspicious", fg=color)
            for k,v in [("total",total),("listening",listening),("suspect",suspect),("blocked",0)]:
                try: self._net_cards[k].update_value(v)
                except: pass
        except: pass
        if self.data["settings"].get("net_monitor_auto", True) and self._current_page=="network":
            self._net_auto_after = self.after(10000, self._refresh_network)

    def _get_proc_map(self):
        pmap = {}
        try:
            r = subprocess.run(["tasklist","/FO","CSV","/NH"],
                               capture_output=True, text=True, timeout=6, creationflags=_NOCONSOLE)
            for line in r.stdout.splitlines():
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    pmap[parts[1]] = parts[0].replace(".exe","")
        except: pass
        return pmap

    # ──────────────────────────────────────────────────────────────
    # STARTUP MANAGER
    # ──────────────────────────────────────────────────────────────
    _STARTUP_KEYS = [
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",       "HKCU Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",       "HKLM Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",  "HKCU RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",  "HKLM RunOnce"),
    ]
    _LEGIT_PROCS = {"explorer","svchost","wscript","msiexec","rundll32","conhost",
                    "taskhostw","sihost","ctfmon","onedrive","teams","discord","slack",
                    "windowsdefender","msmpeng","nvcplui","igfxtray","jusched"}

    def _build_startup(self):
        p = self._pages["startup"]
        hdr = self._page_hdr(p, "Startup Manager", "Programs that run automatically at login")
        self._btn(hdr, "🔄  Refresh", ACCENT2, BG, self._refresh_startup).pack(side="right")

        info = tk.Frame(p, bg="#0a1020", highlightbackground=ACCENT2, highlightthickness=1)
        info.pack(fill="x", padx=28, pady=(0,10))
        tk.Label(info, text="ℹ️  Review what launches at boot. Suspicious entries could be malware persisting on your system.",
                 font=("Segoe UI",9), bg="#0a1020", fg=ACCENT2, wraplength=800, justify="left"
                 ).pack(anchor="w", padx=12, pady=8)

        # Action row first so treeview doesn't swallow it
        ar2 = tk.Frame(p, bg=BG); ar2.pack(fill="x", padx=28, pady=(4,14), side="bottom")
        self._btn(ar2, "🗑️  Disable Entry", DANGER, "#fff", self._disable_startup_entry).pack(side="left")
        self._startup_count = tk.Label(ar2, text="", font=("Segoe UI",8), bg=BG, fg=TEXT_DIM)
        self._startup_count.pack(side="right")
        trf = tk.Frame(p, bg=BG); trf.pack(fill="both", expand=True, padx=28, pady=(0,4))
        self._startup_tree = ttk.Treeview(trf,
            columns=("name","command","source","risk"),
            show="headings", style="Startup.Treeview")
        for col,w,lbl in [("name",170,"Name"),("command",370,"Command"),
                           ("source",120,"Registry Key"),("risk",80,"Risk")]:
            self._startup_tree.heading(col,text=lbl)
            self._startup_tree.column(col,width=w,minwidth=50)
        ss = DarkScrollbar(trf, orient="vertical", command=self._startup_tree.yview)
        self._startup_tree.configure(yscrollcommand=ss.set)
        ss.pack(side="right", fill="y"); self._startup_tree.pack(fill="both", expand=True)
        self._startup_tree.tag_configure("danger", foreground=DANGER)
        self._startup_tree.tag_configure("warn",   foreground=WARNING)
        self._startup_tree.tag_configure("ok",     foreground=TEXT_MID)

        self._refresh_startup()

    def _refresh_startup(self):
        try:
            for r in self._startup_tree.get_children(): self._startup_tree.delete(r)
            count = 0
            for hive, keypath, label in self._STARTUP_KEYS:
                try:
                    key = winreg.OpenKey(hive, keypath, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(key, i)
                            i += 1; count += 1
                            val_l = val.lower()
                            risk = "OK"; tag = "ok"
                            # Heuristic: script in suspicious dir, or known-bad name token
                            for tok in THREAT_TOKENS:
                                if tok in val_l or tok in name.lower():
                                    risk = "HIGH"; tag = "danger"; break
                            if risk == "OK":
                                for ext in (".vbs",".ps1",".bat",".cmd",".hta",".js",".jse",".wsf"):
                                    if ext in val_l and "\\temp\\" in val_l:
                                        risk = "SUSPICIOUS"; tag = "warn"; break
                            base = Path(val.split('"')[1] if '"' in val else val.split()[0]).name.lower().replace(".exe","")
                            if risk == "OK" and base not in self._LEGIT_PROCS:
                                risk = "REVIEW"; tag = "warn"
                            self._startup_tree.insert("", "end",
                                values=(name, val[:80]+("…" if len(val)>80 else ""), label, risk),
                                tags=(tag,))
                        except OSError: break
                    winreg.CloseKey(key)
                except: pass
            self._startup_count.config(text=f"{count} startup entries")
        except Exception as e:
            self._startup_count.config(text=f"Error: {e}")

    def _disable_startup_entry(self):
        sel = self._startup_tree.selection()
        if not sel: return
        vals = self._startup_tree.item(sel[0], "values")
        name, _, source, _ = vals
        for hive, keypath, label in self._STARTUP_KEYS:
            if label != source: continue
            is_hklm = (hive == winreg.HKEY_LOCAL_MACHINE)
            hint = ("\n\nNote: This is a system-wide entry (HKLM).\n"
                    "Run Gifty Antivirus as Administrator to remove it.") if is_hklm else ""
            dlg = ConfirmDialog(self, "Disable Startup Entry",
                f"Remove '{name}' from startup?\n\nThe registry entry will be deleted; the program itself stays.{hint}",
                ok="Disable", danger=True, icon="🚀")
            if dlg.result:
                try:
                    access = winreg.KEY_WRITE
                    key = winreg.OpenKey(hive, keypath, 0, access)
                    winreg.DeleteValue(key, name)
                    winreg.CloseKey(key)
                    self._refresh_startup()
                    self._show_toast("Entry Removed", f"'{name}' removed from startup.", "✅", ACCENT)
                except PermissionError:
                    InfoDialog(self, "Permission Denied",
                        "Cannot modify this system-level startup entry.\n\n"
                        "Right-click Gifty Antivirus → 'Run as administrator',\n"
                        "then try again.", "🔒", WARNING)
                except Exception as e:
                    InfoDialog(self, "Error", f"Could not remove entry:\n{type(e).__name__}: {e}", "❌", DANGER)
            break

    # ──────────────────────────────────────────────────────────────
    # SCHEDULED SCANS
    # ──────────────────────────────────────────────────────────────
    def _build_schedule(self):
        p = self._pages["schedule"]
        sf = ScrollableFrame(p); sf.pack(fill="both", expand=True)
        inner = sf.inner
        self._page_hdr(inner, "Scheduled Scans", "Automate scans on a timed basis")

        # Status card
        sc = tk.Frame(inner, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        sc.pack(fill="x", padx=28, pady=(0,14))
        tk.Frame(sc, bg=ACCENT2, height=2).pack(fill="x")
        sr = tk.Frame(sc, bg=CARD); sr.pack(fill="x", padx=20, pady=16)
        tk.Label(sr, text="⏰", font=("Segoe UI Emoji",32), bg=CARD, fg=ACCENT2).pack(side="left", padx=(0,16))
        si = tk.Frame(sr, bg=CARD); si.pack(side="left", fill="x", expand=True)
        self._sched_title = tk.Label(si, text="Scheduled scans disabled",
                                      font=("Segoe UI",13,"bold"), bg=CARD, fg=TEXT_DIM)
        self._sched_title.pack(anchor="w")
        self._sched_sub = tk.Label(si, text="Enable below to automate regular scans",
                                    font=("Segoe UI",9), bg=CARD, fg=TEXT_DIM)
        self._sched_sub.pack(anchor="w", pady=(4,0))
        self._sched_en_var = tk.BooleanVar(value=self.data["scheduled_scan"].get("enabled",False))
        ToggleSwitch(sr, self._sched_en_var, on_toggle=self._sched_toggle, bg=CARD).pack(side="right")

        # Config rows
        def cfg_row(parent, label, desc, widget_factory):
            r = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
            r.pack(fill="x", padx=28, pady=2)
            lc = tk.Frame(r, bg=CARD); lc.pack(side="left", fill="x", expand=True, padx=16, pady=10)
            tk.Label(lc, text=label, font=("Segoe UI",10,"bold"), bg=CARD, fg=TEXT).pack(anchor="w")
            tk.Label(lc, text=desc, font=("Segoe UI",8), bg=CARD, fg=TEXT_DIM).pack(anchor="w")
            widget_factory(r)

        self._sched_type_var = tk.StringVar(
            value=self.data["scheduled_scan"].get("type","quick"))
        self._sched_time_var = tk.StringVar(
            value=self.data["scheduled_scan"].get("time","02:00"))
        self._sched_freq_var = tk.StringVar(
            value=self.data["scheduled_scan"].get("freq","daily"))

        def make_type(parent):
            CustomSelect(parent, self._sched_type_var, ["quick","full"],
                width=140, bg=CARD, on_change=lambda v: self._save_sched()
                ).pack(side="right", padx=16, pady=8)
        def make_time(parent):
            times = [f"{h:02d}:{m:02d}" for h in range(24) for m in (0,30)]
            CustomSelect(parent, self._sched_time_var, times,
                width=120, bg=CARD, on_change=lambda v: self._save_sched()
                ).pack(side="right", padx=16, pady=8)
        def make_freq(parent):
            CustomSelect(parent, self._sched_freq_var, ["daily","weekly","monthly"],
                width=140, bg=CARD, on_change=lambda v: self._save_sched()
                ).pack(side="right", padx=16, pady=8)

        cfg_row(inner, "Scan Type",  "Quick checks common spots; Full scans entire user folder", make_type)
        cfg_row(inner, "Start Time",  "When to run the scan each day (24-hour clock)", make_time)
        cfg_row(inner, "Frequency",  "How often the automatic scan triggers", make_freq)

        # History of scheduled scans
        tk.Label(inner, text="Scheduled Scan History", font=("Segoe UI",12,"bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", padx=28, pady=(18,6))
        hf = tk.Frame(inner, bg=BG); hf.pack(fill="x", padx=28, pady=(0,28))
        self._sched_hist = tk.Text(hf, bg=CARD, fg=TEXT_MID, font=("Segoe UI",9),
                                    relief="flat", state="disabled", height=8,
                                    highlightbackground=BORDER, highlightthickness=1)
        self._sched_hist.pack(fill="x")
        self._refresh_schedule()
        self._start_schedule_checker()

    def _sched_toggle(self, val):
        self.data["scheduled_scan"]["enabled"] = val
        save_data(self.data)
        self._refresh_schedule()

    def _save_sched(self):
        self.data["scheduled_scan"]["type"] = self._sched_type_var.get()
        self.data["scheduled_scan"]["time"] = self._sched_time_var.get()
        self.data["scheduled_scan"]["freq"] = self._sched_freq_var.get()
        save_data(self.data)

    def _refresh_schedule(self):
        enabled = self.data["scheduled_scan"].get("enabled", False)
        t  = self.data["scheduled_scan"].get("time","02:00")
        st = self.data["scheduled_scan"].get("type","quick").title()
        fr = self.data["scheduled_scan"].get("freq","daily").title()
        try:
            if enabled:
                self._sched_title.config(text=f"Next {st} Scan: {fr} at {t}", fg=ACCENT)
                self._sched_sub.config(text="Gifty Antivirus will scan automatically.", fg=TEXT_MID)
            else:
                self._sched_title.config(text="Scheduled scans disabled", fg=TEXT_DIM)
                self._sched_sub.config(text="Enable above to automate regular scans.", fg=TEXT_DIM)
        except: pass
        hist = self.data.get("scan_history",[])
        sched_hist = [h for h in hist if h.get("scheduled")][-10:]
        try:
            self._sched_hist.config(state="normal")
            self._sched_hist.delete("1.0","end")
            if not sched_hist:
                self._sched_hist.insert("end","No scheduled scans have run yet.\n")
            for h in reversed(sched_hist):
                t2 = h.get("threats_found",0)
                line = f"[{h['date']}]  {h['scan_type'].title()} — {h['files_scanned']:,} files  •  {'⚠️ '+str(t2)+' threat(s)' if t2 else '✅ Clean'}\n"
                self._sched_hist.insert("end", line)
            self._sched_hist.config(state="disabled")
        except: pass

    def _start_schedule_checker(self):
        threading.Thread(target=self._schedule_loop, daemon=True).start()

    def _schedule_loop(self):
        while True:
            time.sleep(55)
            try:
                sc = self.data.get("scheduled_scan",{})
                if not sc.get("enabled"): continue
                now = datetime.datetime.now()
                target_t = sc.get("time","02:00")
                h, m = map(int, target_t.split(":"))
                if now.hour == h and now.minute == m:
                    last = sc.get("last_run","")
                    freq = sc.get("freq","daily")
                    today = now.strftime("%Y-%m-%d")
                    if last == today: continue
                    self.data["scheduled_scan"]["last_run"] = today
                    save_data(self.data)
                    st = sc.get("type","quick")
                    self.after(0, lambda s=st: self._run_scheduled_scan(s))
            except: pass

    def _run_scheduled_scan(self, stype):
        self._show_toast("Scheduled Scan", f"Starting {stype} scan now...", "⏰", ACCENT2, 5000)
        targets = []
        if stype == "quick":
            home = os.path.expanduser("~")
            targets = [os.path.join(home,d) for d in ("Downloads","Desktop","Documents")
                       if os.path.exists(os.path.join(home,d))]
        else:
            targets = [os.path.expanduser("~")]
        if not targets: return
        def _do():
            files = []
            for t in targets:
                if os.path.isfile(t): files.append(t)
                else:
                    for root,dirs,fns in os.walk(t, onerror=lambda e: None):
                        files.extend(os.path.join(root,fn) for fn in fns)
            threats = []
            for fp in files:
                r = analyze_file(fp)
                if r: threats.append((fp,)+r)
            entry = {
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                "scan_type": stype, "files_scanned": len(files),
                "threats_found": len(threats), "scheduled": True,
                "threats": [{"file":t[0],"name":t[1],"cat":t[2],"sev":t[3]} for t in threats],
            }
            self.data["scan_history"].append(entry)
            self.data["total_scanned"] += len(files)
            self.data["total_threats"] += len(threats)
            save_data(self.data)
            msg = f"Scheduled scan done — {len(files):,} files, {len(threats)} threat(s)"
            self.after(0, lambda: self._show_toast("Scheduled Scan Complete", msg,
                "✅" if not threats else "🦠",
                ACCENT if not threats else DANGER, 6000))
            self.after(0, self._update_stats)
        threading.Thread(target=_do, daemon=True).start()


    # ══════════════════════════════════════════════════════════════
    # VULNERABILITY SCANNER
    # ══════════════════════════════════════════════════════════════
    def _build_vulnscan(self):
        p = self._pages["vulnscan"]
        hdr = self._page_hdr(p, "Vulnerability Scanner", "System security audit")
        self._btn(hdr,"🔄  Re-scan",ACCENT2,BG,self._run_vulnscan).pack(side="right")

        # Score hero
        sh = tk.Frame(p, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        sh.pack(fill="x", padx=28, pady=(0,12))
        tk.Frame(sh, bg=WARNING, height=2).pack(fill="x")
        sr2 = tk.Frame(sh, bg=CARD); sr2.pack(fill="x", padx=20, pady=14)
        self._vuln_score_lbl = tk.Label(sr2, text="—", font=("Consolas",42,"bold"),
                                        bg=CARD, fg=ACCENT)
        self._vuln_score_lbl.pack(side="left")
        vi = tk.Frame(sr2, bg=CARD); vi.pack(side="left", padx=16)
        tk.Label(vi, text="Security Score", font=("Segoe UI",13,"bold"),
                 bg=CARD, fg=TEXT).pack(anchor="w")
        self._vuln_score_sub = tk.Label(vi, text="Scanning…",
                                        font=("Segoe UI",9), bg=CARD, fg=TEXT_DIM)
        self._vuln_score_sub.pack(anchor="w")
        self._vuln_bar = AnimatedProgressBar(sr2, height=10, fill=ACCENT, bg=CARD)
        self._vuln_bar.pack(side="right", fill="x", expand=True, padx=(20,0))

        # Results list
        self._vuln_list = tk.Frame(p, bg=BG)
        self._vuln_list.pack(fill="both", expand=True, padx=28, pady=(0,20))

    _VULN_CHECKS = [
        ("windows_defender",    "Windows Defender",          "Antivirus protection"),
        ("firewall",            "Windows Firewall",          "Network protection"),
        ("uac",                 "User Account Control",      "Elevation prompts"),
        ("remote_desktop",      "Remote Desktop",            "RDP access control"),
        ("autorun",             "AutoRun / AutoPlay",        "USB/media auto-execute"),
        ("guest_account",       "Guest Account",             "Open user accounts"),
        ("smb1",                "SMBv1 Protocol",            "Legacy file sharing (EternalBlue)"),
        ("screen_lock",         "Screen Lock Timeout",       "Auto-lock on idle"),
        ("pending_updates",     "Windows Updates",           "Patch status"),
        ("open_rdp_port",       "RDP Port Exposure",         "Port 3389 listener"),
    ]

    def _run_vulnscan(self):
        for w in self._vuln_list.winfo_children(): w.destroy()
        tk.Label(self._vuln_list, text="Scanning…", font=("Segoe UI",10),
                 bg=BG, fg=TEXT_DIM).pack(pady=20)
        self._vuln_score_lbl.config(text="…", fg=TEXT_DIM)
        self._vuln_score_sub.config(text="Running checks…")
        threading.Thread(target=self._vulnscan_bg, daemon=True).start()

    def _vulnscan_bg(self):
        results = []
        for key, title, desc in self._VULN_CHECKS:
            status, detail, ok = self._vuln_check(key)
            results.append((title, desc, status, detail, ok))
        score = int(sum(1 for _,_,_,_,ok in results if ok) / len(results) * 100)
        self.after(0, lambda: self._show_vuln_results(results, score))

    def _vuln_check(self, key):
        try:
            if key == "windows_defender":
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows Defender", 0, winreg.KEY_READ)
                val,_ = winreg.QueryValueEx(k, "DisableAntiSpyware")
                winreg.CloseKey(k)
                ok = (val == 0)
                return ("ENABLED" if ok else "DISABLED", "Real-time protection", ok)
            elif key == "firewall":
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                    0, winreg.KEY_READ)
                val,_ = winreg.QueryValueEx(k, "EnableFirewall")
                winreg.CloseKey(k)
                ok = (val == 1)
                return ("ENABLED" if ok else "DISABLED", "Windows Firewall", ok)
            elif key == "uac":
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    0, winreg.KEY_READ)
                val,_ = winreg.QueryValueEx(k, "EnableLUA")
                winreg.CloseKey(k)
                ok = (val == 1)
                return ("ENABLED" if ok else "DISABLED", "UAC active", ok)
            elif key == "remote_desktop":
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                    0, winreg.KEY_READ)
                val,_ = winreg.QueryValueEx(k, "fDenyTSConnections")
                winreg.CloseKey(k)
                ok = (val == 1)
                return ("DISABLED" if ok else "⚠ ENABLED", "Remote Desktop", ok)
            elif key == "autorun":
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                    0, winreg.KEY_READ)
                try: val,_ = winreg.QueryValueEx(k,"NoDriveTypeAutoRun"); ok=(val>=0xFF)
                except: ok=False
                winreg.CloseKey(k)
                return ("DISABLED" if ok else "⚠ ENABLED", "AutoRun for drives", ok)
            elif key == "guest_account":
                r = subprocess.run(["net","user","Guest"], capture_output=True,
                                   text=True, creationflags=_NOCONSOLE)
                ok = "Account active" not in r.stdout or "No" in r.stdout
                active = "Account active" in r.stdout and "Yes" in r.stdout
                return ("DISABLED" if not active else "⚠ ENABLED",
                        "Guest login", not active)
            elif key == "smb1":
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    0, winreg.KEY_READ)
                try: val,_ = winreg.QueryValueEx(k,"SMB1"); ok=(val==0)
                except: ok=True  # not set = disabled on modern Windows
                winreg.CloseKey(k)
                return ("DISABLED" if ok else "⚠ ENABLED", "SMBv1 protocol", ok)
            elif key == "screen_lock":
                k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r"Control Panel\Desktop", 0, winreg.KEY_READ)
                try: val,_ = winreg.QueryValueEx(k,"ScreenSaverIsSecure"); ok=(val=="1")
                except: ok=False
                winreg.CloseKey(k)
                return ("SECURED" if ok else "⚠ UNSECURED", "Lock on screensaver", ok)
            elif key == "pending_updates":
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install",
                    0, winreg.KEY_READ)
                try: val,_ = winreg.QueryValueEx(k,"LastSuccessTime"); ok=bool(val)
                except: ok=False
                winreg.CloseKey(k)
                return ("UP TO DATE" if ok else "⚠ CHECK NEEDED", "Last install time found", ok)
            elif key == "open_rdp_port":
                import socket as _s
                sock = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex(("127.0.0.1", 3389))
                sock.close()
                ok = (result != 0)
                return ("CLOSED" if ok else "⚠ OPEN", "Port 3389 (RDP)", ok)
        except: pass
        return ("UNKNOWN", "Could not check", True)

    def _show_vuln_results(self, results, score):
        for w in self._vuln_list.winfo_children(): w.destroy()
        color = ACCENT if score>=80 else WARNING if score>=50 else DANGER
        self._vuln_score_lbl.config(text=f"{score}%", fg=color)
        grade = "Excellent" if score>=90 else "Good" if score>=70 else "Fair" if score>=50 else "Poor"
        issues = sum(1 for _,_,_,_,ok in results if not ok)
        self._vuln_score_sub.config(
            text=f"{grade} — {issues} issue{'s' if issues!=1 else ''} found", fg=color)
        self._vuln_bar._fill = color
        self._vuln_bar.set(score/100)

        for title, desc, status, detail, ok in results:
            row = tk.Frame(self._vuln_list, bg=CARD,
                           highlightbackground=ACCENT if ok else DANGER,
                           highlightthickness=1)
            row.pack(fill="x", pady=3)
            tk.Frame(row, bg=ACCENT if ok else DANGER, width=4).pack(side="left", fill="y")
            body = tk.Frame(row, bg=CARD); body.pack(side="left", fill="x", expand=True, padx=14, pady=10)
            tk.Label(body, text=title, font=("Segoe UI",10,"bold"),
                     bg=CARD, fg=TEXT).pack(anchor="w")
            tk.Label(body, text=desc, font=("Segoe UI",8),
                     bg=CARD, fg=TEXT_DIM).pack(anchor="w")
            badge_bg = "#0d2010" if ok else "#200d0d"
            badge_fg = ACCENT if ok else DANGER
            badge = tk.Frame(row, bg=badge_bg, highlightbackground=badge_fg, highlightthickness=1)
            badge.pack(side="right", padx=16, pady=12)
            tk.Label(badge, text=f"  {status}  ", font=("Segoe UI",8,"bold"),
                     bg=badge_bg, fg=badge_fg, pady=4).pack()

    # ══════════════════════════════════════════════════════════════
    # SYSTEM CLEANER
    # ══════════════════════════════════════════════════════════════
    def _build_cleaner(self):
        p = self._pages["cleaner"]
        hdr = self._page_hdr(p, "System Cleaner", "Remove junk and free up space")
        self._btn(hdr,"🔍  Scan Now",ACCENT2,BG,self._refresh_cleaner).pack(side="right")

        # Summary strip
        top = tk.Frame(p, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        top.pack(fill="x", padx=28, pady=(0,12))
        tk.Frame(top, bg=ACCENT2, height=2).pack(fill="x")
        tr = tk.Frame(top, bg=CARD); tr.pack(fill="x", padx=20, pady=14)
        self._clean_total = tk.Label(tr, text="—", font=("Consolas",34,"bold"),
                                     bg=CARD, fg=ACCENT2)
        self._clean_total.pack(side="left")
        ci = tk.Frame(tr, bg=CARD); ci.pack(side="left", padx=14)
        tk.Label(ci, text="Reclaimable Space", font=("Segoe UI",12,"bold"),
                 bg=CARD, fg=TEXT).pack(anchor="w")
        self._clean_sub = tk.Label(ci, text="Click 'Scan Now' to analyse",
                                   font=("Segoe UI",9), bg=CARD, fg=TEXT_DIM)
        self._clean_sub.pack(anchor="w")
        self._btn(tr,"🗑️  Clean Selected",DANGER,"#fff",self._do_clean).pack(side="right")

        sf = ScrollableFrame(p); sf.pack(fill="both", expand=True)
        self._clean_rows_frame = sf.inner
        self._clean_targets = {}  # key → (BooleanVar, paths, size_label)

    _CLEAN_TARGETS = [
        ("windows_temp",  "Windows Temp",        "Temporary system files",
         ["%TEMP%", "%WINDIR%\\Temp"]),
        ("user_temp",     "User Temp Folder",     "Your personal temp cache",
         ["%USERPROFILE%\\AppData\\Local\\Temp"]),
        ("prefetch",      "Prefetch Cache",       "App launch cache (speeds up first launch)",
         ["%WINDIR%\\Prefetch"]),
        ("thumb_cache",   "Thumbnail Cache",      "Explorer image thumbnails",
         ["%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\Explorer"]),
        ("recycle_bin",   "Recycle Bin",          "Deleted files awaiting permanent removal",
         ["%USERPROFILE%\\$Recycle.Bin"]),
        ("chrome_cache",  "Chrome Cache",         "Google Chrome browser cache",
         ["%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"]),
        ("edge_cache",    "Edge Cache",           "Microsoft Edge browser cache",
         ["%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache"]),
        ("firefox_cache", "Firefox Cache",        "Mozilla Firefox browser cache",
         ["%USERPROFILE%\\AppData\\Local\\Mozilla\\Firefox\\Profiles"]),
        ("event_logs",    "Windows Event Logs",   "System and application event logs",
         ["%WINDIR%\\System32\\winevt\\Logs"]),
        ("error_reports", "Error Reports",        "Windows crash dump reports",
         ["%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\WER"]),
    ]

    def _expand_path(self, p):
        return os.path.expandvars(p)

    def _folder_size(self, path):
        total = 0
        try:
            for root,_,files in os.walk(path):
                for f in files:
                    try: total += os.path.getsize(os.path.join(root,f))
                    except: pass
        except: pass
        return total

    def _fmt_size(self, b):
        for u in ("B","KB","MB","GB"):
            if b < 1024: return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} TB"

    def _refresh_cleaner(self):
        for w in self._clean_rows_frame.winfo_children(): w.destroy()
        self._clean_targets.clear()
        self._clean_total.config(text="…", fg=TEXT_DIM)
        self._clean_sub.config(text="Scanning…")
        threading.Thread(target=self._cleaner_scan_bg, daemon=True).start()

    def _cleaner_scan_bg(self):
        items = []
        for key, title, desc, paths in self._CLEAN_TARGETS:
            expanded = [self._expand_path(p) for p in paths]
            size = sum(self._folder_size(p) for p in expanded if os.path.exists(p))
            items.append((key, title, desc, expanded, size))
        total = sum(s for _,_,_,_,s in items)
        self.after(0, lambda: self._show_cleaner_results(items, total))

    def _show_cleaner_results(self, items, total):
        for w in self._clean_rows_frame.winfo_children(): w.destroy()
        self._clean_targets.clear()
        self._clean_total.config(text=self._fmt_size(total), fg=ACCENT2)
        count = sum(1 for _,_,_,_,s in items if s>0)
        self._clean_sub.config(text=f"{count} location{'s' if count!=1 else ''} with junk found")

        for key, title, desc, paths, size in items:
            var = tk.BooleanVar(value=size>0)
            row = tk.Frame(self._clean_rows_frame, bg=CARD,
                           highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill="x", padx=28, pady=3)
            tk.Frame(row, bg=ACCENT2 if size>0 else TEXT_DIM, width=4).pack(side="left",fill="y")
            cb_frame = tk.Frame(row, bg=CARD)
            cb_frame.pack(side="left", padx=12, pady=12)
            ToggleSwitch(cb_frame, var, bg=CARD).pack()
            body = tk.Frame(row, bg=CARD); body.pack(side="left", fill="x", expand=True, pady=12)
            tk.Label(body, text=title, font=("Segoe UI",10,"bold"),
                     bg=CARD, fg=TEXT).pack(anchor="w")
            tk.Label(body, text=desc, font=("Segoe UI",8),
                     bg=CARD, fg=TEXT_DIM).pack(anchor="w")
            size_lbl = tk.Label(row, text=self._fmt_size(size) if size>0 else "0 B",
                                font=("Consolas",11,"bold"), bg=CARD,
                                fg=ACCENT2 if size>512*1024 else TEXT_MID, padx=16)
            size_lbl.pack(side="right")
            self._clean_targets[key] = (var, paths, size_lbl)

    def _do_clean(self):
        selected = [(k,p) for k,(v,p,_) in self._clean_targets.items() if v.get()]
        if not selected:
            self._show_toast("Nothing Selected","Toggle on the items you want to clean.","🧹",WARNING)
            return
        dlg = ConfirmDialog(self, "Clean Files",
            f"Permanently delete files from {len(selected)} location(s)?\nThis cannot be undone.",
            ok="Clean Now", danger=True, icon="🗑️")
        if not dlg.result: return
        threading.Thread(target=self._clean_bg, args=(selected,), daemon=True).start()

    def _clean_bg(self, targets):
        freed = 0
        for key, paths in targets:
            for path in paths:
                if not os.path.exists(path): continue
                try:
                    for item in os.listdir(path):
                        fp = os.path.join(path, item)
                        try:
                            if os.path.isfile(fp):
                                freed += os.path.getsize(fp)
                                os.remove(fp)
                            elif os.path.isdir(fp):
                                import shutil
                                freed += self._folder_size(fp)
                                shutil.rmtree(fp, ignore_errors=True)
                        except: pass
                except: pass
        self.after(0, lambda: (
            self._show_toast("Clean Complete",
                f"Freed {self._fmt_size(freed)} of disk space.", "✅", ACCENT, 6000),
            self._refresh_cleaner()
        ))

    # ══════════════════════════════════════════════════════════════
    # TOOLS
    # ══════════════════════════════════════════════════════════════
    def _build_tools(self):
        p = self._pages["tools"]
        sf = ScrollableFrame(p); sf.pack(fill="both", expand=True)
        inner = sf.inner
        self._page_hdr(inner, "Security Tools", "Advanced utilities")

        def section(title, color=ACCENT):
            f = tk.Frame(inner, bg=BG); f.pack(fill="x", padx=28, pady=(16,6))
            tk.Label(f, text=title, font=("Segoe UI",11,"bold"), bg=BG, fg=color).pack(anchor="w")
            tk.Frame(f, bg=color, height=1).pack(fill="x", pady=(4,0))

        def tool_card(parent, icon, title, desc, btn_text, btn_color, cmd):
            row = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill="x", padx=28, pady=3)
            tk.Label(row, text=icon, font=("Segoe UI Emoji",20), bg=CARD,
                     fg=btn_color).pack(side="left", padx=(16,12), pady=14)
            body = tk.Frame(row, bg=CARD); body.pack(side="left", fill="x", expand=True, pady=14)
            tk.Label(body, text=title, font=("Segoe UI",10,"bold"), bg=CARD, fg=TEXT).pack(anchor="w")
            tk.Label(body, text=desc, font=("Segoe UI",8), bg=CARD, fg=TEXT_DIM).pack(anchor="w")
            self._btn(row, btn_text, btn_color, BG if btn_color!=BORDER else TEXT, cmd
                      ).pack(side="right", padx=16)

        # ── File Shredder ──────────────────────────────────────────
        section("🔥  File Shredder", DANGER)
        shred_f = tk.Frame(inner, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        shred_f.pack(fill="x", padx=28, pady=3)
        tk.Frame(shred_f, bg=DANGER, width=4).pack(side="left", fill="y")
        sb = tk.Frame(shred_f, bg=CARD); sb.pack(fill="x", padx=16, pady=14)
        tk.Label(sb, text="Securely delete files (7-pass overwrite)",
                 font=("Segoe UI",10,"bold"), bg=CARD, fg=TEXT).pack(anchor="w")
        tk.Label(sb, text="Files are overwritten with random data before deletion — unrecoverable even with forensic tools.",
                 font=("Segoe UI",8), bg=CARD, fg=TEXT_DIM, wraplength=600, justify="left"
                 ).pack(anchor="w")
        self._shred_passes_var = tk.IntVar(value=3)
        pf2 = tk.Frame(sb, bg=CARD); pf2.pack(anchor="w", pady=(8,0))
        tk.Label(pf2, text="Passes:", font=("Segoe UI",9), bg=CARD, fg=TEXT_MID).pack(side="left")
        for n,lbl in [(1,"Fast"),(3,"Standard"),(7,"DoD 7-Pass")]:
            rb = tk.Radiobutton(pf2, text=lbl, variable=self._shred_passes_var,
                                value=n, bg=CARD, fg=TEXT_DIM, selectcolor=BORDER,
                                activebackground=CARD, activeforeground=TEXT,
                                font=("Segoe UI",9), cursor="hand2")
            rb.pack(side="left", padx=(12,0))
        bf3 = tk.Frame(sb, bg=CARD); bf3.pack(anchor="w", pady=(10,0))
        self._btn(bf3,"📄  Add Files",DANGER,"#fff",self._shred_add_files).pack(side="left",padx=(0,8))
        self._btn(bf3,"📁  Add Folder",BORDER,TEXT,self._shred_add_folder).pack(side="left")
        self._shred_list_frame = tk.Frame(inner, bg=BG)
        self._shred_list_frame.pack(fill="x", padx=28)
        self._shred_queue = []

        # ── Privacy Tools ──────────────────────────────────────────
        section("🕵️  Privacy Tools", ACCENT2)
        tool_card(inner,"🖥️","Clear Clipboard","Remove sensitive data from the clipboard",
                  "Clear",ACCENT2, self._clear_clipboard)
        tool_card(inner,"🔍","Reveal Hidden File Extensions",
                  "Show .exe, .vbs and other dangerous extensions hidden by Windows",
                  "Enable",WARNING, self._show_extensions)
        tool_card(inner,"📡","Flush DNS Cache","Remove cached DNS entries — helps after malware cleanup",
                  "Flush",ACCENT2, self._flush_dns)

        # ── System Tools ───────────────────────────────────────────
        section("⚙️  System Tools", TEXT_MID)
        tool_card(inner,"🔄","Refresh Group Policy","Force Windows to apply Group Policy updates",
                  "Run",BORDER, lambda: self._run_tool_cmd("gpupdate /force","Group Policy refreshed."))
        tool_card(inner,"🛡️","Run System File Check","Scan and repair corrupted Windows system files (SFC)",
                  "Run SFC",BORDER, lambda: self._run_tool_cmd("sfc /scannow","SFC launched in background."))
        tool_card(inner,"💾","Check Disk Health","Run a quick SMART health check on all drives",
                  "Check",BORDER, self._check_disk_health)

        # ── Process Manager ────────────────────────────────────────
        section("⚡  Process Manager", WARNING)
        pm = tk.Frame(inner, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        pm.pack(fill="x", padx=28, pady=3)
        phdr = tk.Frame(pm, bg=CARD); phdr.pack(fill="x", padx=16, pady=(12,6))
        tk.Label(phdr, text="Running Processes", font=("Segoe UI",10,"bold"),
                 bg=CARD, fg=TEXT).pack(side="left")
        self._btn(phdr,"🔄",BORDER,TEXT,self._refresh_processes).pack(side="right")
        trf2 = tk.Frame(pm, bg=CARD); trf2.pack(fill="x", padx=12, pady=(0,12))
        self._proc_tree = ttk.Treeview(trf2,
            columns=("pid","name","mem","cpu","risk"),
            show="headings", style="Startup.Treeview", height=10)
        for col,w,lbl in [("pid",60,"PID"),("name",200,"Process"),
                           ("mem",90,"Memory"),("cpu",70,"CPU%"),("risk",80,"Risk")]:
            self._proc_tree.heading(col,text=lbl); self._proc_tree.column(col,width=w,minwidth=40)
        ps2 = DarkScrollbar(trf2,orient="vertical",command=self._proc_tree.yview)
        self._proc_tree.configure(yscrollcommand=ps2.set)
        ps2.pack(side="right",fill="y"); self._proc_tree.pack(fill="x",expand=True)
        self._proc_tree.tag_configure("danger",foreground=DANGER)
        self._proc_tree.tag_configure("warn",  foreground=WARNING)
        pkf = tk.Frame(pm, bg=CARD); pkf.pack(fill="x", padx=16, pady=(0,12))
        self._btn(pkf,"💀  Kill Selected",DANGER,"#fff",self._kill_process).pack(side="left")
        tk.Frame(inner,bg=BG,height=20).pack()
        self._refresh_processes()

    def _shred_add_files(self):
        files = filedialog.askopenfilenames(title="Select files to shred")
        for f in files:
            if f not in self._shred_queue:
                self._shred_queue.append(f)
        self._refresh_shred_list()

    def _shred_add_folder(self):
        folder = filedialog.askdirectory(title="Select folder to shred")
        if folder and folder not in self._shred_queue:
            self._shred_queue.append(folder)
            self._refresh_shred_list()

    def _refresh_shred_list(self):
        for w in self._shred_list_frame.winfo_children(): w.destroy()
        if not self._shred_queue:
            return
        for path in list(self._shred_queue):
            r = tk.Frame(self._shred_list_frame, bg=CARD,
                         highlightbackground=DANGER, highlightthickness=1)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=path, font=("Segoe UI",8), bg=CARD, fg=TEXT_MID,
                     anchor="w").pack(side="left", padx=12, pady=6, fill="x", expand=True)
            def _rm(p=path):
                self._shred_queue.remove(p); self._refresh_shred_list()
            tk.Button(r, text="✕", command=_rm, bg=CARD, fg=TEXT_DIM,
                      relief="flat", bd=0, cursor="hand2", font=("Segoe UI",9),
                      activebackground=CARD, activeforeground=DANGER
                      ).pack(side="right", padx=8)
        af = tk.Frame(self._shred_list_frame, bg=BG)
        af.pack(fill="x", pady=6)
        self._btn(af,"🔥  Shred Now",DANGER,"#fff",self._do_shred).pack(side="left")

    def _do_shred(self):
        if not self._shred_queue:
            return
        passes = self._shred_passes_var.get()
        dlg = ConfirmDialog(self,"Shred Files",
            f"Permanently destroy {len(self._shred_queue)} item(s) with {passes} overwrite pass(es)?\n\nThis CANNOT be undone.",
            ok="Shred", danger=True, icon="🔥")
        if not dlg.result: return
        q = list(self._shred_queue); self._shred_queue.clear()
        self._refresh_shred_list()
        threading.Thread(target=self._shred_bg, args=(q, passes), daemon=True).start()

    def _shred_bg(self, paths, passes):
        count = 0
        for path in paths:
            if os.path.isfile(path):
                try:
                    size = os.path.getsize(path)
                    with open(path,"r+b") as f:
                        for _ in range(passes):
                            f.seek(0); f.write(os.urandom(size))
                    os.remove(path); count += 1
                except: pass
            elif os.path.isdir(path):
                import shutil
                for root,_,files in os.walk(path):
                    for fn in files:
                        fp = os.path.join(root,fn)
                        try:
                            sz = os.path.getsize(fp)
                            with open(fp,"r+b") as f:
                                for _ in range(passes): f.seek(0); f.write(os.urandom(sz))
                            os.remove(fp); count += 1
                        except: pass
                try: import shutil; shutil.rmtree(path, ignore_errors=True)
                except: pass
        self.after(0, lambda: self._show_toast("Shred Complete",
            f"{count} file(s) securely destroyed ({passes} passes).", "🔥", DANGER, 5000))

    def _clear_clipboard(self):
        try:
            self.clipboard_clear()
            self._show_toast("Clipboard Cleared","Clipboard contents removed.","🖥️",ACCENT2)
        except: pass

    def _show_extensions(self):
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k,"HideFileExt",0,winreg.REG_DWORD,0)
            winreg.CloseKey(k)
            self._show_toast("Extensions Visible",
                "File extensions are now shown. Restart Explorer to apply.","✅",ACCENT)
        except Exception as e:
            self._show_toast("Error",str(e),"❌",DANGER)

    def _flush_dns(self):
        threading.Thread(target=lambda: (
            subprocess.run(["ipconfig","/flushdns"],capture_output=True,creationflags=_NOCONSOLE),
            self.after(0, lambda: self._show_toast("DNS Flushed","DNS cache cleared.","📡",ACCENT2))
        ), daemon=True).start()

    def _run_tool_cmd(self, cmd, success_msg):
        parts = cmd.split()
        threading.Thread(
            target=lambda: (
                subprocess.run(parts,capture_output=True,creationflags=_NOCONSOLE),
                self.after(0, lambda: self._show_toast("Done", success_msg, "✅", ACCENT))
            ), daemon=True).start()
        self._show_toast("Running…", f"Executing: {cmd}", "⚙️", TEXT_MID, 3000)

    def _check_disk_health(self):
        def _check():
            try:
                r = subprocess.run(["wmic","diskdrive","get","Status"],
                    capture_output=True, text=True, creationflags=_NOCONSOLE, timeout=10)
                lines = [l.strip() for l in r.stdout.splitlines() if l.strip() and l.strip()!="Status"]
                status = ", ".join(lines) if lines else "Unknown"
                msg = f"Drive status: {status}"
                color = ACCENT if "OK" in status else WARNING
                self.after(0, lambda: self._show_toast("Disk Health", msg, "💾", color, 6000))
            except Exception as e:
                self.after(0, lambda: self._show_toast("Error",str(e),"❌",DANGER))
        threading.Thread(target=_check, daemon=True).start()

    def _refresh_processes(self):
        try:
            for r in self._proc_tree.get_children(): self._proc_tree.delete(r)
        except: return
        threading.Thread(target=self._refresh_processes_bg, daemon=True).start()

    def _refresh_processes_bg(self):
        rows = []
        try:
            r = subprocess.run(
                ["wmic","process","get","ProcessId,Name,WorkingSetSize","/format:csv"],
                capture_output=True, text=True, timeout=10, creationflags=_NOCONSOLE)
            for line in r.stdout.splitlines():
                parts = line.strip().split(",")
                if len(parts)<4 or not parts[1].strip(): continue
                try:
                    name = parts[2].strip(); pid = parts[3].strip()
                    mem  = int(parts[1].strip() or 0)
                    tag  = "ok"
                    risk = "—"
                    nl = name.lower().replace(".exe","")
                    if any(s in nl for s in SUSPICIOUS_PROCS): tag="danger"; risk="HIGH"
                    mem_s = f"{mem//1024//1024} MB" if mem>1048576 else f"{mem//1024} KB"
                    rows.append((pid,name,mem_s,"",risk,tag))
                except: pass
            rows.sort(key=lambda x: x[2], reverse=True)
        except: pass
        self.after(0, lambda: self._populate_processes(rows))

    def _populate_processes(self, rows):
        try:
            for r in self._proc_tree.get_children(): self._proc_tree.delete(r)
            for pid,name,mem,cpu,risk,tag in rows[:80]:
                self._proc_tree.insert("","end",values=(pid,name,mem,cpu,risk),tags=(tag,))
        except: pass

    def _kill_process(self):
        sel = self._proc_tree.selection()
        if not sel: return
        vals = self._proc_tree.item(sel[0],"values")
        pid = vals[0]; name = vals[1]
        dlg = ConfirmDialog(self,"Kill Process",
            f"Terminate '{name}' (PID {pid})?\n\nUnsaved work in that process will be lost.",
            ok="Kill", danger=True, icon="💀")
        if dlg.result:
            try:
                subprocess.run(["taskkill","/F","/PID",pid],capture_output=True,
                               creationflags=_NOCONSOLE)
                self._show_toast("Process Killed",f"'{name}' terminated.","✅",ACCENT)
                self.after(500, self._refresh_processes)
            except Exception as e:
                self._show_toast("Error",str(e),"❌",DANGER)

    # ──────────────────────────────────────────────────────────────
    # SYSTEM TRAY
    # ──────────────────────────────────────────────────────────────
    def _setup_tray(self):
        if not HAS_TRAY: return
        try:
            col = (0,229,160) if self._rt_running else (255,71,87)
            img = Image.new("RGBA",(64,64),(0,0,0,0))
            d   = ImageDraw.Draw(img)
            d.polygon([(32,4),(58,16),(54,48),(32,60),(10,48),(6,16)], fill=(*col,255))
            d.polygon([(32,14),(48,22),(45,44),(32,52),(19,44),(16,22)], fill=(20,20,30,255))
            if self._rt_running:
                d.line([(24,32),(30,40),(42,24)], fill=(*col,255), width=3)
            menu = pystray.Menu(
                pystray.MenuItem("Gifty Antivirus — PREMIUM", None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem(lambda i: f"{'● ON' if self._rt_running else '○ OFF'} Real-Time", None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Show Window",     self._tray_show),
                pystray.MenuItem("Quick Scan",      self._tray_scan),
                pystray.MenuItem("Toggle Real-Time",self._tray_toggle),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit",            self._tray_exit),
            )
            self._tray = pystray.Icon("gifty_av", img, "Gifty Antivirus — PREMIUM", menu)
            threading.Thread(target=self._tray.run, daemon=True).start()
        except: self._tray = None

    def _update_tray(self, ok=True):
        if self._tray and HAS_TRAY:
            try:
                col = (0,229,160) if ok else (255,71,87)
                img = Image.new("RGBA",(64,64),(0,0,0,0))
                d = ImageDraw.Draw(img)
                d.polygon([(32,4),(58,16),(54,48),(32,60),(10,48),(6,16)], fill=(*col,255))
                self._tray.icon = img
            except: pass

    def _tray_show(self, *a):   self.after(0, lambda: (self.deiconify(), self.lift(), self.focus_force()))
    def _tray_scan(self, *a):   self.after(0, lambda: self._quick_action("quick")); self.after(50, lambda: self.deiconify())
    def _tray_toggle(self, *a): self.after(0, lambda: self._toggle_master_rt(not self._rt_running))
    def _tray_exit(self, *a):
        self._really_exit = True
        if self._tray:
            try: self._tray.stop()
            except: pass
        self.after(0, self._force_quit)

    def _force_quit(self):
        self._scan_cancel = True
        self._rt_running = False
        self._file_monitor.stop()
        save_data(self.data)
        release_instance()
        self.destroy()

    def _on_close(self):
        if self.data["settings"].get("minimize_to_tray", True) and HAS_TRAY:
            if not self._tray: self._setup_tray()
            self.withdraw()
        else:
            self._force_quit()


# ═══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Must be called before ANY window creation to override Python's taskbar icon
    if sys.platform == "win32":
        try:
            import ctypes as _ct
            _ct.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "GiftySoftware.GiftyAntivirus.4.0")
        except: pass

    if sys.platform != "win32":
        root = tk.Tk(); root.withdraw()
        messagebox.showerror("Gifty Antivirus",
            "Gifty Antivirus is designed for Windows only.\n"
            "Please run this on a Windows system.")
        root.destroy(); sys.exit(1)

    if not acquire_instance():
        root = tk.Tk(); root.withdraw()
        messagebox.showwarning("Already Running",
            "Gifty Antivirus is already running.\n"
            "Check the system tray.")
        root.destroy(); sys.exit(0)

    try:
        app = GiftyAV()
        threading.Thread(target=fb_ping_user, daemon=True).start()
        app.mainloop()
    finally:
        release_instance()