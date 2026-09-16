#!/usr/bin/env python3
"""
CBU Cybersecurity Compliance Monitoring Agent
=============================================
Deploy this script on endpoint machines (Windows/Linux/Mac).
It collects system activity and reports it to the central server.

Usage:
  python agent.py --server http://192.168.1.X:8000
  python agent.py --server http://192.168.1.X:8000 --simulate usb     # fire one fake event and exit
  python agent.py --list-simulations

What it watches (all real, no fake data):
  process_started     every new process (catches short-lived ones like nmap/nc)
  network_connection  every new outbound connection (ESTABLISHED or attempting)
  usb_connected       removable drives being plugged in (Windows/Mac/Linux)
  file_transfer       files copied onto a removable drive
  login               interactive sessions (reported once per session)
  login_failed        bad sudo/su/console/ssh passwords (best effort per OS)

Requirements:
  pip install requests psutil
"""

import argparse
import json
import platform
import re
import socket
import subprocess
import threading
import time
import os
import logging
from datetime import datetime
from typing import Optional

try:
    import requests
    import psutil
except ImportError:
    print("Missing dependencies. Run: pip install requests psutil")
    exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AGENT] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_SERVER = "http://localhost:8000"
SEND_INTERVAL  = 5     # seconds between batches sent to the server
SCAN_INTERVAL  = 1     # seconds between process/network scans (catches short-lived commands)
INGEST_URL     = "/logs/ingest/batch"

# File extensions treated as "encrypted" when copied to removable media.
ENCRYPTED_EXTS = {".gpg", ".pgp", ".enc", ".aes", ".7z", ".zip.enc", ".kdbx"}
# Files on USB drives that are never interesting.
IGNORED_FILE_PATTERNS = ("System Volume Information", ".Spotlight-V100", ".Trashes",
                         ".fseventsd", ".TemporaryItems", "$RECYCLE.BIN", "desktop.ini", ".DS_Store")

ENDPOINT_ID = socket.gethostname()
try:
    ENDPOINT_IP = socket.gethostbyname(ENDPOINT_ID)
except socket.gaierror:
    ENDPOINT_IP = "127.0.0.1"
OS_TYPE = platform.system().lower()   # windows / linux / darwin

# ── Helpers ───────────────────────────────────────────────────────────────────

def now_iso() -> str:
    # Local time WITH offset, so the server's "business hours" rule sees wall-clock time.
    return datetime.now().astimezone().isoformat()

def get_current_user() -> str:
    return os.getenv("USERNAME") or os.getenv("USER") or "unknown"

def make_log(event_type: str, event_data: dict, username: Optional[str] = None) -> dict:
    return {
        "endpoint_id": ENDPOINT_ID,
        "endpoint_ip": ENDPOINT_IP,
        "username": username or get_current_user(),
        "event_type": event_type,
        "event_data": json.dumps(event_data),
        "timestamp": now_iso(),
    }

def clean_process_name(name: str) -> str:
    base = os.path.basename((name or "").replace("\\", "/"))
    return base or "unknown"

# ── Collectors: processes ─────────────────────────────────────────────────────

_prev_processes: set = set()
_pending_processes: dict = {}   # pid -> scans waited; a just-forked child still shows the parent's name

def collect_process_events(baseline: bool = False) -> list:
    """Detect newly started processes."""
    global _prev_processes
    events = []
    try:
        current = {}
        for proc in psutil.process_iter(["pid", "name", "username", "create_time", "cmdline", "exe"]):
            try:
                current[proc.pid] = proc.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # The fork/exec name race is POSIX-only. On Windows a new process has its
        # real name immediately, and deferring can DROP a short-lived command
        # (e.g. `nmap -sT`) that exits before the deferral clears — so report at once.
        defer_naming = OS_TYPE != "windows"

        if not baseline:
            for pid in set(current) - _prev_processes:
                info = current[pid]
                cmdline = " ".join(info.get("cmdline") or [])[:200]
                # Between fork() and exec() the child is a clone of the shell with no
                # cmdline yet; wait up to 2 scans so we report the real program name.
                if defer_naming and not cmdline and _pending_processes.get(pid, 0) < 2:
                    _pending_processes[pid] = _pending_processes.get(pid, 0) + 1
                    continue
                _pending_processes.pop(pid, None)
                name = clean_process_name(info.get("name") or (info.get("exe") or ""))
                events.append(make_log("process_started", {
                    "pid": pid,
                    "process_name": name,
                    "cmdline": cmdline,
                }, username=info.get("username") or get_current_user()))

        reported = set(current) - set(_pending_processes)
        _prev_processes = reported
        for pid in list(_pending_processes):
            if pid not in current:
                _pending_processes.pop(pid)
    except Exception as e:
        log.debug(f"process scan failed: {e}")
    return events

# ── Collectors: network ───────────────────────────────────────────────────────

_prev_connections: set = set()
_pid_name_cache: dict = {}

def _pid_name(pid) -> Optional[str]:
    if not pid:
        return None
    if pid not in _pid_name_cache:
        try:
            _pid_name_cache[pid] = psutil.Process(pid).name()
        except Exception:
            _pid_name_cache[pid] = None
    return _pid_name_cache[pid]

# ESTABLISHED = live connection, SYN_SENT = attempt in progress (blocked/unreachable
# ports linger here). The closing states are included so a short-lived outbound
# connection is still caught on at least one 1-second scan.
_WATCHED_STATES = ("ESTABLISHED", "SYN_SENT", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT", "LAST_ACK")
# Conn = (dest_ip, dest_port, local_port, status, pid)


def _conns_via_psutil() -> Optional[list]:
    """System-wide connection list via psutil, or None if the OS denies it.

    On macOS this raises AccessDenied without root and the per-process fallback
    returns nothing either, so we return None and let netstat take over.
    """
    try:
        out = []
        for c in psutil.net_connections(kind="inet"):
            if c.status in _WATCHED_STATES and c.raddr:
                out.append((c.raddr.ip, c.raddr.port,
                            c.laddr.port if c.laddr else None, c.status, c.pid))
        return out
    except (psutil.AccessDenied, PermissionError):
        return None
    except Exception as e:
        log.debug(f"psutil net scan failed: {e}")
        return None


def _split_addr(addr: str):
    """Parse an address:port from netstat, both formats:
    Windows '1.1.1.1:23' / '[::1]:80'  and  BSD/macOS '127.0.0.1.6881' / '::1.80'.
    '*.*' / '*:*' -> (None, None).
    """
    if not addr or addr.startswith("*"):
        return None, None
    if addr.startswith("["):                       # Windows IPv6: [::1]:80
        host, _, port = addr.rpartition("]:")
        host = host.lstrip("[")
    elif ":" in addr and addr.count(":") == 1:      # Windows IPv4: host:port
        host, _, port = addr.rpartition(":")
    else:                                           # BSD/macOS: host.port
        host, _, port = addr.rpartition(".")
    if not port.isdigit():
        return None, None
    return (host or None), int(port)


def _conns_via_netstat() -> list:
    """Parse netstat output. Needs no elevated privileges on macOS or Windows.
    Windows: `netstat -ano`  ·  macOS/BSD: `netstat -anv -p tcp`.
    """
    win = OS_TYPE == "windows"
    cmd = ["netstat", "-ano"] if win else ["netstat", "-anv", "-p", "tcp"]
    try:
        raw = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except Exception as e:
        log.debug(f"netstat failed: {e}")
        return []
    out = []
    for line in raw.splitlines():
        parts = line.split()
        if not parts or not parts[0].lower().startswith("tcp"):
            continue
        if win:
            # Proto  Local  Foreign  State  PID
            if len(parts) < 4:
                continue
            local, foreign, status = parts[1], parts[2], parts[3]
            pid = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else None
        else:
            # Proto Recv-Q Send-Q Local Foreign (state) ... pid
            if len(parts) < 6:
                continue
            local, foreign, status = parts[3], parts[4], parts[5]
            pid = int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else None
        if status not in _WATCHED_STATES:
            continue
        dest_ip, dest_port = _split_addr(foreign)
        _, local_port = _split_addr(local)
        if dest_port is None:
            continue
        out.append((dest_ip, dest_port, local_port, status, pid))
    return out


def _collect_connections() -> list:
    conns = _conns_via_psutil()
    # psutil denied (returns None) or came back empty — fall back to netstat,
    # which needs no elevated privileges and works on macOS and Windows.
    if not conns:
        return _conns_via_netstat()
    return conns


def collect_network_connections(baseline: bool = False) -> list:
    """Detect new outbound connections — including attempts that never complete (SYN_SENT)."""
    global _prev_connections
    events = []
    try:
        current = set()
        for dest_ip, dest_port, local_port, status, pid in _collect_connections():
            key = (dest_ip, dest_port, local_port)
            current.add(key)
            if not baseline and key not in _prev_connections:
                events.append(make_log("network_connection", {
                    "dest_ip":      dest_ip,
                    "dest_port":    dest_port,
                    "local_port":   local_port,
                    "status":       status,
                    "process_name": _pid_name(pid),
                }))
        _prev_connections = current
    except Exception as e:
        log.debug(f"network scan failed: {e}")
    return events

# ── Collectors: removable media + files copied to it ─────────────────────────

_known_volumes: dict = {}     # mountpoint -> label
_volume_files: dict = {}      # mountpoint -> {relpath: (size, mtime)}

def _volume_label(part) -> str:
    mp = part.mountpoint
    if OS_TYPE == "windows":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(261)
            ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(mp), buf, 261, None, None, None, None, 0)
            if buf.value:
                return f"{buf.value} ({mp})"
        except Exception:
            pass
        return mp
    return os.path.basename(mp.rstrip("/")) or mp

def _is_removable(part) -> bool:
    mp, opts = part.mountpoint, (part.opts or "").lower()
    if OS_TYPE == "windows":
        return "removable" in opts or "cdrom" in opts
    if OS_TYPE == "darwin":
        return mp.startswith("/Volumes/") and "nobrowse" not in opts
    # linux
    return mp.startswith(("/media/", "/run/media/", "/mnt/"))

def _list_volume_files(mp: str, limit: int = 5000) -> dict:
    files = {}
    try:
        for root, dirs, names in os.walk(mp):
            dirs[:] = [d for d in dirs if not d.startswith(IGNORED_FILE_PATTERNS)]
            for n in names:
                if n.startswith(IGNORED_FILE_PATTERNS) or n.startswith("._"):
                    continue
                full = os.path.join(root, n)
                try:
                    st = os.stat(full)
                    files[os.path.relpath(full, mp)] = (st.st_size, int(st.st_mtime))
                except OSError:
                    continue
                if len(files) >= limit:
                    return files
    except Exception:
        pass
    return files

def collect_usb_events_linux_sysfs(baseline: bool = False) -> list:
    """Linux extra: USB devices that are NOT storage (keyboards, phones...) via sysfs."""
    global _known_usb_sysfs
    events = []
    usb_path = "/sys/bus/usb/devices"
    if not os.path.isdir(usb_path):
        return events
    try:
        current = {}
        for device in os.listdir(usb_path):
            product_file = os.path.join(usb_path, device, "product")
            if os.path.isfile(product_file):
                with open(product_file) as f:
                    current[device] = f.read().strip()
        if not baseline:
            for dev, product in current.items():
                if dev not in _known_usb_sysfs and product and "hub" not in product.lower():
                    events.append(make_log("usb_connected", {"device": product, "bus_id": dev}))
        _known_usb_sysfs = current
    except Exception:
        pass
    return events

_known_usb_sysfs: dict = {}

def collect_removable_media(baseline: bool = False) -> list:
    """usb_connected when a removable drive appears; file_transfer for every new file on it."""
    events = []
    try:
        seen = {}
        for part in psutil.disk_partitions(all=False):
            if not _is_removable(part):
                continue
            mp = part.mountpoint
            seen[mp] = _volume_label(part)
            if mp not in _known_volumes:
                _volume_files[mp] = _list_volume_files(mp)
                if not baseline:
                    events.append(make_log("usb_connected", {
                        "device": seen[mp], "mountpoint": mp, "fstype": part.fstype,
                    }))
                    log.info(f"Removable media detected: {seen[mp]} at {mp}")
                continue

            # Volume already known — look for files that were added/changed since last scan
            before = _volume_files.get(mp, {})
            after = _list_volume_files(mp)
            for rel, meta in after.items():
                if before.get(rel) != meta:
                    ext = os.path.splitext(rel)[1].lower()
                    events.append(make_log("file_transfer", {
                        "filename":    os.path.basename(rel),
                        "path":        rel,
                        "destination": seen[mp],
                        "size_bytes":  meta[0],
                        "encrypted":   ext in ENCRYPTED_EXTS,
                        "direction":   "to_removable_media",
                    }))
            _volume_files[mp] = after

        for mp in list(_known_volumes):
            if mp not in seen:
                log.info(f"Removable media removed: {_known_volumes[mp]}")
                _volume_files.pop(mp, None)
        _known_volumes.clear()
        _known_volumes.update(seen)
    except Exception as e:
        log.debug(f"removable media scan failed: {e}")

    if OS_TYPE == "linux":
        events += collect_usb_events_linux_sysfs(baseline)
    return events

# ── Collectors: logins ────────────────────────────────────────────────────────

_known_sessions: set = set()

def collect_login_events(baseline: bool = False) -> list:
    """Report each interactive session ONCE (new sessions since last scan)."""
    global _known_sessions
    events = []
    try:
        current = set()
        for user in psutil.users():
            key = (user.name, user.terminal, int(user.started or 0))
            current.add(key)
            if key not in _known_sessions:
                events.append(make_log("login", {
                    "terminal": user.terminal,
                    "host":     user.host,
                    "started":  datetime.fromtimestamp(user.started).isoformat() if user.started else None,
                }, username=user.name))
        _known_sessions = current
    except Exception:
        pass
    # Sessions already open when the agent starts are reported once, so
    # starting the agent out of hours is itself visible on the dashboard.
    return events

# ── Collectors: failed OS logins (best effort per platform) ──────────────────

_failed_login_lines: list = []
_failed_lock = threading.Lock()
_stream_proc = None

FAILED_PATTERNS = [
    re.compile(r"(?P<user>[\w.\-]+) : \d+ incorrect password attempt", re.I),         # sudo (mac/linux)
    re.compile(r"Failed password for (?:invalid user )?(?P<user>[\w.\-]+)", re.I),     # sshd
    re.compile(r"FAILED (?:SU|LOGIN).*?(?:for|to) (?P<user>[\w.\-]+)", re.I),          # su / login
    re.compile(r"authentication failure;.*?user=(?P<user>[\w.\-]*)", re.I),            # pam
    re.compile(r"Authentication failed for user <?(?P<user>[\w.\-]+)>?", re.I),        # loginwindow / gdm
]

def _start_failed_login_stream():
    """macOS: `log stream` in the background. Linux: tail auth log or journalctl."""
    global _stream_proc
    cmd = None
    if OS_TYPE == "darwin":
        pred = ('process == "sudo" OR process == "su" OR process == "loginwindow" '
                'OR process == "sshd" OR process == "screensharingd" OR process == "authd"')
        cmd = ["log", "stream", "--style", "compact", "--predicate", pred]
    elif OS_TYPE == "linux":
        for path in ("/var/log/auth.log", "/var/log/secure"):
            if os.path.isfile(path) and os.access(path, os.R_OK):
                cmd = ["tail", "-n", "0", "-F", path]
                break
        if cmd is None:
            cmd = ["journalctl", "-f", "-n", "0", "-o", "cat", "-q",
                   "_COMM=sudo", "_COMM=su", "_COMM=sshd", "_COMM=login", "_COMM=gdm-password"]
    if cmd is None:
        return
    try:
        _stream_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, bufsize=1)
    except Exception as e:
        log.warning(f"Failed-login monitoring unavailable ({e})")
        return

    def reader():
        for line in _stream_proc.stdout:
            with _failed_lock:
                _failed_login_lines.append(line.rstrip())
    threading.Thread(target=reader, daemon=True).start()
    log.info(f"Failed-login monitor started ({' '.join(cmd[:2])})")

_last_win_check = None

def _collect_failed_logins_windows() -> list:
    """Security event 4625 via wevtutil (needs the agent to run as Administrator)."""
    global _last_win_check
    events = []
    ms = int((SEND_INTERVAL + 1) * 1000)
    query = f"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    try:
        out = subprocess.run(["wevtutil", "qe", "Security", f"/q:{query}", "/f:xml", "/c:50"],
                             capture_output=True, text=True, timeout=10)
        if out.returncode != 0:
            return events
        for block in re.findall(r"<Event .*?</Event>", out.stdout, re.S):
            rec = re.search(r"<EventRecordID>(\d+)</EventRecordID>", block)
            rec_id = int(rec.group(1)) if rec else None
            if rec_id is not None and _last_win_check is not None and rec_id <= _last_win_check:
                continue
            user = re.search(r"<Data Name='TargetUserName'>([^<]*)</Data>", block)
            src = re.search(r"<Data Name='IpAddress'>([^<]*)</Data>", block)
            events.append(make_log("login_failed", {
                "source": "windows_security_log", "event_id": 4625,
                "client_ip": src.group(1) if src else None,
            }, username=(user.group(1) if user else None) or get_current_user()))
            if rec_id is not None:
                _last_win_check = max(_last_win_check or 0, rec_id)
    except Exception:
        pass
    return events

def collect_failed_logins() -> list:
    if OS_TYPE == "windows":
        return _collect_failed_logins_windows()
    events = []
    with _failed_lock:
        lines, _failed_login_lines[:] = list(_failed_login_lines), []
    for line in lines:
        for pat in FAILED_PATTERNS:
            m = pat.search(line)
            if m:
                user = (m.groupdict().get("user") or "").strip() or get_current_user()
                events.append(make_log("login_failed", {
                    "source": "os_auth_log", "detail": line[-160:],
                }, username=user))
                break
    return events

# ── Send to server ────────────────────────────────────────────────────────────

def send_logs(server: str, logs: list) -> bool:
    if not logs:
        return True
    try:
        url = server.rstrip("/") + INGEST_URL
        resp = requests.post(url, json=logs, timeout=10)
        if resp.status_code == 201:
            data = resp.json()
            results = data.get("results", [])
            flagged = [r for r in results if r.get("violations")]
            log.info(f"Sent {data['accepted']} events | violations flagged: {len(flagged)}")
            for r in flagged:
                for d in r.get("details", [f"{r.get('violations')} violation(s)"]):
                    log.warning(f"🚩 VIOLATION FLAGGED [{r.get('event_type')}] {d}")
            return True
        log.warning(f"Server returned {resp.status_code}: {resp.text[:200]}")
        return False
    except requests.ConnectionError:
        log.error(f"Cannot reach server at {server}. Retrying next cycle...")
        return False
    except Exception as e:
        log.error(f"Send error: {e}")
        return False

# ── Simulation (for demos where the physical action is impractical) ──────────

SIMULATIONS = {
    "usb":           ("usb_connected",      {"device": "SanDisk Cruzer 32GB", "simulated": True}),
    "file_transfer": ("file_transfer",      {"filename": "student_records.xlsx", "destination": "SanDisk Cruzer 32GB",
                                             "encrypted": False, "simulated": True}),
    "process":       ("process_started",    {"process_name": "nmap", "cmdline": "nmap -sS 192.168.1.0/24", "simulated": True}),
    "network":       ("network_connection", {"dest_ip": "10.0.0.99", "dest_port": 23, "status": "SYN_SENT", "simulated": True}),
    "login":         ("login",              {"terminal": "console", "simulated": True}),
    "failed_login":  ("login_failed",       {"source": "simulated"}),
}

def simulate(server: str, what: str, repeat: int):
    if what == "all":
        names = list(SIMULATIONS)
    elif what in SIMULATIONS:
        names = [what]
    else:
        log.error(f"Unknown simulation '{what}'. Options: {', '.join(SIMULATIONS)}, all")
        return
    batch = []
    for name in names:
        event_type, data = SIMULATIONS[name]
        batch += [make_log(event_type, data) for _ in range(repeat)]
    log.info(f"Simulating {len(batch)} event(s) from {ENDPOINT_ID}: {', '.join(names)}")
    send_logs(server, batch)

# ── Main loop ─────────────────────────────────────────────────────────────────

def run(server: str):
    log.info(f"Agent started on {ENDPOINT_ID} ({ENDPOINT_IP}) [{OS_TYPE}]")
    log.info(f"Reporting to: {server}")
    log.info(f"Scan every {SCAN_INTERVAL}s, send every {SEND_INTERVAL}s")
    log.info("Press Ctrl+C to stop.\n")

    # Baseline snapshots so existing state isn't reported as "new"
    collect_process_events(baseline=True)
    collect_network_connections(baseline=True)
    collect_removable_media(baseline=True)
    _start_failed_login_stream()

    buffer = []
    last_send = 0.0
    while True:
        tick = time.time()
        try:
            buffer += collect_process_events()
            buffer += collect_network_connections()
            scan_took = time.time() - tick

            if time.time() - last_send >= SEND_INTERVAL:
                buffer += collect_login_events()
                buffer += collect_removable_media()
                buffer += collect_failed_logins()
                t_send = time.time()
                if send_logs(server, buffer):
                    buffer = []
                elif len(buffer) > 2000:
                    buffer = buffer[-2000:]   # server down for a long time: keep the tail
                send_took = time.time() - t_send
                last_send = time.time()
                if send_took > SCAN_INTERVAL:
                    log.warning(f"Server took {send_took:.1f}s to accept the batch — short-lived events may be missed")

            if scan_took > SCAN_INTERVAL * 2:
                log.warning(f"Scan took {scan_took:.1f}s (expected <{SCAN_INTERVAL}s) — short-lived events may be missed")

        except KeyboardInterrupt:
            log.info("Agent stopped.")
            break
        except Exception as e:
            log.error(f"Unexpected error: {e}")

        try:
            time.sleep(SCAN_INTERVAL)
        except KeyboardInterrupt:
            log.info("Agent stopped.")
            break

    if _stream_proc:
        _stream_proc.terminate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CBU Compliance Monitoring Agent")
    parser.add_argument("--server", default=DEFAULT_SERVER,
                        help=f"Server URL (default: {DEFAULT_SERVER})")
    parser.add_argument("--simulate", metavar="EVENT",
                        help="Send one synthetic event and exit: " + ", ".join(SIMULATIONS) + ", all")
    parser.add_argument("--repeat", type=int, default=1,
                        help="With --simulate: how many copies to send (e.g. 5 failed logins)")
    parser.add_argument("--list-simulations", action="store_true")
    args = parser.parse_args()

    if args.list_simulations:
        for k, (et, d) in SIMULATIONS.items():
            print(f"  {k:14s} -> {et:20s} {json.dumps(d)}")
    elif args.simulate:
        simulate(args.server, args.simulate, args.repeat)
    else:
        run(args.server)
