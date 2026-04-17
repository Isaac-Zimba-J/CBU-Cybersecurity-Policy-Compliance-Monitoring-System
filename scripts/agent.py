#!/usr/bin/env python3
"""
CBU Cybersecurity Compliance Monitoring Agent
=============================================
Deploy this script on endpoint machines (Windows/Linux/Mac).
It collects system activity and reports it to the central server.

Usage:
  python agent.py --server http://192.168.1.X:8000

Requirements:
  pip install requests psutil
"""

import argparse
import json
import platform
import socket
import time
import os
import logging
from datetime import datetime, timezone
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
POLL_INTERVAL  = 10    # seconds between log batches
INGEST_URL     = "/logs/ingest/batch"

ENDPOINT_ID    = socket.gethostname()
ENDPOINT_IP    = socket.gethostbyname(ENDPOINT_ID)
OS_TYPE        = platform.system().lower()   # windows / linux / darwin

# ── Helpers ───────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

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

# ── Collectors ────────────────────────────────────────────────────────────────

_prev_connections = set()
_prev_processes   = set()

def collect_network_connections() -> list:
    """Detect new outbound network connections."""
    global _prev_connections
    events = []
    try:
        current = set()
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                key = (conn.raddr.ip, conn.raddr.port)
                current.add(key)
                if key not in _prev_connections:
                    events.append(make_log("network_connection", {
                        "dest_ip":   conn.raddr.ip,
                        "dest_port": conn.raddr.port,
                        "local_port": conn.laddr.port if conn.laddr else None,
                    }))
        _prev_connections = current
    except (psutil.AccessDenied, Exception):
        pass
    return events


def collect_process_events() -> list:
    """Detect newly started processes."""
    global _prev_processes
    events = []
    try:
        current = {}
        for proc in psutil.process_iter(["pid", "name", "username", "create_time"]):
            try:
                current[proc.pid] = proc.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        new_pids = set(current.keys()) - _prev_processes
        for pid in new_pids:
            info = current[pid]
            events.append(make_log("process_started", {
                "pid":          pid,
                "process_name": info.get("name", "unknown"),
            }, username=info.get("username") or get_current_user()))

        _prev_processes = set(current.keys())
    except Exception:
        pass
    return events


def collect_usb_events_linux() -> list:
    """Detect USB devices on Linux via /sys/bus/usb/devices."""
    events = []
    try:
        usb_path = "/sys/bus/usb/devices"
        if os.path.exists(usb_path):
            for device in os.listdir(usb_path):
                product_file = os.path.join(usb_path, device, "product")
                if os.path.isfile(product_file):
                    with open(product_file) as f:
                        product = f.read().strip()
                    if product:
                        events.append(make_log("usb_connected", {"device": product}))
    except Exception:
        pass
    return events


def collect_login_events() -> list:
    """Report currently logged-in users (sampled each cycle)."""
    events = []
    try:
        for user in psutil.users():
            events.append(make_log("login", {
                "terminal": user.terminal,
                "host":     user.host,
                "started":  user.started,
            }, username=user.name))
    except Exception:
        pass
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
            log.info(f"Sent {data['accepted']} logs | violations detected: "
                     f"{sum(r['violations'] for r in data.get('results', []))}")
            return True
        else:
            log.warning(f"Server returned {resp.status_code}: {resp.text[:200]}")
            return False
    except requests.ConnectionError:
        log.error(f"Cannot reach server at {server}. Retrying next cycle...")
        return False
    except Exception as e:
        log.error(f"Send error: {e}")
        return False


# ── Main loop ─────────────────────────────────────────────────────────────────

def run(server: str):
    log.info(f"Agent started on {ENDPOINT_ID} ({ENDPOINT_IP}) [{OS_TYPE}]")
    log.info(f"Reporting to: {server}")
    log.info(f"Poll interval: {POLL_INTERVAL}s")
    log.info("Press Ctrl+C to stop.\n")

    # Init baseline snapshots
    collect_process_events()
    collect_network_connections()

    while True:
        try:
            batch = []
            batch += collect_network_connections()
            batch += collect_process_events()
            batch += collect_login_events()

            if OS_TYPE == "linux":
                batch += collect_usb_events_linux()

            send_logs(server, batch)

        except KeyboardInterrupt:
            log.info("Agent stopped.")
            break
        except Exception as e:
            log.error(f"Unexpected error: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CBU Compliance Monitoring Agent")
    parser.add_argument(
        "--server", default=DEFAULT_SERVER,
        help=f"Server URL (default: {DEFAULT_SERVER})"
    )
    args = parser.parse_args()
    run(args.server)
