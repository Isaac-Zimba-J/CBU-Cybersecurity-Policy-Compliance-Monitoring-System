# Testing Violations Live

How to make the system flag a **real** violation from an endpoint running the agent, and how to change the rules that decide what gets flagged.

Everything here was verified end-to-end (agent → server → dashboard). Nothing is faked unless you explicitly use `--simulate`.

---

## 1. Setup for a demo

**Server laptop**

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
python scripts/seed.py            # first time only
cd cbu-compliance-frontend && npm start
```

**Endpoint laptop** (the machine that will "misbehave" — can be the same laptop)

```bash
pip install requests psutil
python scripts/agent.py --server http://<SERVER-IP>:8000
```

The agent prints what it sends and shows `🚩 VIOLATION FLAGGED …` the moment the server flags something. Keep this terminal visible next to the browser during the demo.

**Browser** — log in as `admin / Admin@123` and open **Alerts** or **Violations**. Both pages now have a green **Live** toggle and refresh every 5 s. New rows flash red and carry a **NEW** badge. The dashboard refreshes every 10 s and the sidebar badges every 10 s.

> **Windows tip:** run the agent terminal **as Administrator** if you want OS-level failed-login detection (Security event 4625). Everything else works without it.
>
> **macOS tip:** the agent asks nothing extra, but the first `log stream` start may take ~2 s. Network scanning works without root (it scans your own processes).

---

## 2. The six violation types and how to trigger each one

Timing: the agent scans processes/connections every **1 s** and sends every **5 s**, so expect a flag within ~5–7 s of the action.

### 2.1 Blocked process — `process_execution` (CRITICAL)

Rule: `{"blocked_processes": ["nmap", "wireshark", "netcat", "nc", "mimikatz"]}`
Names are matched without path or `.exe`, so `nmap.exe` on Windows matches `nmap`.

| OS | Do this |
|----|---------|
| Windows | Open Wireshark, or run `nmap 127.0.0.1` in a terminal (install from nmap.org / wireshark.org) |
| macOS / Linux | `nc -l 4444` (built in) or `nmap 127.0.0.1` or open Wireshark |

Expected: `Blocked process 'nc' executed on <hostname>.`

To flag something you already have installed, edit the rule and add the process name — e.g. add `"notepad"` (Windows) or `"calculator"` (macOS) and open it. See §3.

### 2.2 Blocked port / IP — `network_access` (HIGH)

Rule: `{"blocked_ports": [23, 6881, 4444], "blocked_ips": ["10.0.0.99"]}`
Connection *attempts* count too (SYN_SENT), so the target does not need to exist.

The reliable trigger is a connection that **stays open for a few seconds** (a snapshot every second has to catch it). A connection attempt to an unreachable host is ideal because it lingers in `SYN_SENT`:

| OS | Do this |
|----|---------|
| Windows | `Test-NetConnection 192.168.1.250 -Port 23` in PowerShell |
| macOS / Linux | `nc -w 6 192.168.1.250 23 < /dev/null` — pick a LAN IP that does **not** exist so it hangs ~6 s |
| Any (port 6881, held open) | Terminal 1: `nc -l 6881` · Terminal 2: `nc 127.0.0.1 6881` then **leave it open** (don't type/close for ~6 s) |

Expected: `Connection to blocked port 23 on 192.168.1.250 from <hostname> (process: nc).`

> A connection that opens and closes in under a second (e.g. `curl` to a fast local port) may be missed — that's why the examples keep the socket open. Attempts to a non-existent host, or any real session (browser tab, download), stay open long enough.
>
> On **macOS** the agent reads connections via `netstat` (no `sudo` needed). On **Windows/Linux** it uses the OS connection table directly.

To block a real site for the demo: edit the rule and add the site's IP prefix to `blocked_ips` (e.g. `"142.250."` for Google) then open it in a browser.

### 2.3 Unauthorised USB — `usb_device` (HIGH)

Rule: `{"allowed": false, "allowed_devices": []}`

**Do this:** plug in any USB flash drive. The agent reports it once when the volume mounts (Windows removable drives, macOS `/Volumes/*`, Linux `/media`, `/run/media`, `/mnt`).

Expected: `Unauthorised USB/removable device 'KINGSTON (E:\)' connected on endpoint <hostname>.`

To whitelist a device: add part of its label to `allowed_devices`, e.g. `["KINGSTON"]`. Unplug, re-plug — no violation.

### 2.4 Unencrypted file transfer — `data_transfer` (HIGH)

Rule: `{"require_encryption": true}`

**Do this:** with the USB drive still plugged in, copy any file onto it (`student_records.xlsx`, a PDF, anything). Files with an encrypted extension (`.gpg .pgp .enc .aes .7z .kdbx`) are treated as encrypted and are **not** flagged — copy a `.7z` to show the contrast.

Expected: `Unencrypted file transfer of 'student_records.xlsx' to KINGSTON (E:\) from <hostname> by <user>.`

Files that were already on the drive are ignored; only files added/changed after it was plugged in count.

### 2.5 Login outside business hours — `login_time` (MEDIUM)

Rule: `{"allowed_start": "07:00", "allowed_end": "20:00"}` — compared in the **server's local time**.

**Do this (daytime demo):** edit the rule so *now* is outside the window, e.g. `{"allowed_start": "08:00", "allowed_end": "08:01"}`, then **restart the agent**. On start-up the agent reports every interactive session once, so the flag appears immediately. Set the hours back afterwards.

If the demo genuinely runs after 20:00 you don't need to edit anything — starting the agent is enough.

Expected: `Login detected outside allowed hours (08:00–08:01). Event time: 14:32`

### 2.6 Brute force — `failed_logins` (CRITICAL)

Rule: `{"threshold": 5, "window_minutes": 10}` — flags **once per window** per user per endpoint.

Two real sources:

| Source | Do this |
|--------|---------|
| **Dashboard login page** (works everywhere, no agent needed) | Log out, type `admin` with a wrong password **5 times**. The portal records itself as endpoint `CBU-COMPLIANCE-PORTAL`. |
| **OS login** (via the agent) | macOS/Linux: run `sudo -k ls` and type a wrong password 3× — repeat until 5 failures. Windows (agent as Administrator): lock the PC (Win+L) and type a wrong password 5×. |

Expected: `User admin reached 5 failed logins within 10 minutes on CBU-COMPLIANCE-PORTAL (threshold 5).`

For a faster demo lower `threshold` to `3`.

---

## 3. Editing the rules

### In the dashboard (recommended during the demo)

**Policies → Manage** on a policy → **Edit** next to a rule. You can change name, type, severity, description and the JSON condition. A hint under the condition box explains the fields. **Disable / Enable** switches a rule off without deleting it. Changes take effect on the very next event — no restart needed.

Requires role Admin or Security Personnel (`admin` or `bwembya.rm`).

### Via the API

```bash
# PUT /policies/{policy_id}/rules/{rule_id}   (Bearer token required)
curl -X PUT http://localhost:8000/policies/2/rules/3 \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"condition": "{\"blocked_ports\": [23, 6881, 4444, 3389]}"}'
```

Invalid JSON in `condition` is rejected with `400`.

### In the seed script

[scripts/seed.py](scripts/seed.py) — the `policies_data` list defines the rules that `python scripts/seed.py` creates on a fresh database, and the `suspicious` / `violations_data` lists define the historical demo violations. Edit those and re-seed on an empty DB (`DROP DATABASE` + `CREATE DATABASE`, then run seed again). Seeding is idempotent for users and policies — existing ones are kept, so re-running on a populated DB only adds logs/violations.

### Condition reference

| rule_type | Fields | Event it inspects |
|-----------|--------|-------------------|
| `login_time` | `allowed_start`, `allowed_end` (`"HH:MM"`, local time) | `login` |
| `usb_device` | `allowed` (bool), `allowed_devices` (list of name fragments) | `usb_connected` |
| `network_access` | `blocked_ports` (ints), `blocked_ips` (prefix strings) | `network_connection` |
| `failed_logins` | `threshold`, `window_minutes` | `login_failed` |
| `process_execution` | `blocked_processes` (names, no path/.exe) | `process_started` |
| `data_transfer` | `require_encryption` (bool) | `file_transfer` |

---

## 4. Fallback: simulate an event

If a physical action is impractical on the demo machine (no USB stick, nmap not installed), the agent can send one synthetic event that still comes from the *real* hostname and user:

```bash
python scripts/agent.py --server http://<SERVER-IP>:8000 --simulate usb
python scripts/agent.py --server http://<SERVER-IP>:8000 --simulate failed_login --repeat 5
python scripts/agent.py --server http://<SERVER-IP>:8000 --simulate all
python scripts/agent.py --list-simulations
```

Options: `usb`, `file_transfer`, `process`, `network`, `login`, `failed_login`, `all`. Simulated events carry `"simulated": true` in their data so they are distinguishable in the Logs page.

---

## 5. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Agent prints `Cannot reach server` | Wrong `--server` IP, server not started, or Windows Firewall on the server (see README §4). |
| Action happened but no flag | Check the **Logs** page — is the event there? If the event exists but no violation, the rule doesn't match: compare the event's `event_data` to the rule condition. If the event is missing, the agent didn't see it (e.g. process lived < 1 s, or USB path not recognised). |
| Login flagged every time the agent starts | Expected if the server clock is outside `login_time` hours; widen the window or disable the rule. |
| `nc` / `nmap` flagged but not the connection | The connection lasted under 1 s. Use a listener (`nc -l 6881`) so the connection stays open. |
| Failed OS logins not detected on Windows | Run the agent as Administrator; only Security event 4625 is read. The dashboard login page still works. |
| Same violation repeating every 5 s | Only the old agent did this. Make sure the endpoint runs the current `scripts/agent.py`. |
