# Testing on Windows — Easy Guide

A copy‑paste walkthrough for triggering real violations and for editing / deleting
policies and rules, all on Windows. No Linux/Mac knowledge needed.

> You need three things running: the **API server**, the **Angular UI**, and the
> **agent**. They can all be on the same Windows laptop for a demo.

---

## Part A — Start everything (once)

Open **three** terminal windows. PowerShell or Command Prompt both work.

**Terminal 1 — API server**
```powershell
cd cybersec_compliance
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
First time only, in a spare terminal: `python scripts/seed.py`

**Terminal 2 — Angular UI**
```powershell
cd cybersec_compliance\cbu-compliance-frontend
npm start
```
Then open **http://localhost:4200** and log in as **admin / Admin@123**.

**Terminal 3 — the agent** (run this window **as Administrator** — see the tip)
```powershell
cd cybersec_compliance
pip install requests psutil
python scripts\agent.py --server http://localhost:8000
```

> **Run the agent terminal as Administrator** (right‑click PowerShell → *Run as
> administrator*). Without it, everything works **except** OS failed‑login
> detection (§B6). To do that: press Windows, type "PowerShell", right‑click →
> Run as administrator, then `cd` to the folder.

**Keep Terminal 3 visible next to the browser.** The moment the server flags
something, the agent prints a line like:
```
🚩 VIOLATION FLAGGED [process_started] Blocked process 'notepad' executed on DESKTOP-XXX.
```
In the browser, open the **Alerts** or **Violations** page. Both have a green
**Live** button and refresh every 5 seconds — new items flash red with a **NEW**
badge. You don't need to reload the page.

---

## Part B — Trigger each violation

The agent checks every second and sends every 5 seconds, so a flag shows up
about **5–7 seconds** after you do the action.

### B1. Blocked program (CRITICAL) — the easiest one

The rule blocks `nmap, wireshark, netcat, nc, mimikatz`. You probably don't have
those installed, so the simplest demo is to **add a program you already have**,
then open it.

1. In the UI: **Policies → Data Protection Policy → Manage → Edit** on
   **Blocked Process Execution**.
2. Change the condition to include Notepad:
   ```json
   {"blocked_processes": ["nmap", "wireshark", "netcat", "nc", "notepad"]}
   ```
   Click **Save Changes**.
3. Open **Notepad** (Windows → type "notepad").

Expected flag: `Blocked process 'notepad' executed on DESKTOP-XXX.`

> Names are matched without the path or `.exe`, so `notepad.exe` matches
> `notepad`. If you have Wireshark or Nmap installed, just open those instead —
> no rule edit needed.

### B2. Blocked network port (HIGH)

The rule blocks ports **23, 6881, 4444**. Easiest reliable trigger in PowerShell —
connect to a made‑up address on the LAN that doesn't answer, so the attempt
stays open long enough to be seen:

```powershell
Test-NetConnection 192.168.1.250 -Port 23
```
Use any IP on your network that isn't a real device (it will say "TcpTestSucceeded : False" after a few seconds — that's fine, the attempt is what gets flagged).

Expected flag: `Connection to blocked port 23 on 192.168.1.250 from DESKTOP-XXX ...`

> Want to block a real website for the demo instead? Edit the rule and add the
> site's IP start to `blocked_ips`, e.g.
> `{"blocked_ports": [23, 6881, 4444], "blocked_ips": ["142.250."]}`, then open
> that site in a browser.

### B3. USB flash drive (HIGH)

**Plug in any USB flash drive.** That's it.

Expected flag: `Unauthorised USB/removable device 'KINGSTON (E:\)' connected ...`

> To allow a specific drive: edit the **Unauthorised USB Device** rule to
> `{"allowed": false, "allowed_devices": ["KINGSTON"]}`, unplug and re‑plug — no
> flag.

### B4. Copying a file to USB (HIGH)

With the flash drive still plugged in, **copy any file onto it** (drag a file
onto the E:\ drive, or `Copy-Item report.pdf E:\`).

Expected flag: `Unencrypted file transfer of 'report.pdf' to KINGSTON (E:\) ...`

> Files already on the drive are ignored — only files you add after plugging in
> count. Files with an encrypted extension (`.gpg .pgp .enc .aes .7z .kdbx`) are
> treated as encrypted and are **not** flagged — copy one of those to show the
> contrast with a plain file.

### B5. Login outside business hours (MEDIUM)

The rule allows logins **07:00–20:00**. To demo during the day, make "now"
outside the window:

1. UI: **Policies → Acceptable Use Policy → Manage → Edit** on
   **Login Outside Business Hours**.
2. Set a tiny window that excludes now, e.g. `{"allowed_start": "08:00", "allowed_end": "08:01"}`. Save.
3. In Terminal 3, stop the agent (**Ctrl+C**) and start it again
   (`python scripts\agent.py --server http://localhost:8000`).

On start‑up the agent reports your current login once, so the flag appears
right away. **Set the hours back to 07:00–20:00 afterward.**

### B6. Brute‑force / repeated failed logins (CRITICAL)

Two ways — the first needs **no agent** and always works:

**Way 1 — the dashboard login page (recommended)**
1. Log out.
2. Type username **admin** with a **wrong password 5 times**.
3. Log in properly and check Alerts.

Expected flag: `User admin reached 5 failed logins within 10 minutes on CBU-COMPLIANCE-PORTAL (threshold 5).`

**Way 2 — Windows sign‑in (agent must be Administrator)**
Lock the PC (**Win+L**) and type a wrong password 5 times, then sign in. The
agent reads Windows Security event 4625.

> Faster demo: lower `threshold` to `3` on the **Excessive Failed Logins** rule.

---

## Part C — Edit, disable and delete rules

Everything is in **Policies → (pick a policy) → Manage**. You must be logged in
as **admin** or a Security user (`bwembya.rm`).

| Action | How |
|--------|-----|
| **Edit a rule** | Click **Edit** on the rule. Change the name, severity, description or the JSON condition, then **Save Changes**. A hint under the condition box explains each field. Takes effect on the very next event — no restart. |
| **Turn a rule off** | Click **Disable** (click **Enable** to turn it back on). The rule stays but stops flagging. |
| **Delete a rule** | Click **Delete** and confirm. It disappears from the policy. |
| **Add a rule** | Click **+ Add Rule**, pick a type (the condition auto‑fills a template), adjust it, **Add Rule**. |

Bad JSON in a condition is rejected with a red message, so you can't save a
broken rule.

---

## Part D — Edit and delete policies

Also under **Policies → (pick a policy) → Manage**:

| Action | How |
|--------|-----|
| **Create a policy** | On the Policies page, click **+ New Policy**, fill in name / description / version, **Create**. Then open it and add rules. |
| **Edit a policy** | In the Manage window, click **Edit Policy** (top right). Change the name, description or version and **Save Details**. |
| **Delete a policy** | In the Manage window, click **Deactivate Policy** and confirm. It's removed from the list and its rules stop flagging. |

---

## Part E — If something doesn't flag

| What you see | Fix |
|--------------|-----|
| Agent says `Cannot reach server` | Server not started, or wrong `--server` address. On another PC use the server's IP and open port 8000 in Windows Firewall (README §4). |
| Did the action, no flag | Open the **Logs** page. Is your event listed? If **yes** but no violation, the rule doesn't match — compare the event to the rule's condition. If **no**, the agent didn't see it (program closed in under a second, or the port connection was too brief — keep it open a few seconds). |
| Login flagged every time the agent starts | Expected if the clock is outside the `login_time` hours. Widen the window or disable that rule. |
| Failed Windows logins not detected | The agent terminal must be **Administrator**. The dashboard login page (§B6 Way 1) works without it. |
| Nothing happens on the page | Make sure the green **Live** button is on, or click **↻ Refresh**. |

---

## Part F — Can't do the physical action? Simulate it

If you have no USB stick or can't install a program, the agent can send one
real‑looking event from your actual PC and exit:

```powershell
python scripts\agent.py --server http://localhost:8000 --simulate usb
python scripts\agent.py --server http://localhost:8000 --simulate process
python scripts\agent.py --server http://localhost:8000 --simulate network
python scripts\agent.py --server http://localhost:8000 --simulate failed_login --repeat 5
python scripts\agent.py --server http://localhost:8000 --simulate all
python scripts\agent.py --list-simulations
```

These are for when a real action isn't practical — everything in Part B is the
real thing and is what you'd show in the demo.
