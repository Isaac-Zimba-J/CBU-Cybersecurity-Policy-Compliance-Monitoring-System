# CBU Cybersecurity Policy Compliance Monitoring System
### Backend API — Phase 1

---

## Prerequisites

Install these on the server laptop before starting:

| Tool | Where needed | Download |
| ---- | ------------ | -------- |
| Python 3.10+ | Backend server | [python.org](https://python.org) |
| PostgreSQL 15+ | Backend server | [postgresql.org](https://postgresql.org) |
| Node.js 20+ & npm | Angular UI | [nodejs.org](https://nodejs.org) |
| Git (optional) | All machines | [git-scm.com](https://git-scm.com) |

---

## Setup (Run Once)

> **Running on Windows?** Follow the Windows-specific commands below. Mac/Linux commands are shown alongside for reference.

### 1. Install Python dependencies

**Windows (Command Prompt or PowerShell):**
```cmd
cd cybersec_compliance
pip install -r requirements.txt
```

**Mac/Linux:**
```bash
cd cybersec_compliance
pip install -r requirements.txt
```

### 2. Create the PostgreSQL database
Open pgAdmin or run in a terminal:
```sql
CREATE DATABASE cybersec_compliance;
CREATE USER cbu_admin WITH PASSWORD 'yourpassword';
GRANT ALL PRIVILEGES ON DATABASE cybersec_compliance TO cbu_admin;
```

### 3. Configure environment

**Windows (Command Prompt):**
```cmd
copy .env.example .env
```

**Windows (PowerShell):**

```powershell
Copy-Item .env.example .env
```

**Mac/Linux:**
```bash
cp .env.example .env
```

Then open `.env` in any text editor (Notepad on Windows is fine) and set:

```env
DATABASE_URL=postgresql://cbu_admin:your_password@localhost:5432/cybersec_compliance
SECRET_KEY=any-long-random-string-at-least-32-chars
```

### 4. Open port 8000 on Windows Firewall

Windows blocks incoming connections by default. Run this **once** in PowerShell as Administrator to allow other machines to reach the server:

```powershell
New-NetFirewallRule -DisplayName "CBU Compliance API" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
```

Or manually: **Windows Defender Firewall → Advanced Settings → Inbound Rules → New Rule → Port → TCP 8000 → Allow**.

### 5. Find your machine's local IP address

**Windows:**
```cmd
ipconfig
```
Look for **IPv4 Address** under your active network adapter, e.g. `192.168.1.5`.

**Mac/Linux:**

```bash
ip addr   # or: ifconfig
```

> Note this IP — every other machine on the network will use it to reach this server.

### 6. Start the server

**Windows (Command Prompt or PowerShell):**
```cmd
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Mac/Linux:**
```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

`--host 0.0.0.0` binds to all network interfaces so other computers on the same WiFi/LAN can connect.

You should see output like:

```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

### 7. Seed demo data (first time only)
Open a **second** terminal window in the same folder and run:

**Windows:**

```cmd
python scripts/seed.py
```

**Mac/Linux:**
```bash
python3 scripts/seed.py
```

This creates demo users, policies, violations, and activity logs.

---

## Demo Accounts

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `Admin@123` |
| Security Personnel | `bwembya.rm` | `Bwembya@123` |
| Security Personnel | `daka.lz` | `Daka@123` |
| Viewer | `viewer1` | `Viewer@123` |

---

## Accessing the API

### From the server machine
- API docs (Swagger): http://localhost:8000/docs
- Health check:       http://localhost:8000/health

### From other machines on the same network
Find your server's local IP address:
- **Windows:** Open CMD → type `ipconfig` → look for "IPv4 Address" (e.g. 192.168.1.5)
- **Linux/Mac:** Open Terminal → type `ip addr` or `ifconfig`

Then on other machines visit:
- http://192.168.1.5:8000/docs  ← replace with your actual IP

---

## Running the Monitoring Agent (on demo endpoint machines)

Copy `scripts/agent.py` to each demo machine, then run:
```bash
# Install agent dependencies
pip install requests psutil

# Run the agent, pointing to the server IP
python agent.py --server http://192.168.1.5:8000
```

The agent will start collecting activity and sending it to the server every 10 seconds.

---

## Angular UI Setup

The frontend lives in the `cbu-compliance-frontend/` folder. Run it on any machine that has Node.js 20+ installed — it does not have to be the same machine as the backend.

### 1. Install dependencies (run once)

```cmd
cd cbu-compliance-frontend
npm install
```

### 2. Point the UI at the backend

Open `cbu-compliance-frontend/src/environments/environment.ts` in any text editor and update the `apiUrl` to match the server's IP:

```ts
export const environment = {
  production: false,
  apiUrl: 'http://192.168.1.5:8000'   // ← replace with your server IP
};
```

> If you are running the UI **on the same machine** as the backend, leave it as `http://localhost:8000`.

### 3. Start the UI dev server

**To access from the same machine only:**

```cmd
npm start
```

**To allow other machines on the network to open the UI too:**

```cmd
npx ng serve --host 0.0.0.0 --port 4200
```

Then open **Windows Firewall** and allow port `4200` inbound (same steps as port 8000 above), or run in PowerShell as Administrator:

```powershell
New-NetFirewallRule -DisplayName "CBU Compliance UI" -Direction Inbound -Protocol TCP -LocalPort 4200 -Action Allow
```

### 4. Open the UI

| From | URL |
| ---- | --- |
| Same machine | `http://localhost:4200` |
| Other machines on network | `http://192.168.1.5:4200` ← replace with UI machine IP |

Log in with any of the demo accounts listed above.

---

## API Endpoints Summary

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Login (returns JWT token) |
| POST | `/auth/register` | Register new user |
| GET  | `/auth/me` | Get current user info |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard/stats` | Summary stats for dashboard |

### Policies
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/policies/` | List all policies |
| POST   | `/policies/` | Create a policy |
| PUT    | `/policies/{id}` | Update a policy |
| POST   | `/policies/{id}/rules` | Add a rule to a policy |

### Activity Logss
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/logs/ingest` | Agent posts a single log |
| POST | `/logs/ingest/batch` | Agent posts multiple logs |
| GET  | `/logs/` | View activity logs |
| GET  | `/logs/endpoints` | List all monitored endpoints |

### Violations
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/violations/` | List violations (filterable) |
| PUT | `/violations/{id}` | Update status / assign investigator |
| GET | `/violations/stats/summary` | Violation statistics |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/alerts/` | List alerts |
| PUT | `/alerts/{id}/read` | Mark alert as read |
| PUT | `/alerts/read-all` | Mark all read |
| GET | `/alerts/count` | Unread alert count |

### Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/reports/generate` | Generate a compliance report |
| GET  | `/reports/` | List all reports |
| GET  | `/reports/{id}` | Get a specific report |

---

## Project Structure

```
cybersec_compliance/
├── app/
│   ├── main.py                  ← FastAPI app entry point
│   ├── core/
│   │   ├── config.py            ← Settings / env vars
│   │   ├── database.py          ← SQLAlchemy setup
│   │   └── security.py          ← JWT auth, password hashing
│   ├── models/
│   │   └── user.py              ← All database models
│   ├── schemas/
│   │   └── schemas.py           ← Pydantic request/response schemas
│   ├── routers/
│   │   ├── auth.py              ← Login / register
│   │   ├── users.py             ← User management
│   │   ├── policies.py          ← Policy & rule CRUD
│   │   ├── logs.py              ← Activity log ingestion
│   │   ├── violations.py        ← Violation management
│   │   ├── alerts.py            ← Alert management
│   │   ├── reports.py           ← Report generation
│   │   └── dashboard.py         ← Dashboard statistics
│   └── services/
│       └── compliance_engine.py ← Core rule evaluation logic
├── scripts/
│   ├── seed.py                  ← Demo data seeder
│   └── agent.py                 ← Endpoint monitoring agent
├── requirements.txt
└── .env.example
```

---

## Next Steps
- **Phase 1:** Build the API Backend engine annd ENdpoits
- **Phase 2:** Angular frontend dashboard
- **Phase 3:** Enhanced agent (Windows event log support, scheduled reports)
