# CBU Cybersecurity Policy Compliance Monitoring System
### Backend API — Phase 1

---

## Prerequisites

Install these on the server laptop before starting:

| Tool | Download |
|------|----------|
| Python 3.10+ | https://python.org |
| PostgreSQL 15+ | https://postgresql.org |
| Git (optional) | https://git-scm.com |

---

## Setup (Run Once)

### 1. Install Python dependencies
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
```bash
# Copy the example env file
cp .env.example .env

# Edit .env and set your database password and a secret key
# DATABASE_URL=postgresql://cbu_admin:your_password@localhost:5432/cybersec_compliance
# SECRET_KEY=any-long-random-string-at-least-32-chars
```

### 4. Start the server
```bash
# From inside the cybersec_compliance folder:
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The `--host 0.0.0.0` makes it accessible to other computers on the same WiFi/router.

### 5. Seed demo data (first time only)
In a second terminal:
```bash
python scripts/seed.py
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

### Activity Logs
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
