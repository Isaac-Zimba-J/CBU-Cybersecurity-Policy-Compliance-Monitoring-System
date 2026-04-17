"""
Seed script — run this ONCE after starting the server to populate demo data.
Usage: python scripts/seed.py
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta
import random
from app.core.database import SessionLocal, engine
from app.core.database import Base
from app.core.security import hash_password
from app.models.user import (
    User, Policy, ComplianceRule, ActivityLog, Violation, Alert, Report,
    UserRole, SeverityLevel, ViolationStatus
)

Base.metadata.create_all(bind=engine)
db = SessionLocal()

print("🌱 Seeding database...")

# ── Users ─────────────────────────────────────────────────────────────────────
print("  Creating users...")
users_data = [
    {"username": "admin",       "email": "admin@cbu.ac.zm",       "full_name": "System Administrator",   "password": "Admin@123",    "role": UserRole.ADMIN},
    {"username": "daka.lz",     "email": "daka@cbu.ac.zm",        "full_name": "Mrs Daka L.Z.",           "password": "Daka@123",     "role": UserRole.SECURITY_PERSONNEL},
    {"username": "bwembya.rm",  "email": "bwembya@cbu.ac.zm",     "full_name": "Bwembya Ruth Mwila",      "password": "Bwembya@123",  "role": UserRole.SECURITY_PERSONNEL},
    {"username": "viewer1",     "email": "viewer1@cbu.ac.zm",     "full_name": "IT Viewer",               "password": "Viewer@123",   "role": UserRole.VIEWER},
]
created_users = {}
for u in users_data:
    existing = db.query(User).filter(User.username == u["username"]).first()
    if not existing:
        user = User(
            username=u["username"], email=u["email"], full_name=u["full_name"],
            hashed_password=hash_password(u["password"]), role=u["role"]
        )
        db.add(user)
        db.flush()
        created_users[u["username"]] = user
    else:
        created_users[u["username"]] = existing
db.commit()

admin = created_users["admin"]
security_user = created_users["bwembya.rm"]

# ── Policies ──────────────────────────────────────────────────────────────────
print("  Creating policies and rules...")
policies_data = [
    {
        "name": "Acceptable Use Policy",
        "description": "Governs acceptable use of CBU ICT resources including login hours and device usage.",
        "version": "2.1",
        "rules": [
            {
                "name": "Login Outside Business Hours",
                "rule_type": "login_time",
                "description": "Users must not log in outside of 07:00–20:00 unless authorised.",
                "condition": json.dumps({"allowed_start": "07:00", "allowed_end": "20:00"}),
                "severity": SeverityLevel.MEDIUM,
            },
            {
                "name": "Unauthorised USB Device",
                "rule_type": "usb_device",
                "description": "Removable media is not permitted without prior authorisation.",
                "condition": json.dumps({"allowed": False}),
                "severity": SeverityLevel.HIGH,
            },
        ]
    },
    {
        "name": "Network Security Policy",
        "description": "Controls network access and monitors for suspicious connection attempts.",
        "version": "1.3",
        "rules": [
            {
                "name": "Blocked Port Access",
                "rule_type": "network_access",
                "description": "Access to ports 23 (Telnet), 6881 (BitTorrent) is prohibited.",
                "condition": json.dumps({"blocked_ports": [23, 6881, 4444], "blocked_ips": ["10.0.0.99"]}),
                "severity": SeverityLevel.HIGH,
            },
            {
                "name": "Excessive Failed Logins",
                "rule_type": "failed_logins",
                "description": "More than 5 failed logins in 10 minutes indicates a brute force attempt.",
                "condition": json.dumps({"threshold": 5, "window_minutes": 10}),
                "severity": SeverityLevel.CRITICAL,
            },
        ]
    },
    {
        "name": "Data Protection Policy",
        "description": "Ensures data is handled and transferred securely.",
        "version": "1.0",
        "rules": [
            {
                "name": "Unencrypted File Transfer",
                "rule_type": "data_transfer",
                "description": "All file transfers must be encrypted.",
                "condition": json.dumps({"require_encryption": True}),
                "severity": SeverityLevel.HIGH,
            },
            {
                "name": "Blocked Process Execution",
                "rule_type": "process_execution",
                "description": "Execution of unauthorised tools is prohibited.",
                "condition": json.dumps({"blocked_processes": ["nmap", "wireshark", "netcat", "nc", "mimikatz"]}),
                "severity": SeverityLevel.CRITICAL,
            },
        ]
    },
]

all_policies = []
for p_data in policies_data:
    existing = db.query(Policy).filter(Policy.name == p_data["name"]).first()
    if not existing:
        policy = Policy(name=p_data["name"], description=p_data["description"],
                        version=p_data["version"], created_by=admin.id)
        db.add(policy)
        db.flush()
        for r in p_data["rules"]:
            rule = ComplianceRule(policy_id=policy.id, **r)
            db.add(rule)
        all_policies.append(policy)
    else:
        all_policies.append(existing)
db.commit()

# ── Activity Logs + Violations ────────────────────────────────────────────────
print("  Generating activity logs and violations...")

endpoints = [
    {"id": "DICT-PC-001", "ip": "192.168.1.101"},
    {"id": "DICT-PC-002", "ip": "192.168.1.102"},
    {"id": "DICT-LAPTOP-003", "ip": "192.168.1.103"},
    {"id": "STAFF-PC-007", "ip": "192.168.1.107"},
    {"id": "LIBRARY-PC-012", "ip": "192.168.1.112"},
]
usernames = ["jmwale", "nkayumba", "cmutale", "pchanda", "amwansa", "bwembya.rm"]
event_types = ["login", "logout", "file_access", "network_connection", "login_failed"]

now = datetime.utcnow()
logs_created = []

# Normal activity logs (past 7 days)
for i in range(120):
    ep = random.choice(endpoints)
    hours_ago = random.randint(1, 168)
    log = ActivityLog(
        endpoint_id=ep["id"], endpoint_ip=ep["ip"],
        username=random.choice(usernames),
        event_type=random.choice(event_types),
        event_data=json.dumps({"detail": "normal_activity"}),
        timestamp=now - timedelta(hours=hours_ago),
        processed=True,
    )
    db.add(log)
    logs_created.append(log)

# Suspicious logs that trigger violations
suspicious = [
    {"event_type": "login",             "event_data": json.dumps({}),                                            "hours_ago": 3,   "ep": endpoints[0]},
    {"event_type": "usb_connected",     "event_data": json.dumps({"device": "SanDisk USB 32GB"}),               "hours_ago": 6,   "ep": endpoints[1]},
    {"event_type": "network_connection","event_data": json.dumps({"dest_port": 23, "dest_ip": "172.16.0.5"}),   "hours_ago": 12,  "ep": endpoints[2]},
    {"event_type": "file_transfer",     "event_data": json.dumps({"filename": "student_records.xlsx", "encrypted": False}), "hours_ago": 18, "ep": endpoints[3]},
    {"event_type": "process_started",   "event_data": json.dumps({"process_name": "nmap"}),                     "hours_ago": 24,  "ep": endpoints[0]},
    {"event_type": "usb_connected",     "event_data": json.dumps({"device": "Kingston USB 16GB"}),              "hours_ago": 36,  "ep": endpoints[4]},
    {"event_type": "network_connection","event_data": json.dumps({"dest_port": 6881, "dest_ip": "45.33.32.156"}),"hours_ago": 48, "ep": endpoints[1]},
    {"event_type": "process_started",   "event_data": json.dumps({"process_name": "wireshark"}),                "hours_ago": 60,  "ep": endpoints[2]},
    {"event_type": "file_transfer",     "event_data": json.dumps({"filename": "payroll_2024.xlsx", "encrypted": False}), "hours_ago": 72, "ep": endpoints[3]},
    {"event_type": "login",             "event_data": json.dumps({}),                                            "hours_ago": 2,   "ep": endpoints[4]},
]

rules = db.query(ComplianceRule).all()
rule_map = {r.rule_type: r for r in rules}

violations_data = [
    {"rule_type": "login_time",       "idx": 0,  "severity": SeverityLevel.MEDIUM,   "desc": "Login at 02:30 — outside allowed hours (07:00–20:00)"},
    {"rule_type": "usb_device",       "idx": 1,  "severity": SeverityLevel.HIGH,     "desc": "Unauthorised USB device 'SanDisk USB 32GB' connected"},
    {"rule_type": "network_access",   "idx": 2,  "severity": SeverityLevel.HIGH,     "desc": "Connection to blocked Telnet port 23 detected"},
    {"rule_type": "data_transfer",    "idx": 3,  "severity": SeverityLevel.HIGH,     "desc": "Unencrypted transfer of 'student_records.xlsx'"},
    {"rule_type": "process_execution","idx": 4,  "severity": SeverityLevel.CRITICAL, "desc": "Blocked process 'nmap' executed on DICT-PC-001"},
    {"rule_type": "usb_device",       "idx": 5,  "severity": SeverityLevel.HIGH,     "desc": "Unauthorised USB device 'Kingston USB 16GB' connected"},
    {"rule_type": "network_access",   "idx": 6,  "severity": SeverityLevel.HIGH,     "desc": "Connection to BitTorrent port 6881 detected"},
    {"rule_type": "process_execution","idx": 7,  "severity": SeverityLevel.CRITICAL, "desc": "Blocked process 'wireshark' executed"},
    {"rule_type": "data_transfer",    "idx": 8,  "severity": SeverityLevel.HIGH,     "desc": "Unencrypted transfer of 'payroll_2024.xlsx'"},
    {"rule_type": "login_time",       "idx": 9,  "severity": SeverityLevel.MEDIUM,   "desc": "Login at 01:15 — outside allowed hours (07:00–20:00)"},
]

statuses = [
    ViolationStatus.RESOLVED, ViolationStatus.UNDER_INVESTIGATION, ViolationStatus.PENDING_REVIEW,
    ViolationStatus.RESOLVED, ViolationStatus.ESCALATED, ViolationStatus.DETECTED,
    ViolationStatus.RESOLVED, ViolationStatus.PENDING_REVIEW, ViolationStatus.DETECTED, ViolationStatus.DETECTED,
]

for i, s_log in enumerate(suspicious):
    log = ActivityLog(
        endpoint_id=s_log["ep"]["id"], endpoint_ip=s_log["ep"]["ip"],
        username=random.choice(usernames),
        event_type=s_log["event_type"], event_data=s_log["event_data"],
        timestamp=now - timedelta(hours=s_log["hours_ago"]),
        processed=True,
    )
    db.add(log)
    db.flush()
    logs_created.append(log)

    vd = violations_data[i]
    rule = rule_map.get(vd["rule_type"])
    status = statuses[i]
    violation = Violation(
        rule_id=rule.id if rule else None,
        activity_log_id=log.id,
        endpoint_id=log.endpoint_id,
        username=log.username,
        description=vd["desc"],
        severity=vd["severity"],
        status=status,
        assigned_to=security_user.id if status in (ViolationStatus.UNDER_INVESTIGATION, ViolationStatus.ESCALATED) else None,
        resolved_at=now - timedelta(hours=1) if status == ViolationStatus.RESOLVED else None,
    )
    db.add(violation)
    db.flush()

    alert = Alert(
        violation_id=violation.id,
        title=f"[{vd['severity'].value.upper()}] {rule.name if rule else 'Policy Violation'}",
        message=f"Endpoint: {log.endpoint_id} | {vd['desc']}",
        severity=vd["severity"],
        is_read=(status == ViolationStatus.RESOLVED),
    )
    db.add(alert)

db.commit()

# ── Sample Report ─────────────────────────────────────────────────────────────
print("  Creating sample report...")
from app.routers.reports import build_report_content
period_start = now - timedelta(days=7)
content = build_report_content(db, period_start, now)
report = Report(
    title=f"Weekly Compliance Report — {now.strftime('%Y-%m-%d')}",
    report_type="weekly",
    generated_by=admin.id,
    content=json.dumps(content),
    period_start=period_start,
    period_end=now,
)
db.add(report)
db.commit()

print("\n✅ Seeding complete!\n")
print("=" * 50)
print("  Demo Accounts")
print("=" * 50)
print("  Admin:    admin        / Admin@123")
print("  Security: bwembya.rm   / Bwembya@123")
print("  Security: daka.lz      / Daka@123")
print("  Viewer:   viewer1      / Viewer@123")
print("=" * 50)
print(f"\n  {len(logs_created)} activity logs created")
print(f"  {len(violations_data)} violations created")
print(f"  {len(policies_data)} policies with rules created")
print("\n  API docs: http://localhost:8000/docs\n")
db.close()
