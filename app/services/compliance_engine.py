import json
import os
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from app.models.user import ActivityLog, ComplianceRule, Violation, Alert, SeverityLevel, ViolationStatus


def record_event(
    db: Session,
    endpoint_id: str,
    username: str,
    event_type: str,
    event_data: Optional[dict] = None,
    endpoint_ip: Optional[str] = None,
    timestamp: Optional[datetime] = None,
) -> tuple[ActivityLog, list[Violation]]:
    """
    Store an activity log and evaluate it immediately.
    Used by the agent ingest endpoints and by server-side events
    (e.g. failed dashboard logins). Caller must commit.
    """
    log = ActivityLog(
        endpoint_id=endpoint_id,
        endpoint_ip=endpoint_ip,
        username=username,
        event_type=event_type,
        event_data=json.dumps(event_data) if isinstance(event_data, dict) else event_data,
        timestamp=timestamp or datetime.now().astimezone(),
    )
    db.add(log)
    db.flush()
    violations = evaluate_log(db, log)
    log.processed = True
    return log, violations


def evaluate_log(db: Session, log: ActivityLog) -> list[Violation]:
    """
    Evaluate an activity log against all active compliance rules.
    Returns list of violations created.
    """
    rules = db.query(ComplianceRule).filter(ComplianceRule.is_active == True).all()
    violations_created = []

    for rule in rules:
        try:
            violated, description = check_rule(rule, log, db)
            if violated:
                violation = Violation(
                    rule_id=rule.id,
                    activity_log_id=log.id,
                    endpoint_id=log.endpoint_id,
                    username=log.username,
                    description=description,
                    severity=rule.severity,
                    status=ViolationStatus.DETECTED,
                )
                db.add(violation)
                db.flush()  # get violation.id before commit

                alert = Alert(
                    violation_id=violation.id,
                    title=f"[{rule.severity.upper()}] Policy Violation: {rule.name}",
                    message=f"Endpoint: {log.endpoint_id} | User: {log.username} | {description}",
                    severity=rule.severity,
                )
                db.add(alert)
                violations_created.append(violation)
        except Exception:
            continue  # don't crash on a bad rule

    return violations_created


def _event(log: ActivityLog) -> Optional[dict]:
    try:
        return json.loads(log.event_data or "{}")
    except json.JSONDecodeError:
        return None


def _local_time(ts: datetime) -> datetime:
    """Rules are written in wall-clock time, so compare in the server's local timezone."""
    if ts.tzinfo is not None:
        return ts.astimezone()
    return ts


def normalize_process_name(name: str) -> str:
    """'C:\\Tools\\Nmap.EXE' -> 'nmap' so rule lists don't need per-OS variants."""
    base = os.path.basename((name or "").strip().replace("\\", "/")).lower()
    for ext in (".exe", ".app", ".bat", ".cmd", ".com"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    return base


def check_rule(rule: ComplianceRule, log: ActivityLog, db: Optional[Session] = None) -> tuple[bool, str]:
    """
    Evaluate a single rule against an activity log.
    Returns (violated: bool, description: str)
    """
    try:
        condition = json.loads(rule.condition)
    except (json.JSONDecodeError, TypeError):
        return False, ""

    rule_type = rule.rule_type.lower()
    event_type = log.event_type.lower()

    # ── Login outside allowed hours ──────────────────────────────────────────
    if rule_type == "login_time":
        if event_type not in ("login", "ssh_login", "rdp_login"):
            return False, ""
        allowed_start = condition.get("allowed_start", "07:00")
        allowed_end = condition.get("allowed_end", "20:00")
        local = _local_time(log.timestamp)
        log_minutes = local.hour * 60 + local.minute
        start_h, start_m = map(int, allowed_start.split(":"))
        end_h, end_m = map(int, allowed_end.split(":"))
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m
        if not (start_minutes <= log_minutes <= end_minutes):
            return True, (
                f"Login detected outside allowed hours ({allowed_start}–{allowed_end}). "
                f"Event time: {local.strftime('%H:%M')}"
            )

    # ── Unauthorised USB / removable device ──────────────────────────────────
    elif rule_type == "usb_device":
        if event_type not in ("usb_connected", "removable_media"):
            return False, ""
        if condition.get("allowed", False):
            return False, ""
        event = _event(log) or {}
        device = str(event.get("device", "")).strip()
        # Optional whitelist: {"allowed": false, "allowed_devices": ["Kingston DataTraveler"]}
        for allowed_name in condition.get("allowed_devices", []):
            if allowed_name and allowed_name.lower() in device.lower():
                return False, ""
        label = f" '{device}'" if device else ""
        return True, f"Unauthorised USB/removable device{label} connected on endpoint {log.endpoint_id}."

    # ── Blocked network destination ──────────────────────────────────────────
    elif rule_type == "network_access":
        if event_type != "network_connection":
            return False, ""
        event = _event(log)
        if event is None:
            return False, ""
        blocked_ports = condition.get("blocked_ports", [])
        blocked_ips = condition.get("blocked_ips", [])
        dest_port = event.get("dest_port")
        dest_ip = str(event.get("dest_ip", ""))
        proc = event.get("process_name")
        via = f" (process: {proc})" if proc else ""
        if dest_port and dest_port in blocked_ports:
            return True, f"Connection to blocked port {dest_port} on {dest_ip} from {log.endpoint_id}{via}."
        for blocked in blocked_ips:
            if blocked and dest_ip.startswith(str(blocked)):
                return True, f"Connection to blocked IP {dest_ip}:{dest_port} from {log.endpoint_id}{via}."

    # ── Failed login threshold ────────────────────────────────────────────────
    elif rule_type == "failed_logins":
        if event_type != "login_failed":
            return False, ""
        threshold = condition.get("threshold", 5)
        window_minutes = condition.get("window_minutes", 10)
        cutoff = log.timestamp - timedelta(minutes=window_minutes)
        if db is None:
            from app.core.database import SessionLocal
            db = SessionLocal()
        # The current log is already flushed, so it is included in the count.
        window_logs = db.query(ActivityLog.id).filter(
            ActivityLog.username == log.username,
            ActivityLog.endpoint_id == log.endpoint_id,
            ActivityLog.event_type == "login_failed",
            ActivityLog.timestamp >= cutoff,
        )
        count = window_logs.count()
        # Flag once per window: skip if one of this user's failed logins in the
        # window has already produced a violation for this rule.
        already_flagged = db.query(Violation.id).filter(
            Violation.rule_id == rule.id,
            Violation.activity_log_id.in_(window_logs.subquery().select()),
        ).first()
        if count >= threshold and not already_flagged:
            return True, (
                f"User {log.username} reached {count} failed logins "
                f"within {window_minutes} minutes on {log.endpoint_id} (threshold {threshold})."
            )

    # ── Unauthorised software / process ──────────────────────────────────────
    elif rule_type == "process_execution":
        if event_type not in ("process_started", "application_launch"):
            return False, ""
        event = _event(log)
        if event is None:
            return False, ""
        blocked = {normalize_process_name(p) for p in condition.get("blocked_processes", [])}
        process_name = normalize_process_name(event.get("process_name", ""))
        if process_name and process_name in blocked:
            return True, f"Blocked process '{process_name}' executed on {log.endpoint_id}."

    # ── Unencrypted data transfer ─────────────────────────────────────────────
    elif rule_type == "data_transfer":
        if event_type != "file_transfer":
            return False, ""
        event = _event(log)
        if event is None:
            return False, ""
        require_encryption = condition.get("require_encryption", True)
        encrypted = event.get("encrypted", False)
        if require_encryption and not encrypted:
            filename = event.get("filename")
            dest = event.get("destination")
            what = f" of '{filename}'" if filename else ""
            where = f" to {dest}" if dest else ""
            return True, f"Unencrypted file transfer{what}{where} from {log.endpoint_id} by {log.username}."

    return False, ""
