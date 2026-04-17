import json
from datetime import datetime, time
from typing import Optional
from sqlalchemy.orm import Session
from app.models.user import ActivityLog, ComplianceRule, Violation, Alert, SeverityLevel, ViolationStatus


def evaluate_log(db: Session, log: ActivityLog) -> list[Violation]:
    """
    Evaluate an activity log against all active compliance rules.
    Returns list of violations created.
    """
    rules = db.query(ComplianceRule).filter(ComplianceRule.is_active == True).all()
    violations_created = []

    for rule in rules:
        try:
            violated, description = check_rule(rule, log)
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


def check_rule(rule: ComplianceRule, log: ActivityLog) -> tuple[bool, str]:
    """
    Evaluate a single rule against an activity log.
    Returns (violated: bool, description: str)
    """
    try:
        condition = json.loads(rule.condition)
    except (json.JSONDecodeError, TypeError):
        return False, ""

    rule_type = rule.rule_type.lower()

    # ── Login outside allowed hours ──────────────────────────────────────────
    if rule_type == "login_time":
        if log.event_type.lower() not in ("login", "ssh_login", "rdp_login"):
            return False, ""
        allowed_start = condition.get("allowed_start", "07:00")
        allowed_end = condition.get("allowed_end", "20:00")
        log_hour, log_min = log.timestamp.hour, log.timestamp.minute
        start_h, start_m = map(int, allowed_start.split(":"))
        end_h, end_m = map(int, allowed_end.split(":"))
        log_minutes = log_hour * 60 + log_min
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m
        if not (start_minutes <= log_minutes <= end_minutes):
            return True, (
                f"Login detected outside allowed hours ({allowed_start}–{allowed_end}). "
                f"Event time: {log.timestamp.strftime('%H:%M')}"
            )

    # ── Unauthorised USB / removable device ──────────────────────────────────
    elif rule_type == "usb_device":
        if log.event_type.lower() not in ("usb_connected", "removable_media"):
            return False, ""
        allowed = condition.get("allowed", False)
        if not allowed:
            return True, f"Unauthorised USB/removable device connected on endpoint {log.endpoint_id}."

    # ── Blocked network destination ──────────────────────────────────────────
    elif rule_type == "network_access":
        if log.event_type.lower() != "network_connection":
            return False, ""
        try:
            event = json.loads(log.event_data or "{}")
        except json.JSONDecodeError:
            return False, ""
        blocked_ports = condition.get("blocked_ports", [])
        blocked_ips = condition.get("blocked_ips", [])
        dest_port = event.get("dest_port")
        dest_ip = event.get("dest_ip", "")
        if dest_port and dest_port in blocked_ports:
            return True, f"Connection to blocked port {dest_port} from {log.endpoint_id}."
        for blocked in blocked_ips:
            if dest_ip.startswith(blocked):
                return True, f"Connection to blocked IP {dest_ip} from {log.endpoint_id}."

    # ── Failed login threshold ────────────────────────────────────────────────
    elif rule_type == "failed_logins":
        if log.event_type.lower() != "login_failed":
            return False, ""
        threshold = condition.get("threshold", 5)
        window_minutes = condition.get("window_minutes", 10)
        from sqlalchemy import func
        cutoff = datetime.utcnow().replace(tzinfo=log.timestamp.tzinfo)
        from datetime import timedelta
        cutoff = log.timestamp - timedelta(minutes=window_minutes)
        from app.core.database import SessionLocal
        count = SessionLocal().query(ActivityLog).filter(
            ActivityLog.username == log.username,
            ActivityLog.event_type == "login_failed",
            ActivityLog.timestamp >= cutoff,
        ).count()
        if count >= threshold:
            return True, (
                f"User {log.username} exceeded {threshold} failed logins "
                f"within {window_minutes} minutes."
            )

    # ── Unauthorised software / process ──────────────────────────────────────
    elif rule_type == "process_execution":
        if log.event_type.lower() not in ("process_started", "application_launch"):
            return False, ""
        try:
            event = json.loads(log.event_data or "{}")
        except json.JSONDecodeError:
            return False, ""
        blocked_processes = [p.lower() for p in condition.get("blocked_processes", [])]
        process_name = event.get("process_name", "").lower()
        if process_name and process_name in blocked_processes:
            return True, f"Blocked process '{process_name}' executed on {log.endpoint_id}."

    # ── Unencrypted data transfer ─────────────────────────────────────────────
    elif rule_type == "data_transfer":
        if log.event_type.lower() != "file_transfer":
            return False, ""
        try:
            event = json.loads(log.event_data or "{}")
        except json.JSONDecodeError:
            return False, ""
        require_encryption = condition.get("require_encryption", True)
        encrypted = event.get("encrypted", False)
        if require_encryption and not encrypted:
            return True, f"Unencrypted file transfer detected from {log.endpoint_id} by {log.username}."

    return False, ""
