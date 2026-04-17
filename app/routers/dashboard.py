from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User, ActivityLog, Violation, Alert, ViolationStatus
from app.schemas.schemas import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = now - timedelta(days=7)

    # Unique endpoints (last 7 days)
    from sqlalchemy import func, distinct
    total_endpoints = db.query(func.count(distinct(ActivityLog.endpoint_id))).filter(
        ActivityLog.received_at >= week_ago
    ).scalar() or 0

    # Logs today
    total_logs_today = db.query(ActivityLog).filter(
        ActivityLog.received_at >= today_start
    ).count()

    # Open violations
    open_violations = db.query(Violation).filter(
        Violation.status.notin_([ViolationStatus.RESOLVED, ViolationStatus.FALSE_POSITIVE])
    ).count()

    # Critical violations (open)
    from app.models.user import SeverityLevel
    critical_violations = db.query(Violation).filter(
        Violation.severity == SeverityLevel.CRITICAL,
        Violation.status.notin_([ViolationStatus.RESOLVED, ViolationStatus.FALSE_POSITIVE])
    ).count()

    # Unread alerts
    unread_alerts = db.query(Alert).filter(Alert.is_read == False).count()

    # Compliance rate (last 7 days)
    total_logs_week = db.query(ActivityLog).filter(ActivityLog.received_at >= week_ago).count()
    logs_with_violations = db.query(func.count(distinct(Violation.activity_log_id))).filter(
        Violation.detected_at >= week_ago,
        Violation.activity_log_id.isnot(None)
    ).scalar() or 0
    compliance_rate = round((1 - logs_with_violations / max(total_logs_week, 1)) * 100, 2)

    # Violations by severity (open)
    all_open = db.query(Violation).filter(
        Violation.status.notin_([ViolationStatus.RESOLVED, ViolationStatus.FALSE_POSITIVE])
    ).all()
    by_severity = {}
    by_status = {}
    for v in all_open:
        by_severity[v.severity.value] = by_severity.get(v.severity.value, 0) + 1
        by_status[v.status.value] = by_status.get(v.status.value, 0) + 1

    # Recent violations and alerts
    recent_violations = db.query(Violation).order_by(Violation.detected_at.desc()).limit(5).all()
    recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(5).all()

    return DashboardStats(
        total_endpoints=total_endpoints,
        total_logs_today=total_logs_today,
        open_violations=open_violations,
        critical_violations=critical_violations,
        unread_alerts=unread_alerts,
        compliance_rate=compliance_rate,
        violations_by_severity=by_severity,
        violations_by_status=by_status,
        recent_violations=recent_violations,
        recent_alerts=recent_alerts,
    )
