import json
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timedelta
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User, Report, Violation, ActivityLog, Alert, SeverityLevel, ViolationStatus
from app.schemas.schemas import ReportOut, ReportRequest

router = APIRouter(prefix="/reports", tags=["Reports"])


def build_report_content(db: Session, period_start: datetime, period_end: datetime) -> dict:
    violations = db.query(Violation).filter(
        Violation.detected_at >= period_start,
        Violation.detected_at <= period_end
    ).all()

    logs = db.query(ActivityLog).filter(
        ActivityLog.received_at >= period_start,
        ActivityLog.received_at <= period_end
    ).count()

    resolved = [v for v in violations if v.status == ViolationStatus.RESOLVED]
    open_v = [v for v in violations if v.status not in (ViolationStatus.RESOLVED, ViolationStatus.FALSE_POSITIVE)]

    severity_breakdown = {}
    for v in violations:
        severity_breakdown[v.severity.value] = severity_breakdown.get(v.severity.value, 0) + 1

    # Compliance rate: logs with no violations / total logs
    logs_with_violations = len(set(v.activity_log_id for v in violations if v.activity_log_id))
    compliance_rate = round((1 - logs_with_violations / max(logs, 1)) * 100, 2)

    # Top violating endpoints
    endpoint_counts = {}
    for v in violations:
        endpoint_counts[v.endpoint_id] = endpoint_counts.get(v.endpoint_id, 0) + 1
    top_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "total_activity_logs": logs,
        "total_violations": len(violations),
        "resolved_violations": len(resolved),
        "open_violations": len(open_v),
        "compliance_rate_percent": compliance_rate,
        "violations_by_severity": severity_breakdown,
        "top_violating_endpoints": [{"endpoint": e, "count": c} for e, c in top_endpoints],
    }


@router.post("/generate", response_model=ReportOut, status_code=201)
def generate_report(
    request: ReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    now = datetime.utcnow()

    if request.report_type == "weekly":
        period_start = now - timedelta(days=7)
        period_end = now
        title = f"Weekly Compliance Report — {now.strftime('%Y-%m-%d')}"
    elif request.report_type == "monthly":
        period_start = now - timedelta(days=30)
        period_end = now
        title = f"Monthly Compliance Report — {now.strftime('%Y-%m')}"
    else:
        period_start = request.period_start or (now - timedelta(days=7))
        period_end = request.period_end or now
        title = f"Compliance Report — {period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')}"

    content = build_report_content(db, period_start, period_end)

    report = Report(
        title=title,
        report_type=request.report_type,
        generated_by=current_user.id,
        content=json.dumps(content),
        period_start=period_start,
        period_end=period_end,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/", response_model=List[ReportOut])
def list_reports(
    skip: int = 0,
    limit: int = Query(20, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(Report).order_by(Report.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/{report_id}", response_model=ReportOut)
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Report not found")
    return report
