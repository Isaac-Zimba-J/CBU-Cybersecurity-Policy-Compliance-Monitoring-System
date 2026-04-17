from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models.user import User, UserRole, Violation, ViolationStatus, SeverityLevel
from app.schemas.schemas import ViolationOut, ViolationUpdate

router = APIRouter(prefix="/violations", tags=["Violations"])


@router.get("/", response_model=List[ViolationOut])
def list_violations(
    status: Optional[ViolationStatus] = None,
    severity: Optional[SeverityLevel] = None,
    endpoint_id: Optional[str] = None,
    username: Optional[str] = None,
    hours: int = Query(168, ge=1, le=8760),  # default: last 7 days
    skip: int = 0,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    query = db.query(Violation).filter(Violation.detected_at >= cutoff)

    if status:
        query = query.filter(Violation.status == status)
    if severity:
        query = query.filter(Violation.severity == severity)
    if endpoint_id:
        query = query.filter(Violation.endpoint_id == endpoint_id)
    if username:
        query = query.filter(Violation.username.ilike(f"%{username}%"))

    return query.order_by(Violation.detected_at.desc()).offset(skip).limit(limit).all()


@router.get("/{violation_id}", response_model=ViolationOut)
def get_violation(
    violation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    v = db.query(Violation).filter(Violation.id == violation_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Violation not found")
    return v


@router.put("/{violation_id}", response_model=ViolationOut)
def update_violation(
    violation_id: int,
    update_data: ViolationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.SECURITY_PERSONNEL))
):
    v = db.query(Violation).filter(Violation.id == violation_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Violation not found")

    if update_data.status:
        v.status = update_data.status
        if update_data.status in (ViolationStatus.RESOLVED, ViolationStatus.FALSE_POSITIVE):
            v.resolved_at = datetime.utcnow()
    if update_data.assigned_to is not None:
        v.assigned_to = update_data.assigned_to
    if update_data.notes is not None:
        v.notes = update_data.notes

    db.commit()
    db.refresh(v)
    return v


@router.get("/stats/summary")
def violation_stats(
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from sqlalchemy import func
    cutoff = datetime.utcnow() - timedelta(days=days)
    violations = db.query(Violation).filter(Violation.detected_at >= cutoff).all()

    by_severity = {}
    by_status = {}
    by_day = {}

    for v in violations:
        by_severity[v.severity.value] = by_severity.get(v.severity.value, 0) + 1
        by_status[v.status.value] = by_status.get(v.status.value, 0) + 1
        day = v.detected_at.strftime("%Y-%m-%d")
        by_day[day] = by_day.get(day, 0) + 1

    return {
        "total": len(violations),
        "by_severity": by_severity,
        "by_status": by_status,
        "by_day": by_day,
        "period_days": days,
    }
