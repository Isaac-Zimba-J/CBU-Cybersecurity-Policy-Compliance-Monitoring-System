from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User, ActivityLog
from app.schemas.schemas import ActivityLogIngest, ActivityLogOut
from app.services.compliance_engine import evaluate_log

router = APIRouter(prefix="/logs", tags=["Activity Logs"])


@router.post("/ingest", status_code=201)
def ingest_log(log_data: ActivityLogIngest, db: Session = Depends(get_db)):
    """
    Endpoint called by the Python monitoring agent running on endpoints.
    No auth required so agents can post without user credentials.
    In production, secure this with an API key header.
    """
    log = ActivityLog(
        endpoint_id=log_data.endpoint_id,
        endpoint_ip=log_data.endpoint_ip,
        username=log_data.username,
        event_type=log_data.event_type,
        event_data=log_data.event_data,
        timestamp=log_data.timestamp,
    )
    db.add(log)
    db.flush()

    violations = evaluate_log(db, log)
    log.processed = True

    db.commit()

    return {
        "status": "accepted",
        "log_id": log.id,
        "violations_detected": len(violations),
        "violation_ids": [v.id for v in violations],
    }


@router.post("/ingest/batch", status_code=201)
def ingest_batch(logs: List[ActivityLogIngest], db: Session = Depends(get_db)):
    """Bulk ingest — agent can buffer and send multiple events at once."""
    results = []
    for log_data in logs:
        log = ActivityLog(
            endpoint_id=log_data.endpoint_id,
            endpoint_ip=log_data.endpoint_ip,
            username=log_data.username,
            event_type=log_data.event_type,
            event_data=log_data.event_data,
            timestamp=log_data.timestamp,
        )
        db.add(log)
        db.flush()
        violations = evaluate_log(db, log)
        log.processed = True
        results.append({"log_id": log.id, "violations": len(violations)})

    db.commit()
    return {"accepted": len(results), "results": results}


@router.get("/", response_model=List[ActivityLogOut])
def list_logs(
    endpoint_id: Optional[str] = None,
    username: Optional[str] = None,
    event_type: Optional[str] = None,
    hours: int = Query(24, ge=1, le=720),
    skip: int = 0,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    query = db.query(ActivityLog).filter(ActivityLog.received_at >= cutoff)

    if endpoint_id:
        query = query.filter(ActivityLog.endpoint_id == endpoint_id)
    if username:
        query = query.filter(ActivityLog.username.ilike(f"%{username}%"))
    if event_type:
        query = query.filter(ActivityLog.event_type == event_type)

    return query.order_by(ActivityLog.timestamp.desc()).offset(skip).limit(limit).all()


@router.get("/endpoints")
def list_endpoints(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns a list of all unique endpoints seen in the last 7 days."""
    from sqlalchemy import distinct, func
    cutoff = datetime.utcnow() - timedelta(days=7)
    results = (
        db.query(
            ActivityLog.endpoint_id,
            ActivityLog.endpoint_ip,
            func.max(ActivityLog.received_at).label("last_seen"),
            func.count(ActivityLog.id).label("log_count")
        )
        .filter(ActivityLog.received_at >= cutoff)
        .group_by(ActivityLog.endpoint_id, ActivityLog.endpoint_ip)
        .all()
    )
    return [
        {
            "endpoint_id": r.endpoint_id,
            "endpoint_ip": r.endpoint_ip,
            "last_seen": r.last_seen,
            "log_count": r.log_count,
        }
        for r in results
    ]
