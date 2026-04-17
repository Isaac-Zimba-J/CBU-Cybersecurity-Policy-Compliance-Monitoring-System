from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models.user import User, UserRole, Policy, ComplianceRule
from app.schemas.schemas import PolicyCreate, PolicyOut, PolicyUpdate, ComplianceRuleCreate, ComplianceRuleOut

router = APIRouter(prefix="/policies", tags=["Policies"])


@router.get("/", response_model=List[PolicyOut])
def list_policies(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Policy).filter(Policy.is_active == True).all()


@router.get("/{policy_id}", response_model=PolicyOut)
def get_policy(policy_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.post("/", response_model=PolicyOut, status_code=201)
def create_policy(
    policy_data: PolicyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.SECURITY_PERSONNEL))
):
    policy = Policy(
        name=policy_data.name,
        description=policy_data.description,
        version=policy_data.version,
        created_by=current_user.id,
    )
    db.add(policy)
    db.flush()

    for rule_data in (policy_data.rules or []):
        rule = ComplianceRule(
            policy_id=policy.id,
            name=rule_data.name,
            description=rule_data.description,
            rule_type=rule_data.rule_type,
            condition=rule_data.condition,
            severity=rule_data.severity,
        )
        db.add(rule)

    db.commit()
    db.refresh(policy)
    return policy


@router.put("/{policy_id}", response_model=PolicyOut)
def update_policy(
    policy_id: int,
    update_data: PolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.SECURITY_PERSONNEL))
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    for field, value in update_data.model_dump(exclude_none=True).items():
        setattr(policy, field, value)
    db.commit()
    db.refresh(policy)
    return policy


@router.delete("/{policy_id}")
def delete_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.is_active = False   # soft delete
    db.commit()
    return {"message": "Policy deactivated"}


# ── Rules sub-routes ──────────────────────────────────────────────────────────

@router.post("/{policy_id}/rules", response_model=ComplianceRuleOut, status_code=201)
def add_rule(
    policy_id: int,
    rule_data: ComplianceRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.SECURITY_PERSONNEL))
):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    rule = ComplianceRule(
        policy_id=policy_id,
        name=rule_data.name,
        description=rule_data.description,
        rule_type=rule_data.rule_type,
        condition=rule_data.condition,
        severity=rule_data.severity,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{policy_id}/rules/{rule_id}")
def delete_rule(
    policy_id: int,
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.SECURITY_PERSONNEL))
):
    rule = db.query(ComplianceRule).filter(
        ComplianceRule.id == rule_id,
        ComplianceRule.policy_id == policy_id
    ).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.is_active = False
    db.commit()
    return {"message": "Rule deactivated"}
