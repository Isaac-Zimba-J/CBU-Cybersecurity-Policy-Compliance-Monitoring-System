from pydantic import BaseModel, EmailStr
from typing import Optional, List, Any
from datetime import datetime
from app.models.user import UserRole, SeverityLevel, ViolationStatus


# ─── Auth ────────────────────────────────────────────────────────────────────

class Token(BaseModel):
    access_token: str
    token_type: str
    user: "UserOut"

class TokenData(BaseModel):
    user_id: Optional[int] = None


# ─── Users ───────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    password: str
    role: UserRole = UserRole.VIEWER

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


# ─── Policies ────────────────────────────────────────────────────────────────

class ComplianceRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rule_type: str
    condition: str   # JSON string
    severity: SeverityLevel = SeverityLevel.MEDIUM

class ComplianceRuleOut(BaseModel):
    id: int
    policy_id: int
    name: str
    description: Optional[str]
    rule_type: str
    condition: str
    severity: SeverityLevel
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    version: str = "1.0"
    rules: Optional[List[ComplianceRuleCreate]] = []

class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    version: Optional[str] = None
    is_active: Optional[bool] = None

class PolicyOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    version: str
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime]
    rules: List[ComplianceRuleOut] = []

    class Config:
        from_attributes = True


# ─── Activity Logs ───────────────────────────────────────────────────────────

class ActivityLogIngest(BaseModel):
    endpoint_id: str
    endpoint_ip: Optional[str] = None
    username: str
    event_type: str
    event_data: Optional[str] = None   # JSON string
    timestamp: datetime

class ActivityLogOut(BaseModel):
    id: int
    endpoint_id: str
    endpoint_ip: Optional[str]
    username: str
    event_type: str
    event_data: Optional[str]
    timestamp: datetime
    received_at: datetime
    processed: bool

    class Config:
        from_attributes = True


# ─── Violations ──────────────────────────────────────────────────────────────

class ViolationUpdate(BaseModel):
    status: Optional[ViolationStatus] = None
    assigned_to: Optional[int] = None
    notes: Optional[str] = None

class ViolationOut(BaseModel):
    id: int
    rule_id: Optional[int]
    activity_log_id: Optional[int]
    endpoint_id: str
    username: Optional[str]
    description: str
    severity: SeverityLevel
    status: ViolationStatus
    assigned_to: Optional[int]
    notes: Optional[str]
    detected_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True


# ─── Alerts ──────────────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: int
    violation_id: Optional[int]
    title: str
    message: str
    severity: SeverityLevel
    is_read: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ─── Reports ─────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    report_type: str = "on_demand"
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None

class ReportOut(BaseModel):
    id: int
    title: str
    report_type: str
    generated_by: Optional[int]
    content: Optional[str]
    period_start: Optional[datetime]
    period_end: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


# ─── Dashboard ───────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_endpoints: int
    total_logs_today: int
    open_violations: int
    critical_violations: int
    unread_alerts: int
    compliance_rate: float
    violations_by_severity: dict
    violations_by_status: dict
    recent_violations: List[ViolationOut]
    recent_alerts: List[AlertOut]
