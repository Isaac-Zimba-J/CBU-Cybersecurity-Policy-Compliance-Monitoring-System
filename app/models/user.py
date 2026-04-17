from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from app.core.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    SECURITY_PERSONNEL = "security_personnel"
    VIEWER = "viewer"


class SeverityLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ViolationStatus(str, enum.Enum):
    DETECTED = "detected"
    PENDING_REVIEW = "pending_review"
    UNDER_INVESTIGATION = "under_investigation"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(200), unique=True, nullable=False)
    full_name = Column(String(200))
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)

    violations = relationship("Violation", back_populates="assigned_to_user", foreign_keys="Violation.assigned_to")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    version = Column(String(20), default="1.0")
    is_active = Column(Boolean, default=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    rules = relationship("ComplianceRule", back_populates="policy", cascade="all, delete-orphan")
    creator = relationship("User", foreign_keys=[created_by])


class ComplianceRule(Base):
    __tablename__ = "compliance_rules"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey("policies.id"), nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    rule_type = Column(String(100), nullable=False)  # e.g. login_time, device_type, network_access
    condition = Column(Text, nullable=False)          # JSON string describing the condition
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    policy = relationship("Policy", back_populates="rules")
    violations = relationship("Violation", back_populates="rule")


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(String(100), nullable=False, index=True)   # machine hostname or ID
    endpoint_ip = Column(String(50))
    username = Column(String(100), index=True)
    event_type = Column(String(100), nullable=False)                # login, logout, file_access, network, usb, etc.
    event_data = Column(Text)                                        # JSON payload from agent
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    received_at = Column(DateTime(timezone=True), server_default=func.now())
    processed = Column(Boolean, default=False)

    violations = relationship("Violation", back_populates="activity_log")


class Violation(Base):
    __tablename__ = "violations"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("compliance_rules.id"))
    activity_log_id = Column(Integer, ForeignKey("activity_logs.id"))
    endpoint_id = Column(String(100), nullable=False)
    username = Column(String(100))
    description = Column(Text, nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False)
    status = Column(Enum(ViolationStatus), default=ViolationStatus.DETECTED)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    notes = Column(Text, nullable=True)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    rule = relationship("ComplianceRule", back_populates="violations")
    activity_log = relationship("ActivityLog", back_populates="violations")
    assigned_to_user = relationship("User", back_populates="violations", foreign_keys=[assigned_to])
    alerts = relationship("Alert", back_populates="violation")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    violation_id = Column(Integer, ForeignKey("violations.id"))
    title = Column(String(300), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    violation = relationship("Violation", back_populates="alerts")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(300), nullable=False)
    report_type = Column(String(100), nullable=False)   # weekly, monthly, on_demand, audit
    generated_by = Column(Integer, ForeignKey("users.id"))
    content = Column(Text)                               # JSON summary data
    period_start = Column(DateTime(timezone=True))
    period_end = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    generator = relationship("User", foreign_keys=[generated_by])
