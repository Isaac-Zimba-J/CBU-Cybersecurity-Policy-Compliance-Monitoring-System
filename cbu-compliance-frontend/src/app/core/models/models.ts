export type UserRole = 'admin' | 'security_personnel' | 'viewer';
export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';
export type ViolationStatus = 'detected' | 'pending_review' | 'under_investigation' | 'escalated' | 'resolved' | 'false_positive';

export interface User {
  id: number;
  username: string;
  email: string;
  full_name?: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

export interface AuthToken {
  access_token: string;
  token_type: string;
  user: User;
}

export interface Policy {
  id: number;
  name: string;
  description?: string;
  version: string;
  is_active: boolean;
  created_at: string;
  updated_at?: string;
  rules: ComplianceRule[];
}

export interface ComplianceRule {
  id: number;
  policy_id: number;
  name: string;
  description?: string;
  rule_type: string;
  condition: string;
  severity: SeverityLevel;
  is_active: boolean;
  created_at: string;
}

export interface ActivityLog {
  id: number;
  endpoint_id: string;
  endpoint_ip?: string;
  username: string;
  event_type: string;
  event_data?: string;
  timestamp: string;
  received_at: string;
  processed: boolean;
}

export interface Violation {
  id: number;
  rule_id?: number;
  activity_log_id?: number;
  endpoint_id: string;
  username?: string;
  description: string;
  severity: SeverityLevel;
  status: ViolationStatus;
  assigned_to?: number;
  notes?: string;
  detected_at: string;
  resolved_at?: string;
}

export interface Alert {
  id: number;
  violation_id?: number;
  title: string;
  message: string;
  severity: SeverityLevel;
  is_read: boolean;
  created_at: string;
}

export interface Report {
  id: number;
  title: string;
  report_type: string;
  generated_by?: number;
  content?: string;
  period_start?: string;
  period_end?: string;
  created_at: string;
}

export interface DashboardStats {
  total_endpoints: number;
  total_logs_today: number;
  open_violations: number;
  critical_violations: number;
  unread_alerts: number;
  compliance_rate: number;
  violations_by_severity: Record<string, number>;
  violations_by_status: Record<string, number>;
  recent_violations: Violation[];
  recent_alerts: Alert[];
}

export interface Endpoint {
  endpoint_id: string;
  endpoint_ip?: string;
  last_seen: string;
  log_count: number;
}
