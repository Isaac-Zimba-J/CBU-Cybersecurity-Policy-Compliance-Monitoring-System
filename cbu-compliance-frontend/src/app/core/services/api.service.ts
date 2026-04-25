import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import {
  AuthToken, User, Policy, ComplianceRule, ActivityLog,
  Violation, Alert, Report, DashboardStats, Endpoint
} from '../models/models';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private base = environment.apiUrl;

  constructor(private http: HttpClient) {}

  // ── Auth ────────────────────────────────────────────────────────────────────
  login(username: string, password: string): Observable<AuthToken> {
    const body = new URLSearchParams();
    body.set('username', username);
    body.set('password', password);
    return this.http.post<AuthToken>(`${this.base}/auth/login`, body.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
  }

  getMe(): Observable<User> {
    return this.http.get<User>(`${this.base}/auth/me`);
  }

  register(data: any): Observable<User> {
    return this.http.post<User>(`${this.base}/auth/register`, data);
  }

  // ── Dashboard ────────────────────────────────────────────────────────────────
  getDashboardStats(): Observable<DashboardStats> {
    return this.http.get<DashboardStats>(`${this.base}/dashboard/stats`);
  }

  // ── Users ────────────────────────────────────────────────────────────────────
  getUsers(): Observable<User[]> {
    return this.http.get<User[]>(`${this.base}/users/`);
  }

  updateUser(id: number, data: any): Observable<User> {
    return this.http.put<User>(`${this.base}/users/${id}`, data);
  }

  deleteUser(id: number): Observable<any> {
    return this.http.delete(`${this.base}/users/${id}`);
  }

  // ── Policies ─────────────────────────────────────────────────────────────────
  getPolicies(): Observable<Policy[]> {
    return this.http.get<Policy[]>(`${this.base}/policies/`);
  }

  getPolicy(id: number): Observable<Policy> {
    return this.http.get<Policy>(`${this.base}/policies/${id}`);
  }

  createPolicy(data: any): Observable<Policy> {
    return this.http.post<Policy>(`${this.base}/policies/`, data);
  }

  updatePolicy(id: number, data: any): Observable<Policy> {
    return this.http.put<Policy>(`${this.base}/policies/${id}`, data);
  }

  deletePolicy(id: number): Observable<any> {
    return this.http.delete(`${this.base}/policies/${id}`);
  }

  addRule(policyId: number, data: any): Observable<ComplianceRule> {
    return this.http.post<ComplianceRule>(`${this.base}/policies/${policyId}/rules`, data);
  }

  deleteRule(policyId: number, ruleId: number): Observable<any> {
    return this.http.delete(`${this.base}/policies/${policyId}/rules/${ruleId}`);
  }

  // ── Activity Logs ─────────────────────────────────────────────────────────────
  getLogs(params: any = {}): Observable<ActivityLog[]> {
    return this.http.get<ActivityLog[]>(`${this.base}/logs/`, { params });
  }

  getEndpoints(): Observable<Endpoint[]> {
    return this.http.get<Endpoint[]>(`${this.base}/logs/endpoints`);
  }

  // ── Violations ────────────────────────────────────────────────────────────────
  getViolations(params: any = {}): Observable<Violation[]> {
    return this.http.get<Violation[]>(`${this.base}/violations/`, { params });
  }

  getViolation(id: number): Observable<Violation> {
    return this.http.get<Violation>(`${this.base}/violations/${id}`);
  }

  updateViolation(id: number, data: any): Observable<Violation> {
    return this.http.put<Violation>(`${this.base}/violations/${id}`, data);
  }

  getViolationStats(days: number = 7): Observable<any> {
    return this.http.get(`${this.base}/violations/stats/summary`, { params: { days } });
  }

  // ── Alerts ────────────────────────────────────────────────────────────────────
  getAlerts(unreadOnly = false): Observable<Alert[]> {
    return this.http.get<Alert[]>(`${this.base}/alerts/`, { params: { unread_only: unreadOnly } });
  }

  getAlertCount(): Observable<{ unread: number; total: number }> {
    return this.http.get<any>(`${this.base}/alerts/count`);
  }

  markAlertRead(id: number): Observable<any> {
    return this.http.put(`${this.base}/alerts/${id}/read`, {});
  }

  markAllRead(): Observable<any> {
    return this.http.put(`${this.base}/alerts/read-all`, {});
  }

  // ── Reports ───────────────────────────────────────────────────────────────────
  getReports(): Observable<Report[]> {
    return this.http.get<Report[]>(`${this.base}/reports/`);
  }

  getReport(id: number): Observable<Report> {
    return this.http.get<Report>(`${this.base}/reports/${id}`);
  }

  generateReport(data: any): Observable<Report> {
    return this.http.post<Report>(`${this.base}/reports/generate`, data);
  }
}
