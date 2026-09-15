import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { Policy, ComplianceRule } from '../../core/models/models';

const CONDITION_TEMPLATES: Record<string, string> = {
  login_time:        '{"allowed_start":"07:00","allowed_end":"20:00"}',
  usb_device:        '{"allowed":false,"allowed_devices":[]}',
  network_access:    '{"blocked_ports":[23,6881,4444],"blocked_ips":[]}',
  failed_logins:     '{"threshold":5,"window_minutes":10}',
  process_execution: '{"blocked_processes":["nmap","wireshark","netcat","nc"]}',
  data_transfer:     '{"require_encryption":true}',
};

/** Plain-language hints shown under the condition editor so rules can be tuned during a demo. */
const CONDITION_HINTS: Record<string, string> = {
  login_time:        'Logins outside allowed_start–allowed_end (24h, local time) are flagged.',
  usb_device:        'Any removable drive is flagged unless allowed is true or its name contains an allowed_devices entry.',
  network_access:    'Connections to any blocked_ports, or to IPs starting with a blocked_ips entry, are flagged.',
  failed_logins:     'threshold failed logins by one user within window_minutes → one violation per window.',
  process_execution: 'Process names are matched without path or .exe (e.g. "nmap" matches C:\\Tools\\nmap.exe).',
  data_transfer:     'file_transfer events with encrypted=false are flagged when require_encryption is true.',
};

const EMPTY_RULE = { name: '', rule_type: 'login_time', severity: 'medium', condition: CONDITION_TEMPLATES['login_time'], description: '' };

@Component({
  standalone: false,
  selector: 'app-policies',
  templateUrl: './policies.component.html',
  styleUrls: ['./policies.component.scss']
})
export class PoliciesComponent implements OnInit {
  policies: Policy[] = [];
  loading = true;
  saving = false;
  showCreate = false;
  showAddRule = false;
  selectedPolicy: Policy | null = null;

  createForm = { name: '', description: '', version: '1.0' };
  ruleForm = { ...EMPTY_RULE };
  editingRule: ComplianceRule | null = null;
  ruleError = '';

  constructor(private api: ApiService, private auth: AuthService, private cdr: ChangeDetectorRef) {}
  ngOnInit(): void { this.load(); }

  get canEdit(): boolean { return this.auth.isSecurityPersonnel(); }

  load(): void {
    this.loading = true;
    this.api.getPolicies().subscribe({
      next: p => { this.policies = p; this.loading = false; this.cdr.detectChanges(); },
      error: () => { this.loading = false; this.cdr.detectChanges(); }
    });
  }

  openCreate(): void { this.showCreate = true; }
  closeCreate(): void { this.showCreate = false; this.createForm = { name: '', description: '', version: '1.0' }; }

  createPolicy(): void {
    if (!this.createForm.name) return;
    this.saving = true;
    this.api.createPolicy(this.createForm).subscribe({
      next: p => { this.policies.unshift(p); this.saving = false; this.closeCreate(); },
      error: () => { this.saving = false; }
    });
  }

  openPolicy(p: Policy): void { this.selectedPolicy = { ...p, rules: [...p.rules] }; this.closeRuleForm(); }
  closePolicy(): void { this.selectedPolicy = null; this.closeRuleForm(); }

  get conditionHint(): string { return CONDITION_HINTS[this.ruleForm.rule_type] || ''; }

  prefillCondition(): void {
    this.ruleForm.condition = CONDITION_TEMPLATES[this.ruleForm.rule_type] || '{}';
  }

  openAddRule(): void {
    this.editingRule = null;
    this.ruleForm = { ...EMPTY_RULE };
    this.ruleError = '';
    this.showAddRule = true;
  }

  openEditRule(r: ComplianceRule): void {
    this.editingRule = r;
    this.ruleForm = { name: r.name, rule_type: r.rule_type, severity: r.severity, condition: r.condition, description: r.description || '' };
    this.ruleError = '';
    this.showAddRule = true;
  }

  closeRuleForm(): void {
    this.showAddRule = false;
    this.editingRule = null;
    this.ruleError = '';
  }

  private validCondition(): boolean {
    try { JSON.parse(this.ruleForm.condition); return true; }
    catch { this.ruleError = 'Condition must be valid JSON.'; return false; }
  }

  private replaceRule(updated: ComplianceRule): void {
    const swap = (rules: ComplianceRule[]) => { const i = rules.findIndex(x => x.id === updated.id); if (i > -1) rules[i] = updated; };
    swap(this.selectedPolicy!.rules);
    const pi = this.policies.findIndex(p => p.id === this.selectedPolicy!.id);
    if (pi > -1) swap(this.policies[pi].rules);
  }

  saveRule(): void {
    if (!this.selectedPolicy || !this.ruleForm.name || !this.validCondition()) return;
    this.saving = true;
    const policyId = this.selectedPolicy.id;
    const req = this.editingRule
      ? this.api.updateRule(policyId, this.editingRule.id, this.ruleForm)
      : this.api.addRule(policyId, this.ruleForm);
    req.subscribe({
      next: r => {
        if (this.editingRule) {
          this.replaceRule(r);
        } else {
          this.selectedPolicy!.rules.push(r);
          const pi = this.policies.findIndex(p => p.id === policyId);
          if (pi > -1) this.policies[pi].rules.push(r);
        }
        this.closeRuleForm();
        this.saving = false;
        this.cdr.detectChanges();
      },
      error: e => { this.ruleError = e?.error?.detail || 'Could not save rule.'; this.saving = false; this.cdr.detectChanges(); }
    });
  }

  toggleRule(r: ComplianceRule): void {
    if (!this.selectedPolicy) return;
    this.api.updateRule(this.selectedPolicy.id, r.id, { is_active: !r.is_active }).subscribe({
      next: updated => { this.replaceRule(updated); this.cdr.detectChanges(); }
    });
  }

  deleteRule(r: ComplianceRule): void {
    if (!this.selectedPolicy) return;
    if (!confirm(`Delete rule "${r.name}"?`)) return;
    this.api.deleteRule(this.selectedPolicy.id, r.id).subscribe({
      next: () => {
        this.selectedPolicy!.rules = this.selectedPolicy!.rules.filter(x => x.id !== r.id);
        const pi = this.policies.findIndex(p => p.id === this.selectedPolicy!.id);
        if (pi > -1) this.policies[pi].rules = this.policies[pi].rules.filter(x => x.id !== r.id);
      }
    });
  }

  deactivatePolicy(): void {
    if (!this.selectedPolicy) return;
    if (!confirm(`Deactivate policy "${this.selectedPolicy.name}"?`)) return;
    this.api.deletePolicy(this.selectedPolicy.id).subscribe({
      next: () => {
        this.policies = this.policies.filter(p => p.id !== this.selectedPolicy!.id);
        this.closePolicy();
      }
    });
  }
}
