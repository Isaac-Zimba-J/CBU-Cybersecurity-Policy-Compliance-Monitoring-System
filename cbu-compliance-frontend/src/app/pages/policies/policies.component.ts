import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { Policy, ComplianceRule } from '../../core/models/models';

const CONDITION_TEMPLATES: Record<string, string> = {
  login_time:        '{"allowed_start":"07:00","allowed_end":"20:00"}',
  usb_device:        '{"allowed":false}',
  network_access:    '{"blocked_ports":[23,6881],"blocked_ips":[]}',
  failed_logins:     '{"threshold":5,"window_minutes":10}',
  process_execution: '{"blocked_processes":["nmap","wireshark","netcat"]}',
  data_transfer:     '{"require_encryption":true}',
};

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
  ruleForm = { name: '', rule_type: 'login_time', severity: 'medium', condition: CONDITION_TEMPLATES['login_time'], description: '' };

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

  openPolicy(p: Policy): void { this.selectedPolicy = { ...p, rules: [...p.rules] }; this.showAddRule = false; }
  closePolicy(): void { this.selectedPolicy = null; this.showAddRule = false; }

  prefillCondition(): void {
    this.ruleForm.condition = CONDITION_TEMPLATES[this.ruleForm.rule_type] || '{}';
  }

  addRule(): void {
    if (!this.selectedPolicy || !this.ruleForm.name) return;
    this.saving = true;
    this.api.addRule(this.selectedPolicy.id, this.ruleForm).subscribe({
      next: r => {
        this.selectedPolicy!.rules.push(r);
        const pi = this.policies.findIndex(p => p.id === this.selectedPolicy!.id);
        if (pi > -1) this.policies[pi].rules.push(r);
        this.showAddRule = false;
        this.ruleForm = { name: '', rule_type: 'login_time', severity: 'medium', condition: CONDITION_TEMPLATES['login_time'], description: '' };
        this.saving = false;
      },
      error: () => { this.saving = false; }
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
