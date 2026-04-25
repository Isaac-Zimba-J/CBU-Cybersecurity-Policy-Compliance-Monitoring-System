import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { ApiService } from '../../core/services/api.service';
import { Violation } from '../../core/models/models';

@Component({
  standalone: false,
  selector: 'app-violations',
  templateUrl: './violations.component.html',
  styleUrls: ['./violations.component.scss']
})
export class ViolationsComponent implements OnInit, OnDestroy {
  violations: Violation[] = [];
  loading = true;
  selected: Violation | null = null;
  saving = false;

  filters = { severity: '', status: '', endpoint_id: '', hours: 720 };
  updateForm = { status: '', notes: '' };
  private filterDebounce: any;

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {}
  ngOnInit(): void { this.load(); }
  ngOnDestroy(): void { if (this.filterDebounce) clearTimeout(this.filterDebounce); }

  onEndpointInput(): void {
    if (this.filterDebounce) clearTimeout(this.filterDebounce);
    this.filterDebounce = setTimeout(() => this.load(), 350);
  }

  load(): void {
    this.loading = true;
    const params: any = { hours: this.filters.hours, limit: 100 };
    if (this.filters.severity)   params.severity    = this.filters.severity;
    if (this.filters.status)     params.status      = this.filters.status;
    if (this.filters.endpoint_id) params.endpoint_id = this.filters.endpoint_id;
    this.api.getViolations(params).subscribe({
      next: v => { this.violations = v; this.loading = false; this.cdr.detectChanges(); },
      error: () => { this.loading = false; this.cdr.detectChanges(); }
    });
  }

  openDetail(v: Violation): void {
    this.selected = v;
    this.updateForm = { status: v.status, notes: v.notes || '' };
  }

  closeDetail(): void { this.selected = null; }

  saveViolation(): void {
    if (!this.selected) return;
    this.saving = true;
    this.api.updateViolation(this.selected.id, this.updateForm).subscribe({
      next: updated => {
        const i = this.violations.findIndex(v => v.id === updated.id);
        if (i > -1) this.violations[i] = updated;
        this.saving = false;
        this.closeDetail();
        this.cdr.detectChanges();
      },
      error: () => { this.saving = false; this.cdr.detectChanges(); }
    });
  }
}
