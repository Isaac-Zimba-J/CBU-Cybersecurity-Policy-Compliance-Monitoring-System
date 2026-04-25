import { Component, OnInit, OnDestroy, ChangeDetectorRef, Pipe, PipeTransform } from '@angular/core';
import { ApiService } from '../../core/services/api.service';
import { ActivityLog, Endpoint } from '../../core/models/models';

@Pipe({
  standalone: false, name: 'jsonPreview' })
export class JsonPreviewPipe implements PipeTransform {
  transform(value: string | undefined): string {
    if (!value) return '—';
    try {
      const obj = JSON.parse(value);
      const keys = Object.keys(obj);
      if (keys.length === 0) return '{}';
      return keys.slice(0, 2).map(k => `${k}: ${obj[k]}`).join(', ') + (keys.length > 2 ? '...' : '');
    } catch { return value.slice(0, 60); }
  }
}

@Component({
  standalone: false,
  selector: 'app-logs',
  templateUrl: './logs.component.html',
  styleUrls: ['./logs.component.scss']
})
export class LogsComponent implements OnInit, OnDestroy {
  logs: ActivityLog[] = [];
  endpoints: Endpoint[] = [];
  loading = true;
  filters = { event_type: '', username: '', endpoint_id: '', hours: 24 };
  private filterDebounce: any;

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.load();
    this.api.getEndpoints().subscribe(e => { this.endpoints = e; this.cdr.detectChanges(); });
  }

  ngOnDestroy(): void { if (this.filterDebounce) clearTimeout(this.filterDebounce); }

  onUsernameInput(): void {
    if (this.filterDebounce) clearTimeout(this.filterDebounce);
    this.filterDebounce = setTimeout(() => this.load(), 350);
  }

  load(): void {
    this.loading = true;
    const params: any = { hours: this.filters.hours, limit: 200 };
    if (this.filters.event_type)  params.event_type  = this.filters.event_type;
    if (this.filters.username)    params.username    = this.filters.username;
    if (this.filters.endpoint_id) params.endpoint_id = this.filters.endpoint_id;
    this.api.getLogs(params).subscribe({
      next: l => { this.logs = l; this.loading = false; this.cdr.detectChanges(); },
      error: () => { this.loading = false; this.cdr.detectChanges(); }
    });
  }

  filterByEndpoint(id: string): void {
    this.filters.endpoint_id = this.filters.endpoint_id === id ? '' : id;
    this.load();
  }
}
