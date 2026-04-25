import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ApiService } from '../../core/services/api.service';
import { Alert } from '../../core/models/models';

@Component({
  standalone: false,
  selector: 'app-alerts',
  templateUrl: './alerts.component.html',
  styleUrls: ['./alerts.component.scss']
})
export class AlertsComponent implements OnInit {
  alerts: Alert[] = [];
  loading = true;
  unreadOnly = false;
  unread = 0;
  total = 0;

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.load();
    this.api.getAlertCount().subscribe(c => { this.unread = c.unread; this.total = c.total; this.cdr.detectChanges(); });
  }

  load(): void {
    this.loading = true;
    this.api.getAlerts(this.unreadOnly).subscribe({
      next: a => { this.alerts = a; this.loading = false; this.cdr.detectChanges(); },
      error: () => { this.loading = false; this.cdr.detectChanges(); }
    });
  }

  markRead(a: Alert): void {
    if (a.is_read) return;
    this.api.markAlertRead(a.id).subscribe(() => {
      a.is_read = true;
      this.unread = Math.max(0, this.unread - 1);
      this.cdr.detectChanges();
    });
  }

  markAllRead(): void {
    this.api.markAllRead().subscribe(() => {
      this.alerts.forEach(a => a.is_read = true);
      this.unread = 0;
      this.cdr.detectChanges();
    });
  }
}
