import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { ApiService } from '../../core/services/api.service';
import { Alert } from '../../core/models/models';

const LIVE_POLL_MS = 5000;

@Component({
  standalone: false,
  selector: 'app-alerts',
  templateUrl: './alerts.component.html',
  styleUrls: ['./alerts.component.scss']
})
export class AlertsComponent implements OnInit, OnDestroy {
  alerts: Alert[] = [];
  loading = true;
  unreadOnly = false;
  unread = 0;
  total = 0;
  live = true;
  /** ids of alerts that arrived while this page was open — rendered with the "NEW" flash */
  fresh = new Set<number>();
  private maxSeenId = 0;
  private pollId: any;

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.load();
    this.pollId = setInterval(() => { if (this.live) this.refresh(); }, LIVE_POLL_MS);
  }

  ngOnDestroy(): void { clearInterval(this.pollId); }

  load(): void {
    this.loading = true;
    this.refresh(true);
  }

  /** Silent re-fetch; new alerts (higher id than anything seen) get flagged as fresh. */
  refresh(initial = false): void {
    this.api.getAlerts(this.unreadOnly).subscribe({
      next: a => {
        if (!initial && this.maxSeenId > 0) {
          a.filter(x => x.id > this.maxSeenId).forEach(x => this.fresh.add(x.id));
        }
        this.maxSeenId = Math.max(this.maxSeenId, ...a.map(x => x.id));
        this.alerts = a;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => { this.loading = false; this.cdr.detectChanges(); }
    });
    this.api.getAlertCount().subscribe(c => { this.unread = c.unread; this.total = c.total; this.cdr.detectChanges(); });
  }

  toggleLive(): void { this.live = !this.live; if (this.live) this.refresh(); }

  markRead(a: Alert): void {
    this.fresh.delete(a.id);
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
      this.fresh.clear();
      this.unread = 0;
      this.cdr.detectChanges();
    });
  }
}
