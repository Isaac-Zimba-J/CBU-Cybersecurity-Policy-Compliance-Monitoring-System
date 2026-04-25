import { Component, OnInit, OnDestroy } from '@angular/core';
import { AuthService } from '../../../core/services/auth.service';
import { ApiService } from '../../../core/services/api.service';
import { User } from '../../../core/models/models';
import { Subscription } from 'rxjs';

@Component({
  standalone: false,
  selector: 'app-sidebar',
  templateUrl: './sidebar.component.html',
  styleUrls: ['./sidebar.component.scss']
})
export class SidebarComponent implements OnInit, OnDestroy {
  currentUser: User | null = null;
  unreadAlerts = 0;
  openViolations = 0;
  private intervalId: any;
  private userSub!: Subscription;

  constructor(private auth: AuthService, private api: ApiService) {}

  ngOnInit(): void {
    this.userSub = this.auth.currentUser$.subscribe(u => {
      this.currentUser = u;
    });
    this.loadCounts();
    this.intervalId = setInterval(() => this.loadCounts(), 30000);
  }

  ngOnDestroy(): void {
    clearInterval(this.intervalId);
    this.userSub?.unsubscribe();
  }

  loadCounts(): void {
    this.api.getAlertCount().subscribe(c => this.unreadAlerts = c.unread);
    this.api.getViolationStats(30).subscribe((s: any) => {
      this.openViolations = (s.by_status['detected'] || 0) +
                            (s.by_status['pending_review'] || 0) +
                            (s.by_status['under_investigation'] || 0) +
                            (s.by_status['escalated'] || 0);
    });
  }

  get initials(): string {
    const name = this.currentUser?.full_name || this.currentUser?.username || '?';
    return name.split(' ').map((n: string) => n[0]).join('').toUpperCase().slice(0, 2);
  }

  get isAdmin(): boolean { return this.auth.isAdmin(); }

  logout(): void { this.auth.logout(); }
}
