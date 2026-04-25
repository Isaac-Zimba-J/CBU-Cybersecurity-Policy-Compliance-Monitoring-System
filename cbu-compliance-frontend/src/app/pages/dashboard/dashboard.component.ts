import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ApiService } from '../../core/services/api.service';
import { DashboardStats } from '../../core/models/models';
import { Chart, registerables } from 'chart.js';
Chart.register(...registerables);

@Component({
  standalone: false,
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit {
  stats: DashboardStats | null = null;
  loading = true;
  lastUpdated = new Date();
  private severityChart: Chart | null = null;
  private statusChart: Chart | null = null;

  severityChartData: { labels: string[], data: number[] } = { labels: [], data: [] };
  statusChartData:   { labels: string[], data: number[] } = { labels: [], data: [] };

  severityColors: Record<string, string> = {
    low: '#4ade80', medium: '#fbbf24', high: '#f87171', critical: '#c084fc'
  };
  statusColors: Record<string, string> = {
    detected: '#38bdf8', pending_review: '#fbbf24',
    under_investigation: '#818cf8', escalated: '#c084fc',
    resolved: '#4ade80', false_positive: '#94a3b8'
  };

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading = true;
    this.destroyCharts();
    this.api.getDashboardStats().subscribe({
      next: s => {
        this.stats = s;
        this.severityChartData = {
          labels: Object.keys(s.violations_by_severity),
          data: Object.values(s.violations_by_severity)
        };
        this.statusChartData = {
          labels: Object.keys(s.violations_by_status),
          data: Object.values(s.violations_by_status)
        };
        this.loading = false;
        this.lastUpdated = new Date();
        this.cdr.detectChanges();
        if (this.severityChartData.labels.length > 0) this.drawSeverityChart();
        if (this.statusChartData.labels.length > 0) this.drawStatusChart();
      },
      error: () => { this.loading = false; }
    });
  }

  destroyCharts(): void {
    this.severityChart?.destroy(); this.severityChart = null;
    this.statusChart?.destroy();   this.statusChart = null;
  }

  drawSeverityChart(): void {
    const el = document.getElementById('severityChart') as HTMLCanvasElement;
    if (!el) return;
    this.severityChart = new Chart(el, {
      type: 'doughnut',
      data: {
        labels: this.severityChartData.labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
        datasets: [{
          data: this.severityChartData.data,
          backgroundColor: this.severityChartData.labels.map(l => this.severityColors[l] + '99'),
          borderColor: this.severityChartData.labels.map(l => this.severityColors[l]),
          borderWidth: 2
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', padding: 12, font: { size: 12 } } } }
      }
    });
  }

  drawStatusChart(): void {
    const el = document.getElementById('statusChart') as HTMLCanvasElement;
    if (!el) return;
    this.statusChart = new Chart(el, {
      type: 'bar',
      data: {
        labels: this.statusChartData.labels.map(l => l.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())),
        datasets: [{
          label: 'Violations',
          data: this.statusChartData.data,
          backgroundColor: this.statusChartData.labels.map(l => (this.statusColors[l] || '#94a3b8') + '88'),
          borderColor:     this.statusChartData.labels.map(l => this.statusColors[l] || '#94a3b8'),
          borderWidth: 2, borderRadius: 6
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#94a3b8', font: { size: 10 } }, grid: { color: '#1e293b' } },
          y: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' }, beginAtZero: true }
        }
      }
    });
  }

  get gaugeColor(): string {
    const r = this.stats?.compliance_rate ?? 0;
    if (r >= 90) return '#4ade80';
    if (r >= 70) return '#fbbf24';
    return '#f87171';
  }
}
