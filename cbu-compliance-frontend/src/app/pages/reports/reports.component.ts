import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ApiService } from '../../core/services/api.service';
import { Report } from '../../core/models/models';

@Component({
  standalone: false,
  selector: 'app-reports',
  templateUrl: './reports.component.html',
  styleUrls: ['./reports.component.scss']
})
export class ReportsComponent implements OnInit {
  reports: Report[] = [];
  selected: Report | null = null;
  parsedContent: any = null;
  loading = true;
  showGenerate = false;
  generating = false;
  genForm = { report_type: 'weekly' };

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {}
  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading = true;
    this.api.getReports().subscribe({
      next: r => { this.reports = r; this.loading = false; if (r.length > 0) this.selectReport(r[0]); this.cdr.detectChanges(); },
      error: () => { this.loading = false; this.cdr.detectChanges(); }
    });
  }

  selectReport(r: Report): void {
    this.selected = r;
    try { this.parsedContent = JSON.parse(r.content || '{}'); }
    catch { this.parsedContent = null; }
  }

  get severityEntries(): { key: string, value: number }[] {
    if (!this.parsedContent?.violations_by_severity) return [];
    return Object.entries(this.parsedContent.violations_by_severity).map(([key, value]) => ({ key, value: value as number }));
  }

  getPercent(val: number, total: number): number {
    return total === 0 ? 0 : Math.round((val / total) * 100);
  }

  generate(): void {
    this.generating = true;
    this.api.generateReport(this.genForm).subscribe({
      next: r => {
        this.reports.unshift(r);
        this.selectReport(r);
        this.generating = false;
        this.showGenerate = false;
      },
      error: () => { this.generating = false; }
    });
  }
}
