import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';

@Component({
  standalone: false,
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent {
  username = '';
  password = '';
  loading = false;
  error = '';

  demoAccounts = [
    { role: 'Admin', username: 'admin', password: 'Admin@123' },
    { role: 'Security', username: 'bwembya.rm', password: 'Bwembya@123' },
    { role: 'Viewer', username: 'viewer1', password: 'Viewer@123' },
  ];

  constructor(private auth: AuthService, private router: Router) {
    if (this.auth.isLoggedIn) this.router.navigate(['/dashboard']);
  }

  fillDemo(d: any): void {
    this.username = d.username;
    this.password = d.password;
  }

  onSubmit(): void {
    if (!this.username || !this.password) return;
    this.loading = true;
    this.error = '';
    this.auth.login(this.username, this.password).subscribe({
      next: () => this.router.navigate(['/dashboard']),
      error: (err) => {
        this.error = err.error?.detail || 'Login failed. Check your credentials.';
        this.loading = false;
      }
    });
  }
}
