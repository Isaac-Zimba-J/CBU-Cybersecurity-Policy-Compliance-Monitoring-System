import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { ApiService } from './api.service';
import { User } from '../models/models';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private currentUserSubject = new BehaviorSubject<User | null>(this.loadUser());
  currentUser$ = this.currentUserSubject.asObservable();

  constructor(private api: ApiService, private router: Router) {}

  private loadUser(): User | null {
    try {
      const u = localStorage.getItem('current_user');
      return u ? JSON.parse(u) : null;
    } catch { return null; }
  }

  get currentUser(): User | null {
    return this.currentUserSubject.value;
  }

  get isLoggedIn(): boolean {
    return !!localStorage.getItem('access_token');
  }

  get token(): string | null {
    return localStorage.getItem('access_token');
  }

  login(username: string, password: string): Observable<any> {
    return this.api.login(username, password).pipe(
      tap(res => {
        localStorage.setItem('access_token', res.access_token);
        localStorage.setItem('current_user', JSON.stringify(res.user));
        this.currentUserSubject.next(res.user);
      })
    );
  }

  logout(): void {
    localStorage.removeItem('access_token');
    localStorage.removeItem('current_user');
    this.currentUserSubject.next(null);
    this.router.navigate(['/login']);
  }

  hasRole(...roles: string[]): boolean {
    return roles.includes(this.currentUser?.role ?? '');
  }

  isAdmin(): boolean { return this.currentUser?.role === 'admin'; }
  isSecurityPersonnel(): boolean {
    return ['admin', 'security_personnel'].includes(this.currentUser?.role ?? '');
  }
}
