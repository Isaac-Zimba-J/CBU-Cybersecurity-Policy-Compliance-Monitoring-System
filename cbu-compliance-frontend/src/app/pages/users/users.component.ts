import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ApiService } from '../../core/services/api.service';
import { AuthService } from '../../core/services/auth.service';
import { User } from '../../core/models/models';

@Component({
  standalone: false,
  selector: 'app-users',
  templateUrl: './users.component.html',
  styleUrls: ['./users.component.scss']
})
export class UsersComponent implements OnInit {
  users: User[] = [];
  loading = true;
  saving = false;
  showCreate = false;
  editTarget: User | null = null;
  createError = '';

  createForm = { username: '', email: '', full_name: '', password: '', role: 'viewer' };
  editForm:   { full_name: string, role: string, is_active: boolean } = { full_name: '', role: '', is_active: true };

  constructor(private api: ApiService, private auth: AuthService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void { this.load(); }

  get currentUserId(): number | undefined { return this.auth.currentUser?.id; }

  load(): void {
    this.loading = true;
    this.api.getUsers().subscribe({
      next: u => { this.users = u; this.loading = false; this.cdr.detectChanges(); },
      error: () => { this.loading = false; this.cdr.detectChanges(); }
    });
  }

  roleBadge(role: string): string {
    return role === 'admin' ? 'badge-critical' : role === 'security_personnel' ? 'badge-medium' : 'badge-low';
  }

  createUser(): void {
    if (!this.createForm.username || !this.createForm.email || !this.createForm.password) {
      this.createError = 'Please fill in all required fields.'; return;
    }
    this.saving = true; this.createError = '';
    this.api.register(this.createForm).subscribe({
      next: u => { this.users.push(u); this.saving = false; this.showCreate = false; this.createForm = { username: '', email: '', full_name: '', password: '', role: 'viewer' }; },
      error: err => { this.createError = err.error?.detail || 'Failed to create user.'; this.saving = false; }
    });
  }

  editUser(u: User): void {
    this.editTarget = u;
    this.editForm = { full_name: u.full_name || '', role: u.role, is_active: u.is_active };
  }

  saveEdit(): void {
    if (!this.editTarget) return;
    this.saving = true;
    this.api.updateUser(this.editTarget.id, this.editForm).subscribe({
      next: updated => {
        const i = this.users.findIndex(u => u.id === updated.id);
        if (i > -1) this.users[i] = updated;
        this.saving = false; this.editTarget = null;
      },
      error: () => { this.saving = false; }
    });
  }

  deleteUser(u: User): void {
    if (!confirm(`Delete user "${u.username}"? This cannot be undone.`)) return;
    this.api.deleteUser(u.id).subscribe({
      next: () => { this.users = this.users.filter(x => x.id !== u.id); }
    });
  }
}
