import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { AuthGuard } from './core/guards/auth.guard';
import { LoginComponent }     from './pages/login/login.component';
import { DashboardComponent } from './pages/dashboard/dashboard.component';
import { ViolationsComponent }from './pages/violations/violations.component';
import { PoliciesComponent }  from './pages/policies/policies.component';
import { LogsComponent }      from './pages/logs/logs.component';
import { AlertsComponent }    from './pages/alerts/alerts.component';
import { ReportsComponent }   from './pages/reports/reports.component';
import { UsersComponent }     from './pages/users/users.component';

const routes: Routes = [
  { path: 'login',      component: LoginComponent },
  { path: 'dashboard',  component: DashboardComponent,  canActivate: [AuthGuard] },
  { path: 'violations', component: ViolationsComponent, canActivate: [AuthGuard] },
  { path: 'policies',   component: PoliciesComponent,   canActivate: [AuthGuard] },
  { path: 'logs',       component: LogsComponent,       canActivate: [AuthGuard] },
  { path: 'alerts',     component: AlertsComponent,     canActivate: [AuthGuard] },
  { path: 'reports',    component: ReportsComponent,    canActivate: [AuthGuard] },
  { path: 'users',      component: UsersComponent,      canActivate: [AuthGuard] },
  { path: '',           redirectTo: '/dashboard', pathMatch: 'full' },
  { path: '**',         redirectTo: '/dashboard' },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule {}
