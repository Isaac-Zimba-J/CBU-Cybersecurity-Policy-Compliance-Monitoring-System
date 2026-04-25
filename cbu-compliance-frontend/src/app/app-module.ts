import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { FormsModule } from '@angular/forms';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import {
  LucideAngularModule,
  Shield, Bell, ClipboardList, ScrollText, TrendingUp, Users,
  LogOut, Radio, TriangleAlert, Siren, CircleCheck, PartyPopper,
  Info, BellOff, Check, Clock, CalendarDays, Calendar, X,
} from 'lucide-angular';

import { AppRoutingModule }   from './app-routing-module';
import { AppComponent }       from './app';
import { AuthInterceptor }    from './core/interceptors/auth.interceptor';

import { SidebarComponent }   from './shared/components/sidebar/sidebar.component';
import { LoginComponent }     from './pages/login/login.component';
import { DashboardComponent } from './pages/dashboard/dashboard.component';
import { ViolationsComponent }from './pages/violations/violations.component';
import { PoliciesComponent }  from './pages/policies/policies.component';
import { LogsComponent, JsonPreviewPipe } from './pages/logs/logs.component';
import { AlertsComponent }    from './pages/alerts/alerts.component';
import { ReportsComponent }   from './pages/reports/reports.component';
import { UsersComponent }     from './pages/users/users.component';

@NgModule({
  declarations: [
    AppComponent,
    SidebarComponent,
    LoginComponent,
    DashboardComponent,
    ViolationsComponent,
    PoliciesComponent,
    LogsComponent,
    JsonPreviewPipe,
    AlertsComponent,
    ReportsComponent,
    UsersComponent,
  ],
  imports: [
    BrowserModule,
    FormsModule,
    HttpClientModule,
    AppRoutingModule,
    LucideAngularModule.pick({
      Shield, Bell, ClipboardList, ScrollText, TrendingUp, Users,
      LogOut, Radio, TriangleAlert, Siren, CircleCheck, PartyPopper,
      Info, BellOff, Check, Clock, CalendarDays, Calendar, X,
    }),
  ],
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true },
  ],
  bootstrap: [AppComponent]
})
export class AppModule {}
