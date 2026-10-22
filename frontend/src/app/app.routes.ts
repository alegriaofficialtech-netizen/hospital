import { Routes } from '@angular/router';
import { authGuard } from './core/auth/auth.guard';
import { roleGuard } from './core/auth/role.guard';
import { ShellComponent } from './layout/shell.component';

export const routes: Routes = [
  {
    path: 'solicitud-cuenta',
    loadComponent: () =>
      import('./features/account-request/account-request.component').then(
        (m) => m.AccountRequestComponent,
      ),
  },
  {
    path: 'login',
    loadComponent: () => import('./features/login/login.component').then((m) => m.LoginComponent),
  },
  {
    path: '',
    component: ShellComponent,
    canActivate: [authGuard],
    children: [
      {
        path: 'dashboard',
        loadComponent: () =>
          import('./features/dashboard/dashboard.component').then((m) => m.DashboardComponent),
      },
      {
        path: 'admision',
        canActivate: [roleGuard(['ROLE_RECEPTION'])],
        loadComponent: () =>
          import('./features/admission/admission.component').then((m) => m.AdmissionComponent),
      },
      {
        path: 'medico',
        canActivate: [roleGuard(['ROLE_PATHOLOGIST'])],
        loadComponent: () => import('./features/doctor/doctor.component').then((m) => m.DoctorComponent),
      },
      {
        path: 'auditoria',
        canActivate: [roleGuard(['ROLE_SECURITY_AUDITOR'])],
        loadComponent: () => import('./features/audit/audit.component').then((m) => m.AuditComponent),
      },
      {
        path: 'administracion',
        canActivate: [roleGuard(['ROLE_PLATFORM_ADMIN'])],
        loadComponent: () =>
          import('./features/admin-users.component').then((m) => m.AdminUsersComponent),
      },
      {
        path: 'indicadores',
        canActivate: [
          roleGuard([
            'ROLE_RECEPTION',
            'ROLE_LAB_TECH',
            'ROLE_PATHOLOGIST',
            'ROLE_SECURITY_AUDITOR',
          ]),
        ],
        loadComponent: () =>
          import('./features/indicators/indicators.component').then((m) => m.IndicatorsComponent),
      },
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
    ],
  },
  { path: '**', redirectTo: 'dashboard' },
];
