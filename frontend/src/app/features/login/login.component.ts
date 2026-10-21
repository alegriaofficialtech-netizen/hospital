import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { Router } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { UserRole } from '../../core/models';
import { environment } from '../../../environments/environment';

interface DemoRole {
  role: UserRole;
  label: string;
  description: string;
  icon: string;
}

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
  ],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LoginComponent {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  username = 'demo.reception';
  readonly error = signal<string | null>(null);
  readonly loading = signal(false);

  /** Reason the OIDC client could not be initialised, if that happened. */
  readonly initError = this.auth.keycloakInitError;

  /** True only in the mock profile. The real build never shows the demo block. */
  readonly isDemo = environment.useMockAuth;

  readonly demoRoles: readonly DemoRole[] = [
    {
      role: 'ROLE_RECEPTION',
      label: 'Recepción',
      description: 'Crear órdenes sintéticas',
      icon: 'assignment_ind',
    },
    {
      role: 'ROLE_LAB_TECH',
      label: 'Laboratorio',
      description: 'Revisar muestras recogidas',
      icon: 'science',
    },
    {
      role: 'ROLE_PATHOLOGIST',
      label: 'Patólogo',
      description: 'Validar con MFA simulada',
      icon: 'biotech',
    },
    {
      role: 'ROLE_SECURITY_AUDITOR',
      label: 'Auditor de seguridad',
      description: 'Inspeccionar la cadena de auditoría',
      icon: 'verified_user',
    },
  ];

  loginDemo(role: UserRole): void {
    this.error.set(null);
    this.auth.loginDemo(role, this.username);
    void this.router.navigate(['/dashboard']);
  }

  async loginWithKeycloak(): Promise<void> {
    this.error.set(null);
    this.loading.set(true);
    try {
      await this.auth.loginWithKeycloak();
      if (this.auth.isAuthenticated()) {
        await this.router.navigate(['/dashboard']);
      }
    } catch (error) {
      this.error.set(
        error instanceof Error
          ? error.message
          : 'No se pudo iniciar el acceso con Keycloak.',
      );
    } finally {
      this.loading.set(false);
    }
  }
}
