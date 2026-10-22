import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { Router } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { environment } from '../../../environments/environment';
import { ROLE_LABELS, UserRole } from '../../core/models';

/**
 * This screen is no longer a login form.
 *
 * The credential form lives in the Keycloak theme, which reproduces the
 * hospital design (two columns, laboratory image, "Iniciar sesion" and
 * "Solicitar cuenta"). Here only the navigation is handed over: Angular never
 * captures, transmits or stores passwords, and there is no second login screen.
 */
@Component({
  selector: 'app-login',
  standalone: true,
  imports: [MatButtonModule, MatProgressSpinnerModule],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LoginComponent implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  readonly state = signal<'redirecting' | 'error' | 'mock'>('redirecting');
  readonly errorMessage = signal<string | null>(null);

  /** Only in the development profile without Keycloak. It never holds passwords. */
  readonly isMockProfile = environment.useMockAuth;
  readonly mockRoles: readonly UserRole[] = [
    'ROLE_RECEPTION',
    'ROLE_PATHOLOGIST',
    'ROLE_SECURITY_AUDITOR',
    'ROLE_PLATFORM_ADMIN',
  ];
  readonly roleLabels = ROLE_LABELS;

  async ngOnInit(): Promise<void> {
    await this.auth.initialize();

    if (this.auth.isAuthenticated()) {
      await this.router.navigateByUrl(this.auth.homeRoute());
      return;
    }

    if (this.isMockProfile) {
      this.state.set('mock');
      return;
    }

    try {
      // keycloak-js navigates to the issuer and processes the response in /login.
      await this.auth.loginWithKeycloak();
    } catch (error) {
      this.state.set('error');
      this.errorMessage.set(
        error instanceof Error
          ? error.message
          : 'No se pudo abrir la ventana de acceso seguro.',
      );
    }
  }

  retry(): void {
    this.state.set('redirecting');
    void this.ngOnInit();
  }

  async enterMockRole(role: UserRole): Promise<void> {
    this.auth.loginDemo(role, '');
    await this.router.navigateByUrl(this.auth.homeRoute());
  }
}