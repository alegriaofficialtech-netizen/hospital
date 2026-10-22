import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { AccountRequestService } from '../../core/api/account-request.service';

/**
 * Public account request screen.
 *
 * The account is not created here: the request is recorded in the audit trail
 * and an administrator authorizes it before creating the identity in Keycloak.
 */
@Component({
  selector: 'app-account-request',
  standalone: true,
  imports: [
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatProgressSpinnerModule,
  ],
  templateUrl: './account-request.component.html',
  styleUrls: ['./account-request.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AccountRequestComponent {
  private readonly api = inject(AccountRequestService);

  readonly fullName = signal('');
  readonly email = signal('');
  readonly justification = signal('');
  readonly submitting = signal(false);
  readonly errorMessage = signal<string | null>(null);
  readonly fieldErrors = signal<Record<string, string>>({});
  readonly confirmation = signal<string | null>(null);

  submit(): void {
    if (this.submitting()) {
      return;
    }
    this.submitting.set(true);
    this.errorMessage.set(null);
    this.fieldErrors.set({});
    this.api
      .submit({
        full_name: this.fullName().trim(),
        email: this.email().trim(),
        justification: this.justification().trim(),
      })
      .subscribe({
        next: (response) => {
          this.submitting.set(false);
          this.confirmation.set(response.request_id);
        },
        error: (error: unknown) => {
          this.submitting.set(false);
          const body = (error as { error?: { message?: string; fields?: Record<string, string> } })
            ?.error ?? {};
          this.fieldErrors.set(body.fields ?? {});
          this.errorMessage.set(
            body.message ?? 'No se pudo registrar la solicitud. Intentelo de nuevo.',
          );
        },
      });
  }
}