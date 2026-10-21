import { Inject, Injectable } from '@angular/core';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import {
  MAT_DIALOG_DATA,
  MatDialog,
  MatDialogModule,
  MatDialogRef,
} from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { firstValueFrom } from 'rxjs';
import { AdminService, ClinicalIdentity, IdentitySummary } from '../core/api/admin.service';

interface ClinicalRole {
  name: string;
  label: string;
  description: string;
  requiresMfa: boolean;
}

@Component({
  selector: 'app-admin-users',
  standalone: true,
  imports: [
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatCheckboxModule,
    MatChipsModule,
    MatDialogModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatProgressSpinnerModule,
    MatSelectModule,
    MatSnackBarModule,
    MatTableModule,
    MatTooltipModule,
  ],
  templateUrl: './admin-users.component.html',
  styleUrl: './admin-users.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AdminUsersComponent {
  private readonly admin = inject(AdminService);
  private readonly snackBar = inject(MatSnackBar);
  private readonly dialog = inject(MatDialog);

  readonly identities = signal<ClinicalIdentity[]>([]);
  readonly summary = signal<IdentitySummary | null>(null);
  readonly roles = signal<ClinicalRole[]>([]);
  readonly loading = signal(false);
  readonly creating = signal(false);
  readonly search = signal('');

  readonly newUsername = signal('');
  readonly newRoles = signal<string[]>([]);
  readonly newRequiresMfa = signal(true);
  readonly formError = signal<string | null>(null);

  /** Roles que la interfaz puede conceder. El rol de plataforma esta excluido. */
  readonly assignableRoles: readonly ClinicalRole[] = [
    {
      name: 'admision',
      label: 'Recepción',
      description: 'Crea órdenes preanalíticas y consulta el listado.',
      requiresMfa: false,
    },
    {
      name: 'laboratorio',
      label: 'Laboratorio',
      description: 'Consulta órdenes y resultados analíticos.',
      requiresMfa: false,
    },
    {
      name: 'medico',
      label: 'Patólogo',
      description: 'Valida y libera informes, con doble factor obligatorio.',
      requiresMfa: true,
    },
    {
      name: 'auditor',
      label: 'Auditor de seguridad',
      description: 'Lee la auditoría y verifica la cadena de integridad.',
      requiresMfa: false,
    },
  ];

  readonly filtered = computed(() => {
    const term = this.search().trim().toLowerCase();
    const list = this.identities();
    if (!term) {
      return list;
    }
    return list.filter(
      (identity) =>
        identity.username.toLowerCase().includes(term) ||
        identity.realm_roles.some((role) => role.toLowerCase().includes(term)),
    );
  });

  readonly columns = ['identity', 'roles', 'mfa', 'state', 'actions'];

  constructor() {
    void this.load();
  }

  async load(): Promise<void> {
    this.loading.set(true);
    try {
      const [identities, summary] = await Promise.all([
        firstValueFrom(this.admin.listIdentities()),
        firstValueFrom(this.admin.summary()),
      ]);
      this.identities.set(identities);
      this.summary.set(summary);
    } catch (error) {
      this.notify(this.describe(error));
    } finally {
      this.loading.set(false);
    }
  }

  onSearch(value: string): void {
    this.search.set(value);
  }

  toggleRole(role: string, selected: boolean): void {
    const current = new Set(this.newRoles());
    if (selected) {
      current.add(role);
    } else {
      current.delete(role);
    }
    this.newRoles.set(Array.from(current));
  }

  isRoleSelected(role: string): boolean {
    return this.newRoles().includes(role);
  }

  validate(): string | null {
    const username = this.newUsername().trim();
    if (!username) {
      return 'Indica el nombre de la cuenta.';
    }
    if (!username.endsWith('.test')) {
      return 'Las cuentas sintéticas terminan en .test.';
    }
    if (!/^[A-Za-z0-9._-]+$/.test(username)) {
      return 'El nombre solo admite letras, dígitos, punto, guion y guion bajo.';
    }
    if (this.newRoles().length === 0) {
      return 'Selecciona al menos un rol clínico.';
    }
    return null;
  }

  async create(): Promise<void> {
    const problem = this.validate();
    this.formError.set(problem);
    if (problem) {
      return;
    }
    this.creating.set(true);
    try {
      const result = await firstValueFrom(this.admin.createIdentity({
        username: this.newUsername().trim(),
        roles: this.newRoles(),
        require_mfa: this.newRequiresMfa(),
      }));
      this.newUsername.set('');
      this.newRoles.set([]);
      await this.load();
      this.notify(
        `Cuenta creada. La credencial quedó en el servidor, en ${result.credential_file}.`,
      );
    } catch (error) {
      this.formError.set(this.describe(error));
    } finally {
      this.creating.set(false);
    }
  }

  async setEnabled(identity: ClinicalIdentity, enabled: boolean): Promise<void> {
    const action = enabled ? 'activar' : 'desactivar';
    const confirmed = await this.confirm(
      enabled ? 'Activar la cuenta' : 'Desactivar la cuenta',
      `Se va a ${action} la cuenta ${identity.username}. La cuenta no se borra: ` +
        'desactivarla conserva la evidencia de auditoria.',
    );
    if (!confirmed) {
      return;
    }
    try {
      await firstValueFrom(this.admin.setIdentityState(identity.id, { enabled }));
      await this.load();
      this.notify(`Cuenta ${action}ada.`);
    } catch (error) {
      this.notify(this.describe(error));
    }
  }

  async resetPassword(identity: ClinicalIdentity): Promise<void> {
    const confirmed = await this.confirm(
      'Restablecer la contraseña',
      `Se generará una credencial nueva para ${identity.username}. La clave no se ` +
        'muestra en el navegador: queda en un fichero protegido en el servidor.',
    );
    if (!confirmed) {
      return;
    }
    try {
      const result = await firstValueFrom(this.admin.resetPassword(identity.id));
      await this.load();
      this.notify(`Credencial nueva en ${result.credential_file}.`);
    } catch (error) {
      this.notify(this.describe(error));
    }
  }

  private confirm(title: string, message: string): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const ref = this.dialog.open<ConfirmDialogComponent, { title: string; message: string }>(
        ConfirmDialogComponent,
        { data: { title, message }, width: '460px' },
      );
      ref.afterClosed().subscribe((result) => resolve(result === true));
    });
  }

  private notify(message: string): void {
    this.snackBar.open(message, 'Cerrar', { duration: 6000 });
  }

  private describe(error: unknown): string {
    if (error && typeof error === 'object' && 'message' in error) {
      return String((error as { message: unknown }).message);
    }
    return 'No se pudo completar la operacion.';
  }
}

@Component({
  selector: 'app-confirm-dialog',
  standalone: true,
  imports: [MatButtonModule, MatCardModule, MatDialogModule, MatIconModule],
  template: `
    <mat-card class="confirm-card">
      <mat-card-content>
        <h2 class="confirm-title">{{ data.title }}</h2>
        <p class="confirm-message">{{ data.message }}</p>
      </mat-card-content>
      <mat-card-actions class="confirm-actions">
        <button mat-stroked-button type="button" (click)="dialogRef.close(false)">Cancelar</button>
        <button mat-flat-button color="primary" type="button" (click)="dialogRef.close(true)">
          Confirmar
        </button>
      </mat-card-actions>
    </mat-card>
  `,
  styles: [
    `
      .confirm-card { padding: 1.5rem; }
      .confirm-title { margin: 0 0 0.5rem; font: var(--mat-sys-title-large); }
      .confirm-message { margin: 0 0 1.25rem; color: var(--mat-sys-on-surface-variant); line-height: 1.5; }
      .confirm-actions { display: flex; justify-content: flex-end; gap: 0.5rem; padding: 0 1.5rem 1.5rem; }
    `,
  ],
})
export class ConfirmDialogComponent {
  constructor(
    public readonly dialogRef: MatDialogRef<ConfirmDialogComponent, boolean>,
    @Inject(MAT_DIALOG_DATA) public readonly data: { title: string; message: string },
  ) {}
}
