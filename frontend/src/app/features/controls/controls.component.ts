import { DatePipe, DecimalPipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { finalize } from 'rxjs/operators';
import { AuthService } from '../../core/auth/auth.service';
import {
  CONTROL_EFFECTIVENESS_LEVELS,
  CONTROL_EVIDENCE_TYPES,
  CONTROL_FRAMEWORKS,
  CONTROL_STATUSES,
  Control,
  ControlDetailResponse,
  ControlEffectiveness,
  ControlEvidence,
  ControlEvidenceType,
  ControlFilters,
  ControlFramework,
  ControlStatus,
  ControlSummary,
  ControlsService,
  CreateControlRequest,
  UpdateControlRequest,
  VerifyControlRequest,
} from '../../core/api/controls.service';

@Component({
  selector: 'app-controls',
  standalone: true,
  imports: [
    DatePipe,
    DecimalPipe,
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatProgressBarModule,
    MatProgressSpinnerModule,
    MatSelectModule,
    MatSnackBarModule,
    MatTableModule,
  ],
  templateUrl: './controls.component.html',
  styleUrl: './controls.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ControlsComponent {
  private readonly api = inject(ControlsService);
  private readonly auth = inject(AuthService);
  private readonly snackBar = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);

  readonly controls = signal<Control[]>([]);
  readonly summary = signal<ControlSummary | null>(null);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  // Filtros
  readonly filterFramework = signal<ControlFramework | null>(null);
  readonly filterStatus = signal<ControlStatus | null>(null);
  readonly filterEffectiveness = signal<ControlEffectiveness | null>(null);

  // Seleccion de detalle
  readonly selectedControl = signal<Control | null>(null);
  readonly linkedRisks = signal<any[]>([]);
  readonly evidences = signal<ControlEvidence[]>([]);
  readonly loadingDetail = signal(false);

  // Formulario de creacion / edicion
  readonly showForm = signal(false);
  readonly formMode = signal<'create' | 'edit'>('create');
  readonly saving = signal(false);
  readonly formError = signal<string | null>(null);

  // Campos de formulario
  formCode = '';
  formFramework: ControlFramework = 'ISO_27001_2022';
  formClause = '';
  formName = '';
  formDescription = '';
  formOwnerRole = 'ROLE_PLATFORM_ADMIN';
  formStatus: ControlStatus = 'PROPUESTO';
  formEffectiveness: ControlEffectiveness = 'NO_EVALUADA';

  // Diálogo de Verificación Formal con Evidencia
  readonly showVerifyDialog = signal(false);
  readonly verifying = signal(false);
  readonly verifyError = signal<string | null>(null);
  verifyControlTarget: Control | null = null;
  verifySource = 'test_suite';
  verifyReferenceId = '';
  verifyObservedResult = '';
  verifyEvidenceType: ControlEvidenceType = 'test_suite';

  // Vocabularios
  readonly frameworks = CONTROL_FRAMEWORKS;
  readonly statuses = CONTROL_STATUSES;
  readonly effectivenessLevels = CONTROL_EFFECTIVENESS_LEVELS;
  readonly evidenceTypes = CONTROL_EVIDENCE_TYPES;

  // Paridad con la politica MANAGE_CONTROLS del PEP (backend/jwt_validator.py):
  // administrador de plataforma Y MFA acreditada. El auditor solo consulta, asi
  // que no se le ofrecen acciones que la API rechaza con 403. Ante la duda la
  // interfaz es restrictiva: la API sigue siendo la autoridad.
  readonly canManage = computed(
    () => this.auth.hasAnyRole(['ROLE_PLATFORM_ADMIN']) && this.auth.mfaVerified(),
  );

  readonly displayedColumns: string[] = [
    'code',
    'framework',
    'clause_or_pillar',
    'name',
    'status',
    'effectiveness',
    'evidence',
    'actions',
  ];

  constructor() {
    this.loadData();
  }

  loadData(): void {
    this.loading.set(true);
    this.error.set(null);

    const filters: ControlFilters = {
      framework: this.filterFramework(),
      status: this.filterStatus(),
      effectiveness: this.filterEffectiveness(),
    };

    this.api
      .listControls(filters)
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          this.controls.set(res.controls || []);
          this.summary.set(res.summary || null);
        },
        error: (err: unknown) => {
          this.error.set(this.extractError(err));
        },
      });
  }

  selectControl(control: Control): void {
    this.selectedControl.set(control);
    this.loadingDetail.set(true);
    this.api
      .getControl(control.id)
      .pipe(
        finalize(() => this.loadingDetail.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res: ControlDetailResponse) => {
          this.selectedControl.set(res.control);
          this.linkedRisks.set(res.linked_risks || []);
          this.evidences.set(res.evidences || []);
        },
        error: (err: unknown) => {
          this.snackBar.open(
            `Error al cargar detalle del control: ${this.extractError(err)}`,
            'Cerrar',
            { duration: 4000 },
          );
        },
      });
  }

  clearSelection(): void {
    this.selectedControl.set(null);
    this.linkedRisks.set([]);
    this.evidences.set([]);
  }

  openCreateForm(): void {
    this.formMode.set('create');
    this.formCode = '';
    this.formFramework = 'ISO_27001_2022';
    this.formClause = '';
    this.formName = '';
    this.formDescription = '';
    this.formOwnerRole = 'ROLE_PLATFORM_ADMIN';
    this.formStatus = 'PROPUESTO';
    this.formEffectiveness = 'NO_EVALUADA';
    this.formError.set(null);
    this.showForm.set(true);
  }

  openEditForm(control: Control): void {
    this.formMode.set('edit');
    this.formCode = control.code;
    this.formFramework = control.framework;
    this.formClause = control.clause_or_pillar;
    this.formName = control.name;
    this.formDescription = control.description;
    this.formOwnerRole = control.owner_role;
    this.formStatus = control.status;
    this.formEffectiveness = control.effectiveness;
    this.formError.set(null);
    this.selectedControl.set(control);
    this.showForm.set(true);
  }

  cancelForm(): void {
    this.showForm.set(false);
    this.formError.set(null);
  }

  saveControl(): void {
    this.saving.set(true);
    this.formError.set(null);

    if (this.formMode() === 'create') {
      const payload: CreateControlRequest = {
        code: this.formCode.trim(),
        framework: this.formFramework,
        clause_or_pillar: this.formClause.trim(),
        name: this.formName.trim(),
        description: this.formDescription.trim(),
        owner_role: this.formOwnerRole,
        status: this.formStatus,
        effectiveness: this.formEffectiveness,
        // La sinteticidad no se declara desde el navegador: la API impone
        // synthetic = 1 en el alta de controles (regla de evidencia).
      };

      this.api
        .createControl(payload)
        .pipe(
          finalize(() => this.saving.set(false)),
          takeUntilDestroyed(this.destroyRef),
        )
        .subscribe({
          next: (res) => {
            this.snackBar.open(
              `Control ${res.control.code} registrado con éxito`,
              'Cerrar',
              { duration: 3500 },
            );
            this.showForm.set(false);
            this.loadData();
          },
          error: (err: unknown) => {
            this.formError.set(this.extractError(err));
          },
        });
    } else {
      const current = this.selectedControl();
      if (!current) return;

      const payload: UpdateControlRequest = {
        framework: this.formFramework,
        clause_or_pillar: this.formClause.trim(),
        name: this.formName.trim(),
        description: this.formDescription.trim(),
        owner_role: this.formOwnerRole,
        status: this.formStatus,
        effectiveness: this.formEffectiveness,
      };

      this.api
        .updateControl(current.id, payload)
        .pipe(
          finalize(() => this.saving.set(false)),
          takeUntilDestroyed(this.destroyRef),
        )
        .subscribe({
          next: (res) => {
            this.snackBar.open(
              `Control ${res.control.code} actualizado correctamente (rev ${res.control.revision})`,
              'Cerrar',
              { duration: 3500 },
            );
            this.showForm.set(false);
            this.selectControl(res.control);
            this.loadData();
          },
          error: (err: unknown) => {
            this.formError.set(this.extractError(err));
          },
        });
    }
  }

  openVerifyDialog(control: Control): void {
    this.verifyControlTarget = control;
    this.verifySource = 'test_suite';
    this.verifyReferenceId = '';
    this.verifyObservedResult = '';
    this.verifyEvidenceType = 'test_suite';
    this.verifyError.set(null);
    this.showVerifyDialog.set(true);
  }

  cancelVerifyDialog(): void {
    this.showVerifyDialog.set(false);
    this.verifyControlTarget = null;
    this.verifyError.set(null);
  }

  confirmVerifyControl(): void {
    if (!this.verifyControlTarget) return;

    if (!this.verifyReferenceId.trim() || !this.verifyObservedResult.trim()) {
      this.verifyError.set(
        'La verificación formal exige referencia técnica identificable y resultado real observado.',
      );
      return;
    }

    this.verifying.set(true);
    this.verifyError.set(null);

    const payload: VerifyControlRequest = {
      evidence_source: this.verifySource.trim(),
      reference_id: this.verifyReferenceId.trim(),
      observed_result: this.verifyObservedResult.trim(),
      evidence_type: this.verifyEvidenceType,
    };

    this.api
      .verifyControl(this.verifyControlTarget.id, payload)
      .pipe(
        finalize(() => this.verifying.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          this.snackBar.open(
            `Control ${res.control.code} formalmente VERIFICADO con hash SHA-256`,
            'Cerrar',
            { duration: 4000 },
          );
          this.showVerifyDialog.set(false);
          this.verifyControlTarget = null;
          this.loadData();
          if (this.selectedControl()?.id === res.control.id) {
            this.selectControl(res.control);
          }
        },
        error: (err: unknown) => {
          this.verifyError.set(this.extractError(err));
        },
      });
  }

  frameworkLabel(fw: ControlFramework): string {
    switch (fw) {
      case 'ISO_27001_2022':
        return 'ISO/IEC 27001:2022';
      case 'NIST_SP_800_207':
        return 'NIST SP 800-207';
      case 'CISA_ZTM':
        return 'CISA ZTM';
      default:
        return fw;
    }
  }

  private extractError(err: unknown): string {
    if (err instanceof HttpErrorResponse) {
      if (err.status === 403) {
        const body = err.error as any;
        if (body?.code === 'MFA_AUTHENTICATION_REQUIRED') {
          return 'Operación rechazada: se requiere segundo factor (MFA TOTP) para modificar controles.';
        }
        return 'Acceso denegado: permiso insuficiente.';
      }
      if (err.status === 409) {
        return 'Conflicto: ya existe un control registrado con ese código.';
      }
      if (err.status === 400 && err.error?.fields) {
        const fields = Object.entries(err.error.fields)
          .map(([k, v]) => `${k}: ${v}`)
          .join(', ');
        return `Datos no válidos: ${fields}`;
      }
      return err.error?.message || err.message;
    }
    return String(err);
  }
}
