import { DatePipe } from '@angular/common';
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
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { finalize } from 'rxjs/operators';
import {
  GenerateReportRequest,
  REPORT_OBJECTIVES,
  REPORT_OBJECTIVE_LABELS,
  Report,
  ReportObjective,
  ReportSummary,
  ValidationService,
  describeValidationError,
} from '../../core/api/validation.service';
import { AuthService } from '../../core/auth/auth.service';

/**
 * Informes de evidencia (F5).
 *
 * El contenido lo construye el backend exclusivamente con filas reales: la
 * pantalla no lo redacta, no lo resume y no lo interpreta. Se muestra el
 * Markdown integro en un <pre>, junto con el codigo y el hash que prueban su
 * integridad (sha256 del contenido).
 */
@Component({
  selector: 'app-reports',
  standalone: true,
  imports: [
    DatePipe,
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatProgressSpinnerModule,
    MatSelectModule,
    MatSnackBarModule,
    MatTableModule,
  ],
  templateUrl: './reports.component.html',
  styleUrl: './reports.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ReportsComponent {
  private readonly api = inject(ValidationService);
  private readonly auth = inject(AuthService);
  private readonly snackBar = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);

  readonly reports = signal<ReportSummary[]>([]);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  readonly selected = signal<Report | null>(null);
  readonly loadingDetail = signal(false);

  readonly showForm = signal(false);
  readonly saving = signal(false);
  readonly formError = signal<string | null>(null);

  formObjective: ReportObjective = 'O1';
  formPeriodFrom = this.firstDayOfMonth();
  formPeriodTo = this.today();

  // Paridad con GENERATE_REPORTS: administrador de plataforma Y MFA.
  readonly canManage = computed(
    () => this.auth.hasAnyRole(['ROLE_PLATFORM_ADMIN']) && this.auth.mfaVerified(),
  );

  readonly objectives = REPORT_OBJECTIVES;
  readonly objectiveLabels = REPORT_OBJECTIVE_LABELS;

  readonly reportCount = computed(() => this.reports().length);
  readonly coveredObjectives = computed(() => {
    const covered = new Set<string>();
    for (const report of this.reports()) {
      covered.add(report.objective);
    }
    return covered.size;
  });

  readonly displayedColumns: string[] = [
    'code',
    'title',
    'objective',
    'period',
    'generated_at',
    'author',
    'hash',
    'actions',
  ];

  constructor() {
    this.loadData();
  }

  loadData(): void {
    this.loading.set(true);
    this.error.set(null);
    this.api
      .listReports()
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => this.reports.set(res.reports || []),
        error: (err: unknown) => this.error.set(describeValidationError(err)),
      });
  }

  openReport(report: ReportSummary): void {
    this.selected.set(null);
    this.loadingDetail.set(true);
    this.api
      .getReport(report.id)
      .pipe(
        finalize(() => this.loadingDetail.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => this.selected.set(res.report),
        error: (err: unknown) => {
          this.snackBar.open(
            `No se pudo cargar el informe: ${describeValidationError(err)}`,
            'Cerrar',
            { duration: 4500 },
          );
        },
      });
  }

  clearSelection(): void {
    this.selected.set(null);
  }

  openForm(): void {
    this.formObjective = 'O1';
    this.formPeriodFrom = this.firstDayOfMonth();
    this.formPeriodTo = this.today();
    this.formError.set(null);
    this.showForm.set(true);
  }

  cancelForm(): void {
    this.showForm.set(false);
    this.formError.set(null);
  }

  /**
   * Solo se envian objetivo y periodo. El Markdown, el codigo y el hash los
   * construye el backend; la pantalla no aporta contenido.
   */
  generateReport(): void {
    const periodFrom = this.formPeriodFrom.trim();
    const periodTo = this.formPeriodTo.trim();

    if (!periodFrom || !periodTo) {
      this.formError.set('Indique el periodo completo (desde y hasta, YYYY-MM-DD).');
      return;
    }
    if (periodFrom > periodTo) {
      this.formError.set('La fecha desde no puede ser posterior a la fecha hasta.');
      return;
    }

    const payload: GenerateReportRequest = {
      objective: this.formObjective,
      period_from: periodFrom,
      period_to: periodTo,
    };

    this.saving.set(true);
    this.formError.set(null);
    this.api
      .generateReport(payload)
      .pipe(
        finalize(() => this.saving.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          this.snackBar.open(
            `Informe ${res.report.code} generado (hash ${this.shortHash(res.report.content_hash)})`,
            'Cerrar',
            { duration: 5000 },
          );
          this.showForm.set(false);
          this.selected.set(res.report);
          this.loadData();
        },
        error: (err: unknown) => this.formError.set(describeValidationError(err)),
      });
  }

  /** Hash corto para la lista; el hash completo se muestra en el detalle. */
  shortHash(hash: string): string {
    return (hash || '').slice(0, 12);
  }

  /** La API entrega segundos epoch; DatePipe espera milisegundos. */
  toDate(seconds: number | null): Date | null {
    if (seconds === null || seconds === undefined) return null;
    return new Date(Number(seconds) * 1000);
  }

  private today(): string {
    return new Date().toISOString().slice(0, 10);
  }

  private firstDayOfMonth(): string {
    return `${this.today().slice(0, 8)}01`;
  }
}
