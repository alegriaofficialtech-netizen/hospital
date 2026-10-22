import { DatePipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  input,
  signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { firstValueFrom, forkJoin } from 'rxjs';
import { finalize } from 'rxjs/operators';
import { AuthService } from '../../core/auth/auth.service';
import {
  DiagnosticChecker,
  DiagnosticRun,
  DiagnosticsService,
  DiagnosticsSummary,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  FindingFilters,
  FindingSeverity,
  FindingStatus,
  SecurityFinding,
} from '../../core/api/diagnostics.service';

/** Reparto de un indicador de la API: clave tecnica y valor. */
interface BreakdownEntry {
  key: string;
  value: number;
}

/**
 * Evidencia completa de un hallazgo.
 *
 * Se muestra entera: el comando que produjo el hallazgo, su salida y la
 * remediacion propuesta. Es la parte que sostiene el diagnostico.
 */
@Component({
  selector: 'app-finding-evidence',
  standalone: true,
  imports: [MatIconModule],
  template: `
    <div class="evidence">
      <div class="evidence-block">
        <span class="evidence-label">
          <mat-icon>terminal</mat-icon>
          Comando que produjo la evidencia
        </span>
        @if (finding().evidence_command) {
          <pre class="evidence-command"><code>{{ finding().evidence_command }}</code></pre>
        } @else {
          <p class="evidence-empty">El hallazgo no trae comando asociado.</p>
        }
      </div>

      <div class="evidence-block">
        <span class="evidence-label">
          <mat-icon>receipt_long</mat-icon>
          Salida del comando
        </span>
        @if (finding().evidence_output) {
          <pre class="evidence-output">{{ finding().evidence_output }}</pre>
        } @else {
          <p class="evidence-empty">El hallazgo no trae salida asociada.</p>
        }
      </div>

      <div class="evidence-block">
        <span class="evidence-label">
          <mat-icon>build</mat-icon>
          Remediación
        </span>
        @if (finding().remediation) {
          <p class="evidence-remediation">{{ finding().remediation }}</p>
        } @else {
          <p class="evidence-empty">El hallazgo no trae remediación asociada.</p>
        }
      </div>
    </div>
  `,
  styles: [
    `
      .evidence {
        display: grid;
        gap: 0.9rem;
        padding: 0.25rem 0 0.5rem;
      }

      .evidence-block {
        display: grid;
        gap: 0.35rem;
      }

      .evidence-label {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        color: var(--mat-sys-on-surface-variant);
        font: var(--mat-sys-label-medium);
      }

      .evidence-label .mat-icon {
        font-size: 1.1rem;
        width: 1.1rem;
        height: 1.1rem;
      }

      .evidence-command,
      .evidence-output {
        margin: 0;
        padding: 0.65rem 0.8rem;
        border-radius: 0.5rem;
        border: 1px solid var(--mat-sys-outline-variant);
        background: var(--mat-sys-surface-container-highest);
        color: var(--mat-sys-on-surface);
        font: var(--mat-sys-body-small);
        white-space: pre-wrap;
        word-break: break-word;
        overflow-wrap: anywhere;
      }

      .evidence-command {
        white-space: pre-wrap;
      }

      .evidence-output {
        max-height: 22rem;
        overflow: auto;
      }

      .evidence-remediation {
        margin: 0;
        line-height: 1.55;
        font: var(--mat-sys-body-medium);
      }

      .evidence-empty {
        margin: 0;
        color: var(--mat-sys-on-surface-variant);
        font: var(--mat-sys-body-small);
      }
    `,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class FindingEvidenceComponent {
  readonly finding = input.required<SecurityFinding>();
}

/**
 * Pantalla M2: diagnostico de seguridad del laboratorio F11.
 *
 * Muestra los hallazgos con su evidencia completa (el comando que lo produjo y
 * su salida), el historial de ejecuciones y los indicadores del resumen. La
 * ejecucion del diagnostico solo se ofrece al administrador de plataforma con
 * MFA acreditada; cuando no procede se explica el motivo en vez de dejar un
 * boton inerte sin explicacion.
 */
@Component({
  selector: 'app-diagnostics',
  standalone: true,
  imports: [
    DatePipe,
    FindingEvidenceComponent,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatFormFieldModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatSelectModule,
    MatSnackBarModule,
    MatTableModule,
  ],
  templateUrl: './diagnostics.component.html',
  styleUrl: './diagnostics.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DiagnosticsComponent {
  private readonly api = inject(DiagnosticsService);
  private readonly auth = inject(AuthService);
  private readonly snackBar = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);

  /** Entorno declarado por la API; el laboratorio F11 se identifica como f11-local. */
  readonly environment = signal('f11-local');

  readonly checkers = signal<DiagnosticChecker[]>([]);
  readonly runs = signal<DiagnosticRun[]>([]);
  readonly findings = signal<SecurityFinding[]>([]);
  readonly findingsTotal = signal(0);
  readonly summary = signal<DiagnosticsSummary | null>(null);

  readonly loading = signal(false);
  readonly findingsLoading = signal(false);
  readonly running = signal(false);
  readonly error = signal<string | null>(null);

  readonly statusFilter = signal<FindingStatus | 'ALL'>('ALL');
  readonly severityFilter = signal<FindingSeverity | 'ALL'>('ALL');
  readonly objectiveFilter = signal('ALL');

  readonly selectedRunId = signal<string | null>(null);
  readonly selectedRun = signal<DiagnosticRun | null>(null);
  readonly selectedRunFindings = signal<SecurityFinding[]>([]);
  readonly runLoading = signal(false);
  readonly runError = signal<string | null>(null);

  readonly expandedFindingId = signal<string | null>(null);

  /** Limite de hallazgos que se piden a la API. */
  readonly findingsLimit = 100;

  readonly statuses = FINDING_STATUSES;
  readonly severities = FINDING_SEVERITIES;

  readonly findingColumns = [
    'severity',
    'status',
    'objective',
    'checker',
    'title',
    'asset',
    'detected',
    'evidence',
  ];
  readonly runColumns = [
    'started',
    'finished',
    'triggered',
    'status',
    'passed',
    'failed',
    'warnings',
    'notes',
    'actions',
  ];
  readonly checkerStateColumns = ['checker', 'title', 'objective', 'status'];
  readonly checkerColumns = ['id', 'title', 'objective', 'severity', 'description'];

  /** La ejecucion del diagnostico es una accion sensible: administrador con MFA. */
  readonly canRun = computed(
    () => this.auth.hasAnyRole(['ROLE_PLATFORM_ADMIN']) && this.auth.mfaVerified(),
  );

  /** Motivo por el que la ejecucion no esta disponible, si no lo esta. */
  readonly runBlockedReason = computed(() => {
    if (this.canRun()) {
      return null;
    }
    if (!this.auth.hasAnyRole(['ROLE_PLATFORM_ADMIN'])) {
      return 'La ejecucion del diagnostico esta reservada al administrador de plataforma.';
    }
    return 'La ejecucion del diagnostico exige MFA acreditada en esta sesion.';
  });

  /** Objetivos presentes en la API: resumen, catalogo y hallazgos. */
  readonly objectiveOptions = computed(() => {
    const fromSummary = Object.keys(this.summary()?.by_objective ?? {});
    const fromCheckers = this.checkers().map((checker) => checker.objective);
    const fromFindings = this.findings().map((finding) => finding.objective);
    return Array.from(
      new Set([...fromSummary, ...fromCheckers, ...fromFindings].filter((value) => !!value)),
    ).sort();
  });

  readonly statusBreakdown = computed(() => this.toBreakdown(this.summary()?.by_status));
  readonly severityBreakdown = computed(() => this.toBreakdown(this.summary()?.by_severity));
  readonly objectiveBreakdown = computed(() => this.toBreakdown(this.summary()?.by_objective));
  readonly checkerStates = computed(() => this.summary()?.by_checker ?? []);
  readonly lastRun = computed(() => this.summary()?.last_run ?? null);

  /** Si hay algun filtro activo sobre los hallazgos. */
  readonly hasActiveFilters = computed(
    () =>
      this.statusFilter() !== 'ALL' ||
      this.severityFilter() !== 'ALL' ||
      this.objectiveFilter() !== 'ALL',
  );

  constructor() {
    this.load();
  }

  /** Carga comprobadores, ejecuciones, hallazgos e indicadores. */
  load(): void {
    this.loading.set(true);
    this.error.set(null);
    forkJoin({
      checkers: this.api.listCheckers(),
      runs: this.api.listRuns(20),
      findings: this.api.listFindings(this.buildFilters()),
      summary: this.api.summary(),
    })
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (payload) => {
          this.checkers.set(payload.checkers);
          this.runs.set(payload.runs);
          this.findings.set(payload.findings.findings);
          this.findingsTotal.set(payload.findings.total);
          this.summary.set(payload.summary);
          this.captureEnvironment(payload.summary.environment);
        },
        error: (error: unknown) => this.fail(error),
      });
  }

  /** Vuelve a pedir los hallazgos con los filtros activos. */
  private loadFindings(showSpinner: boolean): void {
    if (showSpinner) {
      this.findingsLoading.set(true);
    }
    this.api
      .listFindings(this.buildFilters())
      .pipe(
        finalize(() => this.findingsLoading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (response) => {
          this.findings.set(response.findings);
          this.findingsTotal.set(response.total);
          this.captureEnvironment(response.environment);
        },
        error: (error: unknown) => this.fail(error),
      });
  }

  setStatusFilter(value: FindingStatus | 'ALL'): void {
    this.statusFilter.set(value);
    this.loadFindings(true);
  }

  setSeverityFilter(value: FindingSeverity | 'ALL'): void {
    this.severityFilter.set(value);
    this.loadFindings(true);
  }

  setObjectiveFilter(value: string): void {
    this.objectiveFilter.set(value);
    this.loadFindings(true);
  }

  /** Ejecuta el diagnostico completo y refresca hallazgos, historial e indicadores. */
  async runDiagnostics(): Promise<void> {
    if (!this.canRun() || this.running()) {
      return;
    }
    this.running.set(true);
    this.error.set(null);
    try {
      const result = await firstValueFrom(this.api.runDiagnostics(null));
      this.selectedRunId.set(result.run.id);
      this.selectedRun.set(result.run);
      this.selectedRunFindings.set(result.findings);
      this.captureEnvironment(result.environment);
      await this.refreshAfterRun();
      this.notify(`Diagnostico ejecutado: ${result.run.id}.`);
    } catch (error) {
      this.fail(error);
    } finally {
      this.running.set(false);
    }
  }

  /** Muestra los hallazgos de una ejecucion concreta. */
  async selectRun(runId: string): Promise<void> {
    this.selectedRunId.set(runId);
    this.runLoading.set(true);
    this.runError.set(null);
    try {
      const detail = await firstValueFrom(this.api.getRun(runId));
      this.selectedRun.set(detail.run);
      this.selectedRunFindings.set(detail.findings);
      this.captureEnvironment(detail.environment);
    } catch (error) {
      this.selectedRun.set(null);
      this.selectedRunFindings.set([]);
      this.runError.set(this.describe(error));
    } finally {
      this.runLoading.set(false);
    }
  }

  clearRunSelection(): void {
    this.selectedRunId.set(null);
    this.selectedRun.set(null);
    this.selectedRunFindings.set([]);
    this.runError.set(null);
  }

  /** Expande o contrae la evidencia de un hallazgo de la tabla. */
  toggleEvidence(findingId: string): void {
    this.expandedFindingId.update((current) => (current === findingId ? null : findingId));
  }

  isRowExpanded(row: SecurityFinding): boolean {
    return this.expandedFindingId() === row.id;
  }

  /** Convierte la marca de tiempo de la API (segundos epoch) en milisegundos. */
  toDate(value: number | string | null | undefined): number | null {
    if (value === null || value === undefined || value === '') {
      return null;
    }
    if (typeof value === 'number') {
      return Number.isFinite(value) ? value * 1000 : null;
    }
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }

  private async refreshAfterRun(): Promise<void> {
    const [runs, findings, summary] = await Promise.all([
      firstValueFrom(this.api.listRuns(20)),
      firstValueFrom(this.api.listFindings(this.buildFilters())),
      firstValueFrom(this.api.summary()),
    ]);
    this.runs.set(runs);
    this.findings.set(findings.findings);
    this.findingsTotal.set(findings.total);
    this.summary.set(summary);
    this.captureEnvironment(summary.environment);
  }

  private buildFilters(): FindingFilters {
    const status = this.statusFilter();
    const severity = this.severityFilter();
    const objective = this.objectiveFilter();
    return {
      status: status === 'ALL' ? null : status,
      severity: severity === 'ALL' ? null : severity,
      objective: objective === 'ALL' ? null : objective,
      limit: this.findingsLimit,
    };
  }

  private captureEnvironment(value: string | undefined): void {
    if (value) {
      this.environment.set(value);
    }
  }

  private toBreakdown(source: Record<string, number> | null | undefined): BreakdownEntry[] {
    if (!source) {
      return [];
    }
    return Object.entries(source).map(([key, value]) => ({ key, value: Number(value) }));
  }

  private fail(error: unknown): void {
    const message = this.describe(error);
    this.error.set(message);
    this.notify(message);
  }

  private notify(message: string): void {
    this.snackBar.open(message, 'Cerrar', { duration: 7000 });
  }

  private describe(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      const body = error.error as { message?: string; code?: string } | null;
      const code = body?.code ? ` (${body.code})` : '';
      return `${body?.message ?? `La peticion fallo con el estado ${error.status}.`}${code}`;
    }
    return 'No se pudo completar la operacion.';
  }
}
