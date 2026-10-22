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
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { firstValueFrom, forkJoin, of } from 'rxjs';
import { catchError, finalize } from 'rxjs/operators';
import { AuthService } from '../../core/auth/auth.service';
import { Asset, AssetsService } from '../../core/api/assets.service';
import { DiagnosticsService, SecurityFinding } from '../../core/api/diagnostics.service';
import {
  RISK_CATEGORIES,
  RISK_LEVELS,
  RISK_STATUSES,
  RISK_TREATMENTS,
  CreateRiskRequest,
  Risk,
  RiskCategory,
  RiskFilters,
  RiskLevel,
  RiskStatus,
  RiskSummary,
  RiskTreatment,
  RisksService,
  UpdateRiskRequest,
} from '../../core/api/risks.service';
import { ControlsService, Control } from '../../core/api/controls.service';

export interface MatrixCell {
  probability: number;
  impact: number;
  score: number;
  level: RiskLevel;
  inherentCount: number;
  residualCount: number;
}

@Component({
  selector: 'app-risks',
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
    MatProgressSpinnerModule,
    MatSelectModule,
    MatSnackBarModule,
    MatTableModule,
  ],
  templateUrl: './risks.component.html',
  styleUrl: './risks.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class RisksComponent {
  private readonly api = inject(RisksService);
  private readonly controlsApi = inject(ControlsService);
  private readonly assetsApi = inject(AssetsService);
  private readonly diagnosticsApi = inject(DiagnosticsService);
  private readonly auth = inject(AuthService);
  private readonly snackBar = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);

  readonly risks = signal<Risk[]>([]);
  readonly summary = signal<RiskSummary | null>(null);
  readonly availableControls = signal<Control[]>([]);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  // Catalogos M3 y M2 para vincular el riesgo por id (trazabilidad O2)
  readonly assets = signal<Asset[]>([]);
  readonly findings = signal<SecurityFinding[]>([]);
  readonly catalogsError = signal<string | null>(null);

  // Filtros
  readonly filterCategory = signal<RiskCategory | null>(null);
  readonly filterInherentLevel = signal<RiskLevel | null>(null);
  readonly filterResidualLevel = signal<RiskLevel | null>(null);
  readonly filterTreatment = signal<RiskTreatment | null>(null);
  readonly filterStatus = signal<RiskStatus | null>(null);

  // Seleccion de detalle
  readonly selectedRisk = signal<Risk | null>(null);
  readonly linkedControls = signal<any[]>([]);
  readonly loadingDetail = signal(false);

  // Formulario de creacion / edicion
  readonly showForm = signal(false);
  readonly formMode = signal<'create' | 'edit'>('create');
  readonly saving = signal(false);
  readonly formError = signal<string | null>(null);

  // Campos de formulario
  formCode = '';
  formName = '';
  formDescription = '';
  formCategory: RiskCategory = 'software';
  formAssetId: string | null = null;
  formFindingId: string | null = null;
  formThreat = '';
  formVulnerability = '';
  formProbInherent = 3;
  formImpInherent = 3;
  formTreatment: RiskTreatment = 'MITIGAR';
  formProbResidual = 2;
  formImpResidual = 2;
  formOwnerRole = 'ROLE_PLATFORM_ADMIN';
  formStatus: RiskStatus = 'IDENTIFICADO';

  // Vinculacion de control
  readonly showLinkDialog = signal(false);
  selectedControlId = '';
  linkCoverage = 'TOTAL';
  linkNotes = '';
  linking = signal(false);

  // Vocabularios
  readonly categories = RISK_CATEGORIES;
  readonly levels = RISK_LEVELS;
  readonly treatments = RISK_TREATMENTS;
  readonly statuses = RISK_STATUSES;

  // Paridad con la politica MANAGE_RISKS del PEP (backend/jwt_validator.py):
  // administrador de plataforma Y MFA acreditada. El auditor solo consulta, asi
  // que no se le ofrecen acciones que la API rechaza con 403.
  readonly canManage = computed(
    () => this.auth.hasAnyRole(['ROLE_PLATFORM_ADMIN']) && this.auth.mfaVerified(),
  );

  readonly displayedColumns: string[] = [
    'code',
    'name',
    'category',
    'asset_name',
    'inherent_risk',
    'treatment',
    'residual_risk',
    'status',
    'actions',
  ];

  // Matriz 5x5 computada a partir de los riesgos activos
  readonly matrixGrid = computed<MatrixCell[][]>(() => {
    const list = this.risks();
    const grid: MatrixCell[][] = [];

    // Filas: Probabilidad de 5 a 1
    for (let p = 5; p >= 1; p--) {
      const row: MatrixCell[] = [];
      // Columnas: Impacto de 1 a 5
      for (let i = 1; i <= 5; i++) {
        const score = p * i;
        let level: RiskLevel = 'BAJO';
        if (score >= 15) level = 'CRITICO';
        else if (score >= 10) level = 'ALTO';
        else if (score >= 5) level = 'MEDIO';

        const inherentCount = list.filter(
          (r) => r.probability_inherent === p && r.impact_inherent === i,
        ).length;
        const residualCount = list.filter(
          (r) => r.probability_residual === p && r.impact_residual === i,
        ).length;

        row.push({
          probability: p,
          impact: i,
          score,
          level,
          inherentCount,
          residualCount,
        });
      }
      grid.push(row);
    }
    return grid;
  });

  constructor() {
    this.loadData();
    this.loadLinkableCatalogs();
  }

  /**
   * Carga los catalogos M3 (activos) y M2 (hallazgos) para los selectores.
   *
   * Son opcionales: si una consulta falla, la matriz de riesgos sigue
   * operativa, los selectores quedan vacios y el formulario lo advierte. No se
   * completa ningun vinculo por cuenta propia.
   */
  loadLinkableCatalogs(): void {
    this.catalogsError.set(null);
    forkJoin({
      assets: this.assetsApi.listAssets().pipe(catchError(() => of(null))),
      findings: this.diagnosticsApi.listFindings({ limit: 200 }).pipe(catchError(() => of(null))),
    })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: ({ assets, findings }) => {
          this.assets.set(assets?.assets ?? []);
          this.findings.set(findings?.findings ?? []);
          if (!assets || !findings) {
            this.catalogsError.set(
              'No se pudieron cargar todos los catalogos M2/M3: los vinculos opcionales quedan sin opciones.',
            );
          }
        },
      });
  }

  loadData(): void {
    this.loading.set(true);
    this.error.set(null);

    const filters: RiskFilters = {
      category: this.filterCategory(),
      inherent_level: this.filterInherentLevel(),
      residual_level: this.filterResidualLevel(),
      treatment: this.filterTreatment(),
      status: this.filterStatus(),
    };

    forkJoin({
      risksRes: this.api.listRisks(filters),
      controlsRes: this.controlsApi.listControls(),
    })
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: ({ risksRes, controlsRes }) => {
          this.risks.set(risksRes.risks || []);
          this.summary.set(risksRes.summary || null);
          this.availableControls.set(controlsRes.controls || []);
        },
        error: (err: unknown) => {
          this.error.set(this.extractError(err));
        },
      });
  }

  selectRisk(risk: Risk): void {
    this.selectedRisk.set(risk);
    this.loadingDetail.set(true);
    this.api
      .getRisk(risk.id)
      .pipe(
        finalize(() => this.loadingDetail.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          this.selectedRisk.set(res.risk);
          this.linkedControls.set(res.risk.controls ?? []);
        },
        error: (err: unknown) => {
          this.snackBar.open(
            `Error al cargar controles del riesgo: ${this.extractError(err)}`,
            'Cerrar',
            { duration: 4000 },
          );
        },
      });
  }

  clearSelection(): void {
    this.selectedRisk.set(null);
    this.linkedControls.set([]);
  }

  openCreateForm(): void {
    this.formMode.set('create');
    this.formCode = '';
    this.formName = '';
    this.formDescription = '';
    this.formCategory = 'software';
    this.formAssetId = null;
    this.formFindingId = null;
    this.formThreat = '';
    this.formVulnerability = '';
    this.formProbInherent = 3;
    this.formImpInherent = 3;
    this.formTreatment = 'MITIGAR';
    this.formProbResidual = 2;
    this.formImpResidual = 2;
    this.formOwnerRole = 'ROLE_PLATFORM_ADMIN';
    this.formStatus = 'IDENTIFICADO';
    this.formError.set(null);
    this.showForm.set(true);
  }

  openEditForm(risk: Risk): void {
    this.formMode.set('edit');
    this.formCode = risk.code;
    this.formName = risk.name;
    this.formDescription = risk.description;
    this.formCategory = risk.category;
    this.formAssetId = risk.asset_id ?? null;
    this.formFindingId = risk.finding_id ?? null;
    this.formThreat = risk.threat;
    this.formVulnerability = risk.vulnerability;
    this.formProbInherent = risk.probability_inherent;
    this.formImpInherent = risk.impact_inherent;
    this.formTreatment = risk.treatment;
    this.formProbResidual = risk.probability_residual || 1;
    this.formImpResidual = risk.impact_residual || 1;
    this.formOwnerRole = risk.owner_role;
    this.formStatus = risk.status;
    this.formError.set(null);
    this.selectedRisk.set(risk);
    this.showForm.set(true);
  }

  cancelForm(): void {
    this.showForm.set(false);
    this.formError.set(null);
  }

  saveRisk(): void {
    this.saving.set(true);
    this.formError.set(null);

    if (this.formMode() === 'create') {
      const payload: CreateRiskRequest = {
        code: this.formCode.trim(),
        name: this.formName.trim(),
        description: this.formDescription.trim(),
        category: this.formCategory,
        asset_id: this.formAssetId,
        finding_id: this.formFindingId,
        threat: this.formThreat.trim(),
        vulnerability: this.formVulnerability.trim(),
        probability_inherent: Number(this.formProbInherent),
        impact_inherent: Number(this.formImpInherent),
        treatment: this.formTreatment,
        probability_residual: Number(this.formProbResidual),
        impact_residual: Number(this.formImpResidual),
        owner_role: this.formOwnerRole,
        status: this.formStatus,
        // synthetic no se declara desde el navegador: la API marca todo lo que
        // crea como sintetico (regla de evidencia).
      };

      this.api
        .createRisk(payload)
        .pipe(
          finalize(() => this.saving.set(false)),
          takeUntilDestroyed(this.destroyRef),
        )
        .subscribe({
          next: (res) => {
            this.snackBar.open(
              `Riesgo ${res.risk.code} registrado con exito`,
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
      const current = this.selectedRisk();
      if (!current) return;

      const payload: UpdateRiskRequest = {
        name: this.formName.trim(),
        description: this.formDescription.trim(),
        category: this.formCategory,
        asset_id: this.formAssetId,
        finding_id: this.formFindingId,
        threat: this.formThreat.trim(),
        vulnerability: this.formVulnerability.trim(),
        probability_inherent: Number(this.formProbInherent),
        impact_inherent: Number(this.formImpInherent),
        treatment: this.formTreatment,
        probability_residual: Number(this.formProbResidual),
        impact_residual: Number(this.formImpResidual),
        owner_role: this.formOwnerRole,
        status: this.formStatus,
      };

      this.api
        .updateRisk(current.id, payload)
        .pipe(
          finalize(() => this.saving.set(false)),
          takeUntilDestroyed(this.destroyRef),
        )
        .subscribe({
          next: (res) => {
            this.snackBar.open(
              `Riesgo ${res.risk.code} actualizado correctamente (rev ${res.risk.revision})`,
              'Cerrar',
              { duration: 3500 },
            );
            this.showForm.set(false);
            this.selectRisk(res.risk);
            this.loadData();
          },
          error: (err: unknown) => {
            this.formError.set(this.extractError(err));
          },
        });
    }
  }

  openLinkDialog(): void {
    this.selectedControlId = '';
    this.linkCoverage = 'TOTAL';
    this.linkNotes = '';
    this.showLinkDialog.set(true);
  }

  cancelLinkDialog(): void {
    this.showLinkDialog.set(false);
  }

  confirmLinkControl(): void {
    const risk = this.selectedRisk();
    if (!risk || !this.selectedControlId) return;

    this.linking.set(true);
    this.api
      .linkControl(risk.id, this.selectedControlId, this.linkCoverage, this.linkNotes)
      .pipe(
        finalize(() => this.linking.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: () => {
          this.snackBar.open('Control mitigante vinculado con exito', 'Cerrar', {
            duration: 3000,
          });
          this.showLinkDialog.set(false);
          this.selectRisk(risk);
        },
        error: (err: unknown) => {
          this.snackBar.open(
            `Fallo al vincular control: ${this.extractError(err)}`,
            'Cerrar',
            { duration: 4500 },
          );
        },
      });
  }

  /** Nombre del activo M3 vinculado; el id si el catalogo aun no lo resolvio. */
  assetLabel(risk: Risk): string {
    const id = risk.asset_id ?? null;
    if (!id) return 'Sin activo asignado';
    return this.assets().find((asset) => asset.id === id)?.name ?? id;
  }

  /**
   * Hallazgo M2 vinculado resuelto por titulo, o comprobador de origen.
   *
   * Si finding_id apunta a un hallazgo real se muestra comprobador y titulo. Si
   * todavia no hay hallazgo (el diagnostico no se ejecuto), se muestra el
   * comprobador de origen declarado (source_checker) sin fingir un vinculo.
   */
  findingLabel(risk: Risk): string {
    const id = risk.finding_id ?? null;
    if (id) {
      const finding = this.findings().find((item) => item.id === id);
      return finding ? `${finding.checker_id} · ${finding.title}` : id;
    }
    const checker = risk.source_checker ?? null;
    if (checker) return `Sin hallazgo ejecutado aun - comprobador de origen: ${checker}`;
    return 'Sin hallazgo vinculado';
  }

  levelClass(level: RiskLevel): string {
    switch (level) {
      case 'CRITICO':
        return 'level-critico';
      case 'ALTO':
        return 'level-alto';
      case 'MEDIO':
        return 'level-medio';
      case 'BAJO':
        return 'level-bajo';
      default:
        return '';
    }
  }

  private extractError(err: unknown): string {
    if (err instanceof HttpErrorResponse) {
      if (err.status === 403) {
        const body = err.error as any;
        if (body?.code === 'MFA_AUTHENTICATION_REQUIRED') {
          return 'Operacion rechazada: se requiere autenticacion de segundo factor (TOTP).';
        }
        return 'Acceso denegado: rol insuficiente o privilegio protegido.';
      }
      if (err.status === 409) {
        return 'Conflicto: ya existe un registro con el mismo codigo.';
      }
      if (err.status === 400 && err.error?.fields) {
        const fields = Object.entries(err.error.fields)
          .map(([k, v]) => `${k}: ${v}`)
          .join(', ');
        return `Campos invalidos: ${fields}`;
      }
      return err.error?.message || err.message;
    }
    return String(err);
  }
}
