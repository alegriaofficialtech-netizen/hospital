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
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { forkJoin, of } from 'rxjs';
import { catchError, finalize } from 'rxjs/operators';
import { Asset, AssetsService } from '../../core/api/assets.service';
import {
  CreateIncidentRequest,
  INCIDENT_SEVERITIES,
  INCIDENT_STATUSES,
  INCIDENT_TRANSITIONS,
  Incident,
  IncidentFilters,
  IncidentSeverity,
  IncidentStatus,
  IncidentUpdate,
  MonitoringService,
  TransitionIncidentRequest,
  describeMonitoringError,
} from '../../core/api/monitoring.service';
import { Risk, RisksService } from '../../core/api/risks.service';
import { AuthService } from '../../core/auth/auth.service';

/**
 * Pantalla de incidentes de seguridad (M6).
 *
 * Solo lectura para el auditor; el alta y las transiciones de estado exigen el
 * mismo criterio que la politica MANAGE_INCIDENTS del PEP: administrador de
 * plataforma Y MFA acreditada. La API sigue siendo la autoridad.
 */
@Component({
  selector: 'app-incidents',
  standalone: true,
  imports: [
    DatePipe,
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
  templateUrl: './incidents.component.html',
  styleUrl: './incidents.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class IncidentsComponent {
  private readonly api = inject(MonitoringService);
  private readonly assetsApi = inject(AssetsService);
  private readonly risksApi = inject(RisksService);
  private readonly auth = inject(AuthService);
  private readonly snackBar = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);

  readonly incidents = signal<Incident[]>([]);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  // Filtros admitidos por GET /api/v1/incidents
  readonly filterStatus = signal<IncidentStatus | null>(null);
  readonly filterSeverity = signal<IncidentSeverity | null>(null);

  // Catalogos M3 (activos) y M4 (riesgos) para el alta y para resolver vinculos
  readonly assets = signal<Asset[]>([]);
  readonly risks = signal<Risk[]>([]);
  readonly catalogsError = signal<string | null>(null);

  // Detalle e historial de transiciones (incident_updates)
  readonly selectedIncident = signal<Incident | null>(null);
  readonly updates = signal<IncidentUpdate[]>([]);
  readonly loadingDetail = signal(false);

  // Alta
  readonly showForm = signal(false);
  readonly saving = signal(false);
  readonly formError = signal<string | null>(null);
  formCode = '';
  formTitle = '';
  formDescription = '';
  formSeverity: IncidentSeverity = 'MEDIA';
  formAssetId: string | null = null;
  formRiskId: string | null = null;
  formOwnerRole = 'ROLE_SECURITY_AUDITOR';

  // Transicion de estado
  readonly showTransition = signal(false);
  readonly transitioning = signal(false);
  readonly transitionError = signal<string | null>(null);
  transitionTarget: Incident | null = null;
  transitionTo: IncidentStatus | null = null;
  transitionNote = '';

  // Vocabularios copiados del backend
  readonly severities = INCIDENT_SEVERITIES;
  readonly statuses = INCIDENT_STATUSES;

  // Paridad con MANAGE_INCIDENTS (backend/jwt_validator.py): administrador de
  // plataforma Y MFA acreditada. El auditor solo consulta, asi que no se le
  // ofrecen acciones que la API rechaza con 403.
  readonly canManage = computed(
    () => this.auth.hasAnyRole(['ROLE_PLATFORM_ADMIN']) && this.auth.mfaVerified(),
  );

  readonly totalCount = computed(() => this.incidents().length);
  readonly openCount = computed(
    () =>
      this.incidents().filter(
        (incident) => incident.status === 'ABIERTO' || incident.status === 'EN_INVESTIGACION',
      ).length,
  );
  readonly criticalCount = computed(
    () => this.incidents().filter((incident) => incident.severity === 'CRITICA').length,
  );

  readonly displayedColumns: string[] = [
    'code',
    'title',
    'severity',
    'status',
    'detected_at',
    'links',
    'actions',
  ];

  constructor() {
    this.loadData();
    this.loadCatalogs();
  }

  /**
   * Catalogos de apoyo: activos M3 y riesgos M4. Si una consulta falla la
   * pantalla sigue operativa; los selectores quedan vacios y se advierte. No se
   * completa ningun vinculo por cuenta propia.
   */
  loadCatalogs(): void {
    this.catalogsError.set(null);
    forkJoin({
      assets: this.assetsApi.listAssets().pipe(catchError(() => of(null))),
      risks: this.risksApi.listRisks().pipe(catchError(() => of(null))),
    })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: ({ assets, risks }) => {
          this.assets.set(assets?.assets ?? []);
          this.risks.set(risks?.risks ?? []);
          if (!assets || !risks) {
            this.catalogsError.set(
              'No se pudieron cargar todos los catalogos de activos y riesgos: los selectores de vinculo quedan sin opciones.',
            );
          }
        },
      });
  }

  loadData(): void {
    this.loading.set(true);
    this.error.set(null);

    const filters: IncidentFilters = {
      status: this.filterStatus(),
      severity: this.filterSeverity(),
    };

    this.api
      .listIncidents(filters)
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => this.incidents.set(res.incidents || []),
        error: (err: unknown) => this.error.set(describeMonitoringError(err)),
      });
  }

  selectIncident(incident: Incident): void {
    this.selectedIncident.set(incident);
    this.loadDetail(incident.id);
  }

  loadDetail(idOrCode: string): void {
    this.loadingDetail.set(true);
    // Se limpia el historial anterior: si la consulta falla no se mezclan las
    // transiciones de dos incidentes distintos.
    this.updates.set([]);
    this.api
      .getIncident(idOrCode)
      .pipe(
        finalize(() => this.loadingDetail.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          this.selectedIncident.set(res.incident);
          this.updates.set(res.updates || []);
        },
        error: (err: unknown) => {
          this.snackBar.open(
            `No se pudo cargar el detalle del incidente: ${describeMonitoringError(err)}`,
            'Cerrar',
            { duration: 4500 },
          );
        },
      });
  }

  clearSelection(): void {
    this.selectedIncident.set(null);
    this.updates.set([]);
  }

  openCreateForm(): void {
    this.formCode = '';
    this.formTitle = '';
    this.formDescription = '';
    this.formSeverity = 'MEDIA';
    this.formAssetId = null;
    this.formRiskId = null;
    this.formOwnerRole = 'ROLE_SECURITY_AUDITOR';
    this.formError.set(null);
    this.showForm.set(true);
  }

  cancelForm(): void {
    this.showForm.set(false);
    this.formError.set(null);
  }

  saveIncident(): void {
    const code = this.formCode.trim();
    const title = this.formTitle.trim();
    if (!code || !title) {
      this.formError.set('El codigo y el titulo del incidente son obligatorios.');
      return;
    }

    const payload: CreateIncidentRequest = {
      code,
      title,
      description: this.formDescription.trim(),
      severity: this.formSeverity,
      asset_id: this.formAssetId,
      risk_id: this.formRiskId,
      owner_role: this.formOwnerRole.trim(),
      // El estado inicial lo aplica la API (ABIERTO) y la sinteticidad tambien
      // la impone el servidor: el navegador no declara synthetic.
    };

    this.saving.set(true);
    this.formError.set(null);
    this.api
      .createIncident(payload)
      .pipe(
        finalize(() => this.saving.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          this.snackBar.open(
            `Incidente ${res.incident.code} registrado con exito`,
            'Cerrar',
            { duration: 3500 },
          );
          this.showForm.set(false);
          this.loadData();
        },
        error: (err: unknown) => this.formError.set(describeMonitoringError(err)),
      });
  }

  /** Transiciones que el backend declara validas desde el estado actual. */
  allowedTransitions(incident: Incident): readonly IncidentStatus[] {
    return INCIDENT_TRANSITIONS[incident.status] ?? [];
  }

  canTransition(incident: Incident): boolean {
    return this.canManage() && this.allowedTransitions(incident).length > 0;
  }

  openTransitionDialog(incident: Incident): void {
    this.transitionTarget = incident;
    this.transitionTo = null;
    this.transitionNote = '';
    this.transitionError.set(null);
    this.showTransition.set(true);
  }

  cancelTransitionDialog(): void {
    this.showTransition.set(false);
    this.transitionTarget = null;
    this.transitionTo = null;
    this.transitionNote = '';
    this.transitionError.set(null);
  }

  confirmTransition(): void {
    const target = this.transitionTarget;
    const to = this.transitionTo;
    const note = this.transitionNote.trim();

    if (!target || !to) {
      this.transitionError.set('Seleccione el estado destino de la transicion.');
      return;
    }
    if (!note) {
      this.transitionError.set('La nota de la transicion es obligatoria.');
      return;
    }
    if (!this.allowedTransitions(target).includes(to)) {
      this.transitionError.set(
        `Transicion no permitida desde ${target.status} hacia ${to}.`,
      );
      return;
    }

    const payload: TransitionIncidentRequest = { to_status: to, note };
    this.transitioning.set(true);
    this.transitionError.set(null);
    this.api
      .transitionIncident(target.id, payload)
      .pipe(
        finalize(() => this.transitioning.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          // Solo se pinta el estado nuevo cuando la API lo confirma.
          this.selectedIncident.set(res.incident);
          this.snackBar.open(
            `Incidente ${res.incident.code} ahora en estado ${res.incident.status}`,
            'Cerrar',
            { duration: 3500 },
          );
          this.showTransition.set(false);
          this.transitionTarget = null;
          this.transitionTo = null;
          this.transitionNote = '';
          this.loadDetail(res.incident.id);
          this.loadData();
        },
        error: (err: unknown) => {
          // 409 INCIDENT_TRANSITION_INVALID (o cualquier rechazo): se muestra el
          // motivo y NO se toca selectedIncident ni el historial. La pantalla
          // conserva el estado que la API tiene, no el que el formulario queria.
          this.transitionError.set(describeMonitoringError(err));
        },
      });
  }

  /** Nombre del activo M3 vinculado; el id si el catalogo no lo resolvio. */
  assetLabel(incident: Incident): string {
    const id = incident.asset_id;
    if (!id) return 'Sin activo';
    return this.assets().find((asset) => asset.id === id)?.name ?? id;
  }

  /** Codigo del riesgo M4 vinculado; el id si el catalogo no lo resolvio. */
  riskLabel(incident: Incident): string {
    const id = incident.risk_id;
    if (!id) return 'Sin riesgo';
    const risk = this.risks().find((item) => item.id === id);
    return risk ? risk.code : id;
  }

  /** La API entrega segundos epoch; DatePipe espera milisegundos. */
  toDate(seconds: number | null): Date | null {
    if (seconds === null || seconds === undefined) return null;
    return new Date(Number(seconds) * 1000);
  }

  /** Fecha de cierre legible; el incidente sigue abierto si no hay closed_at. */
  closedAtLabel(incident: Incident): string {
    const closed = this.toDate(incident.closed_at);
    return closed ? closed.toLocaleString() : 'Aún abierto';
  }

  severityClass(severity: IncidentSeverity): string {
    switch (severity) {
      case 'CRITICA':
        return 'sev-critica';
      case 'ALTA':
        return 'sev-alta';
      case 'MEDIA':
        return 'sev-media';
      case 'BAJA':
        return 'sev-baja';
      default:
        return '';
    }
  }

  statusClass(status: IncidentStatus): string {
    switch (status) {
      case 'ABIERTO':
        return 'st-abierto';
      case 'EN_INVESTIGACION':
        return 'st-investigacion';
      case 'MITIGADO':
        return 'st-mitigado';
      case 'CERRADO':
        return 'st-cerrado';
      default:
        return '';
    }
  }
}
