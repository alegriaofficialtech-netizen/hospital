import { HttpErrorResponse } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTableModule } from '@angular/material/table';
import { RouterLink } from '@angular/router';
import { forkJoin, of } from 'rxjs';
import { catchError, finalize } from 'rxjs/operators';
import { ApiService } from '../../core/api/api.service';
import {
  Alert,
  Incident,
  Indicator,
  MonitoringService,
} from '../../core/api/monitoring.service';
import { AuditEventsResponse, ClinicalOrder, DashboardMetrics } from '../../core/models';
import { AuthService } from '../../core/auth/auth.service';
import { OrderStatusBadgeComponent } from '../../shared/order-status-badge.component';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [
    DatePipe,
    MatButtonModule,
    MatCardModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatTableModule,
    RouterLink,
    OrderStatusBadgeComponent,
  ],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DashboardComponent {
  private readonly api = inject(ApiService);
  private readonly monitoringApi = inject(MonitoringService);
  private readonly auth = inject(AuthService);
  private readonly destroyRef = inject(DestroyRef);

  readonly orders = signal<ClinicalOrder[]>([]);
  readonly audit = signal<AuditEventsResponse | null>(null);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  // Monitorizacion de seguridad (F4). null = no consultado por falta de permiso
  // o porque la API no respondio: la seccion no inventa cifras.
  readonly incidents = signal<Incident[] | null>(null);
  readonly alerts = signal<Alert[] | null>(null);
  readonly indicators = signal<Indicator[] | null>(null);

  readonly isAuditor = computed(() => this.auth.hasAnyRole(['ROLE_SECURITY_AUDITOR']));
  readonly canViewOrders = computed(() =>
    this.auth.hasAnyRole(['ROLE_RECEPTION', 'ROLE_LAB_TECH', 'ROLE_PATHOLOGIST']),
  );

  // Paridad con VIEW_INCIDENTS / VIEW_ALERTS: auditor de seguridad y
  // administrador de plataforma. VIEW_INDICATORS: todos los roles.
  readonly canViewIncidents = computed(() =>
    this.auth.hasAnyRole(['ROLE_SECURITY_AUDITOR', 'ROLE_PLATFORM_ADMIN']),
  );
  readonly canViewAlerts = computed(() =>
    this.auth.hasAnyRole(['ROLE_SECURITY_AUDITOR', 'ROLE_PLATFORM_ADMIN']),
  );
  readonly canViewIndicators = computed(() =>
    this.auth.hasAnyRole([
      'ROLE_RECEPTION',
      'ROLE_LAB_TECH',
      'ROLE_PATHOLOGIST',
      'ROLE_SECURITY_AUDITOR',
      'ROLE_PLATFORM_ADMIN',
    ]),
  );
  readonly canViewMonitoring = computed(
    () => this.canViewIncidents() || this.canViewAlerts() || this.canViewIndicators(),
  );

  readonly metrics = computed<DashboardMetrics>(() => {
    const orders = this.orders();
    const audit = this.audit();
    return {
      totalOrders: orders.length,
      pendingValidation: orders.filter((order) => order.status === 'ANALYZED').length,
      released: orders.filter((order) => order.status === 'VALIDATED_AND_RELEASED').length,
      auditChainValid: audit?.audit_chain_valid ?? null,
      auditEvents: audit?.total_events ?? 0,
    };
  });
  readonly recentOrders = computed(() =>
    [...this.orders()]
      .sort((left, right) => right.created_at.localeCompare(left.created_at))
      .slice(0, 6),
  );
  readonly displayedColumns = ['order', 'patient', 'test', 'status', 'created'];

  /** Incidentes ABIERTO o EN_INVESTIGACION; null si no se consultaron. */
  readonly openIncidents = computed<number | null>(() => {
    const list = this.incidents();
    if (list === null) return null;
    return list.filter(
      (incident) => incident.status === 'ABIERTO' || incident.status === 'EN_INVESTIGACION',
    ).length;
  });

  /** Alertas derivadas que siguen sin acuse; null si no se consultaron. */
  readonly unacknowledgedAlerts = computed<number | null>(() => {
    const list = this.alerts();
    if (list === null) return null;
    return list.filter((alert) => !alert.acknowledged).length;
  });

  /** Los tres indicadores con peor estado, segun el estado que declara la API. */
  readonly worstIndicators = computed<Indicator[]>(() => {
    const list = this.indicators() ?? [];
    return [...list]
      .sort((left, right) => this.indicatorRank(left) - this.indicatorRank(right))
      .slice(0, 3);
  });

  constructor() {
    this.load();
  }

  refresh(): void {
    this.load();
  }

  auditChainLabel(): string {
    if (!this.isAuditor()) {
      return 'Restringido';
    }
    const audit = this.audit();
    if (!audit) {
      return 'Pendiente';
    }
    return audit.audit_chain_valid ? 'Válida' : 'Inválida';
  }

  /** Valor de un indicador con su unidad; null se muestra como "sin dato". */
  indicatorValue(indicator: Indicator): string {
    if (indicator.value === null || indicator.value === undefined) {
      return 'sin dato';
    }
    const unit = indicator.unit;
    if (!unit) {
      return String(indicator.value);
    }
    return unit === '%' ? `${indicator.value}%` : `${indicator.value} ${unit}`;
  }

  indicatorStatusColor(indicator: Indicator): string {
    switch (indicator.status) {
      case 'OK':
        return '#146c2e';
      case 'ATENCION':
        return '#9a5b00';
      case 'CRITICO':
        return '#b3261e';
      default:
        return 'inherit';
    }
  }

  private indicatorRank(indicator: Indicator): number {
    switch (indicator.status) {
      case 'CRITICO':
        return 0;
      case 'ATENCION':
        return 1;
      case 'OK':
        return 2;
      default:
        return 3;
    }
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    const orders$ = this.canViewOrders() ? this.api.listOrders() : of(null);
    const audit$ = this.isAuditor() ? this.api.getAuditEvents() : of(null);
    // La monitorizacion no debe romper el panel clinico: cada consulta fallida
    // se degrada a null y su bloque queda sin cifra.
    const incidents$ = this.canViewIncidents()
      ? this.monitoringApi.listIncidents().pipe(catchError(() => of(null)))
      : of(null);
    const alerts$ = this.canViewAlerts()
      ? this.monitoringApi.listAlerts().pipe(catchError(() => of(null)))
      : of(null);
    const indicators$ = this.canViewIndicators()
      ? this.monitoringApi.listIndicators().pipe(catchError(() => of(null)))
      : of(null);

    forkJoin({
      orders: orders$,
      audit: audit$,
      incidents: incidents$,
      alerts: alerts$,
      indicators: indicators$,
    })
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: ({ orders, audit, incidents, alerts, indicators }) => {
          this.orders.set(orders?.orders ?? []);
          this.audit.set(audit);
          this.incidents.set(incidents?.incidents ?? null);
          this.alerts.set(alerts?.alerts ?? null);
          this.indicators.set(indicators?.indicators ?? null);
        },
        error: (error: unknown) => {
          this.error.set(this.describeError(error));
        },
      });
  }

  private describeError(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      const body = error.error as { message?: string } | null;
      return body?.message ?? `La solicitud falló con el estado ${error.status}.`;
    }
    return 'No se pudo cargar el panel clínico.';
  }
}
