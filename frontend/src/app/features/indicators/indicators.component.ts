import { DecimalPipe } from '@angular/common';
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
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { forkJoin, of } from 'rxjs';
import { finalize } from 'rxjs/operators';
import { ApiService } from '../../core/api/api.service';
import { AuthService } from '../../core/auth/auth.service';
import { RisksService, RiskSummary } from '../../core/api/risks.service';
import { ControlsService, ControlSummary } from '../../core/api/controls.service';
import {
  AuditEventsResponse,
  ClinicalOrder,
  ORDER_STATUSES,
  OrderStatus,
  orderStatusSlug,
} from '../../core/models';
import { OrderStatusPipe } from '../../shared/order-status.pipe';

interface StatusSlice {
  status: OrderStatus;
  count: number;
  percent: number;
  slug: string;
}

interface DailyVolume {
  date: string;
  count: number;
  height: number;
}

@Component({
  selector: 'app-indicators',
  standalone: true,
  imports: [
    DecimalPipe,
    MatButtonModule,
    MatCardModule,
    MatIconModule,
    MatProgressBarModule,
    MatProgressSpinnerModule,
    OrderStatusPipe,
  ],
  templateUrl: './indicators.component.html',
  styleUrl: './indicators.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class IndicatorsComponent {
  private readonly api = inject(ApiService);
  private readonly risksApi = inject(RisksService);
  private readonly controlsApi = inject(ControlsService);
  private readonly auth = inject(AuthService);
  private readonly destroyRef = inject(DestroyRef);

  readonly orders = signal<ClinicalOrder[]>([]);
  readonly audit = signal<AuditEventsResponse | null>(null);
  readonly riskSummary = signal<RiskSummary | null>(null);
  readonly controlSummary = signal<ControlSummary | null>(null);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  readonly isAuditorOrAdmin = computed(() =>
    this.auth.hasAnyRole(['ROLE_SECURITY_AUDITOR', 'ROLE_PLATFORM_ADMIN']),
  );
  readonly isAuditor = computed(() => this.auth.hasAnyRole(['ROLE_SECURITY_AUDITOR']));
  readonly canViewOrders = computed(() =>
    this.auth.hasAnyRole(['ROLE_RECEPTION', 'ROLE_LAB_TECH', 'ROLE_PATHOLOGIST']),
  );
  readonly totalOrders = computed(() => this.orders().length);
  readonly analyzedCount = computed(
    () => this.orders().filter((order) => order.status === 'ANALYZED').length,
  );
  readonly releasedCount = computed(
    () => this.orders().filter((order) => order.status === 'VALIDATED_AND_RELEASED').length,
  );
  readonly validationRate = computed(() => {
    const total = this.totalOrders();
    return total === 0 ? 0 : Math.round((this.releasedCount() / total) * 100);
  });
  readonly auditEvents = computed(() => this.audit()?.total_events ?? null);

  readonly statusDistribution = computed<StatusSlice[]>(() => {
    const orders = this.orders();
    const total = orders.length;
    return ORDER_STATUSES.map((status) => {
      const count = orders.filter((order) => order.status === status).length;
      return {
        status,
        count,
        percent: total === 0 ? 0 : Math.round((count / total) * 100),
        slug: orderStatusSlug(status),
      };
    });
  });

  readonly dailyVolume = computed<DailyVolume[]>(() => {
    const counts = new Map<string, number>();
    for (const order of this.orders()) {
      const date = order.created_at.slice(0, 10);
      counts.set(date, (counts.get(date) ?? 0) + 1);
    }
    const entries = Array.from(counts.entries()).sort(([left], [right]) =>
      left.localeCompare(right),
    );
    const max = Math.max(1, ...entries.map(([, count]) => count));
    return entries.map(([date, count]) => ({
      date,
      count,
      height: Math.max(8, Math.round((count / max) * 100)),
    }));
  });

  constructor() {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    const orders$ = this.canViewOrders() ? this.api.listOrders() : of(null);
    const audit$ = this.isAuditor() ? this.api.getAuditEvents() : of(null);
    const risks$ = this.isAuditorOrAdmin() ? this.risksApi.getSummary() : of(null);
    const controls$ = this.isAuditorOrAdmin() ? this.controlsApi.getSummary() : of(null);

    forkJoin({ orders: orders$, audit: audit$, risks: risks$, controls: controls$ })
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: ({ orders, audit, risks, controls }) => {
          this.orders.set(orders?.orders ?? []);
          this.audit.set(audit);
          this.riskSummary.set(risks);
          this.controlSummary.set(controls);
        },
        error: (error: unknown) => this.error.set(this.describeError(error)),
      });
  }

  private describeError(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      const body = error.error as { message?: string } | null;
      return body?.message ?? `Request failed with status ${error.status}.`;
    }
    return 'No se pudieron calcular los indicadores.';
  }
}
