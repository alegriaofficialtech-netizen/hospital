import { HttpErrorResponse } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTableModule } from '@angular/material/table';
import { forkJoin, of } from 'rxjs';
import { finalize } from 'rxjs/operators';
import { ApiService } from '../../core/api/api.service';
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
    OrderStatusBadgeComponent,
  ],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DashboardComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly destroyRef = inject(DestroyRef);

  readonly orders = signal<ClinicalOrder[]>([]);
  readonly audit = signal<AuditEventsResponse | null>(null);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  readonly isAuditor = computed(() => this.auth.hasAnyRole(['ROLE_SECURITY_AUDITOR']));
  readonly canViewOrders = computed(() =>
    this.auth.hasAnyRole(['ROLE_RECEPTION', 'ROLE_LAB_TECH', 'ROLE_PATHOLOGIST']),
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

  constructor() {
    this.load();
  }

  refresh(): void {
    this.load();
  }

  auditChainLabel(): string {
    if (!this.isAuditor()) {
      return 'Restricted';
    }
    const audit = this.audit();
    if (!audit) {
      return 'Pending';
    }
    return audit.audit_chain_valid ? 'Valid' : 'Invalid';
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    const orders$ = this.canViewOrders() ? this.api.listOrders() : of(null);
    const audit$ = this.isAuditor() ? this.api.getAuditEvents() : of(null);

    forkJoin({ orders: orders$, audit: audit$ })
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: ({ orders, audit }) => {
          this.orders.set(orders?.orders ?? []);
          this.audit.set(audit);
        },
        error: (error: unknown) => {
          this.error.set(this.describeError(error));
        },
      });
  }

  private describeError(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      const body = error.error as { message?: string } | null;
      return body?.message ?? `Request failed with status ${error.status}.`;
    }
    return 'The dashboard could not be loaded.';
  }
}
