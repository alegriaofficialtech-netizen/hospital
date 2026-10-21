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
import { HttpErrorResponse } from '@angular/common/http';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatTableModule } from '@angular/material/table';
import { finalize } from 'rxjs/operators';
import { ApiService } from '../../core/api/api.service';
import { AuditEvent, AuditEventsResponse } from '../../core/models';

@Component({
  selector: 'app-audit',
  standalone: true,
  imports: [
    DatePipe,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatFormFieldModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatSelectModule,
    MatTableModule,
  ],
  templateUrl: './audit.component.html',
  styleUrl: './audit.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AuditComponent {
  private readonly api = inject(ApiService);
  private readonly destroyRef = inject(DestroyRef);

  readonly audit = signal<AuditEventsResponse | null>(null);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);
  readonly actionFilter = signal('ALL');
  readonly statusFilter = signal('ALL');
  readonly displayedColumns = [
    'timestamp',
    'action',
    'actor',
    'role',
    'status',
    'mfa',
    'ip',
    'details',
    'hash',
  ];

  readonly actions = computed(() =>
    Array.from(new Set((this.audit()?.events ?? []).map((event) => event.action))).sort(),
  );
  readonly statuses = computed(() =>
    Array.from(new Set((this.audit()?.events ?? []).map((event) => event.status))).sort(),
  );
  readonly filteredEvents = computed(() => {
    const action = this.actionFilter();
    const status = this.statusFilter();
    return (this.audit()?.events ?? []).filter(
      (event) =>
        (action === 'ALL' || event.action === action) &&
        (status === 'ALL' || event.status === status),
    );
  });

  constructor() {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.api
      .getAuditEvents()
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (response) => this.audit.set(response),
        error: (error: unknown) => this.error.set(this.describeError(error)),
      });
  }

  setActionFilter(value: string): void {
    this.actionFilter.set(value);
  }

  setStatusFilter(value: string): void {
    this.statusFilter.set(value);
  }

  isMfaVerified(event: AuditEvent): boolean {
    return event.mfa_verified === true;
  }

  private describeError(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      const body = error.error as { message?: string } | null;
      return body?.message ?? `Request failed with status ${error.status}.`;
    }
    return 'The audit trail could not be loaded.';
  }
}
