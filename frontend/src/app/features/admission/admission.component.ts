import { HttpErrorResponse } from '@angular/common/http';
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
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
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
import { ApiService } from '../../core/api/api.service';
import { MockDataService } from '../../core/api/mock-data.service';
import {
  ClinicalOrder,
  ORDER_STATUSES,
  ORDER_STATUS_LABELS,
  OrderStatus,
  TEST_TYPES,
} from '../../core/models';
import { OrderStatusBadgeComponent } from '../../shared/order-status-badge.component';

@Component({
  selector: 'app-admission',
  standalone: true,
  imports: [
    DatePipe,
    ReactiveFormsModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatProgressSpinnerModule,
    MatSelectModule,
    MatSnackBarModule,
    MatTableModule,
    OrderStatusBadgeComponent,
  ],
  templateUrl: './admission.component.html',
  styleUrl: './admission.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AdmissionComponent {
  private readonly api = inject(ApiService);
  private readonly mockData = inject(MockDataService);
  private readonly fb = inject(FormBuilder);
  private readonly snackBar = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);

  readonly testTypes = TEST_TYPES;
  readonly statuses = ORDER_STATUSES;
  readonly statusLabels = ORDER_STATUS_LABELS;
  readonly orders = signal<ClinicalOrder[]>([]);
  readonly loading = signal(false);
  readonly submitting = signal(false);
  readonly listError = signal<string | null>(null);
  readonly createError = signal<string | null>(null);
  readonly statusFilter = signal<'ALL' | OrderStatus>('ALL');
  readonly displayedColumns = ['order', 'patient', 'test', 'status', 'created', 'version'];

  private dniSequence = 7;

  readonly form = this.fb.nonNullable.group({
    order_id: [
      this.mockData.suggestOrderId(),
      [Validators.required, Validators.pattern(/^ORD-\d{4}-\d{4}$/)],
    ],
    patient_dni: [
      this.formatDni(this.dniSequence),
      [Validators.required, Validators.pattern(/^DEMO-\d{4}$/)],
    ],
    test_type: [TEST_TYPES[0] as string, Validators.required],
  });

  readonly filteredOrders = computed(() => {
    const filter = this.statusFilter();
    const orders = this.orders();
    return filter === 'ALL' ? orders : orders.filter((order) => order.status === filter);
  });

  constructor() {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.listError.set(null);
    this.api
      .listOrders()
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (response) => this.orders.set(response.orders),
        error: (error: unknown) => this.listError.set(this.describeError(error)),
      });
  }

  createOrder(): void {
    this.createError.set(null);
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    this.submitting.set(true);
    this.api
      .createOrder(this.form.getRawValue())
      .pipe(
        finalize(() => this.submitting.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (response) => {
          this.snackBar.open(`Order ${response.order.order_id} created.`, 'Dismiss', {
            duration: 4000,
          });
          this.resetForm();
          this.load();
        },
        error: (error: unknown) => {
          const message = this.describeError(error);
          this.createError.set(message);
          if (error instanceof HttpErrorResponse && error.status === 409) {
            this.snackBar.open('Duplicate order ID rejected.', 'Dismiss', { duration: 4000 });
          }
        },
      });
  }

  setStatusFilter(value: 'ALL' | OrderStatus): void {
    this.statusFilter.set(value);
  }

  private resetForm(): void {
    this.dniSequence += 1;
    this.form.reset({
      order_id: this.mockData.suggestOrderId(),
      patient_dni: this.formatDni(this.dniSequence),
      test_type: TEST_TYPES[0],
    });
  }

  private formatDni(sequence: number): string {
    return `DEMO-${String(sequence).padStart(4, '0')}`;
  }

  private describeError(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      const body = error.error as { message?: string; code?: string } | null;
      if (error.status === 409) {
        return body?.message ?? 'That order ID already exists.';
      }
      return body?.message ?? `Request failed with status ${error.status}.`;
    }
    return 'The request could not be completed.';
  }
}
