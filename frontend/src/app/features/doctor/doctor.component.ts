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
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatListModule } from '@angular/material/list';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { finalize } from 'rxjs/operators';
import { ApiService } from '../../core/api/api.service';
import { AuthService } from '../../core/auth/auth.service';
import { ClinicalOrder } from '../../core/models';
import { OrderStatusBadgeComponent } from '../../shared/order-status-badge.component';

const MEASUREMENT_LABELS: Record<string, string> = {
  hemoglobina_g_dl: 'Hemoglobin (g/dL)',
  hematocrito_pct: 'Hematocrit (%)',
  leucocitos_mm3: 'Leukocytes (/mm³)',
  leucocitos_mil_ul: 'Leukocytes (10³/µL)',
  plaquetas_k_ul: 'Platelets (10³/µL)',
  plaquetas_mil_ul: 'Platelets (10³/µL)',
  glucosa_mg_dl: 'Glucose (mg/dL)',
  creatinina_mg_dl: 'Creatinine (mg/dL)',
  sodio_mmol_l: 'Sodium (mmol/L)',
  potasio_mmol_l: 'Potassium (mmol/L)',
};

interface MeasurementRow {
  key: string;
  label: string;
  value: number;
}

@Component({
  selector: 'app-doctor',
  standalone: true,
  imports: [
    DatePipe,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatListModule,
    MatProgressSpinnerModule,
    MatSnackBarModule,
    OrderStatusBadgeComponent,
  ],
  templateUrl: './doctor.component.html',
  styleUrl: './doctor.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DoctorComponent {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly snackBar = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);

  readonly orders = signal<ClinicalOrder[]>([]);
  readonly selectedId = signal<string | null>(null);
  readonly observations = signal('');
  readonly loading = signal(false);
  readonly validating = signal(false);
  readonly error = signal<string | null>(null);
  readonly actionError = signal<string | null>(null);
  readonly mfaVerified = this.auth.mfaVerified;
  readonly demoAuth = this.auth.isDemoAuth;

  readonly selected = computed(
    () => this.orders().find((order) => order.order_id === this.selectedId()) ?? null,
  );
  readonly measurements = computed<MeasurementRow[]>(() => {
    const order = this.selected();
    if (!order) {
      return [];
    }
    return Object.entries(order.measurements).map(([key, value]) => ({
      key,
      label: MEASUREMENT_LABELS[key] ?? key.replace(/_/g, ' '),
      value,
    }));
  });

  constructor() {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.api
      .listOrders()
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (response) => {
          const analyzed = response.orders.filter((order) => order.status === 'ANALYZED');
          this.orders.set(analyzed);
          if (this.selectedId() && !analyzed.some((order) => order.order_id === this.selectedId())) {
            this.selectedId.set(null);
          }
        },
        error: (error: unknown) => this.error.set(this.describeError(error)),
      });
  }

  select(order: ClinicalOrder): void {
    this.selectedId.set(order.order_id);
    this.observations.set(order.observations ?? '');
    this.actionError.set(null);
  }

  simulateMfa(): void {
    if (!this.demoAuth()) {
      return;
    }
    this.auth.markMfaVerified();
    this.snackBar.open('Synthetic MFA verification recorded for this session.', 'Dismiss', {
      duration: 3500,
    });
  }

  onObservationsInput(event: Event): void {
    this.observations.set((event.target as HTMLTextAreaElement).value);
  }

  validate(): void {
    const order = this.selected();
    if (!order || !this.mfaVerified() || this.validating()) {
      return;
    }

    this.validating.set(true);
    this.actionError.set(null);
    this.api
      .validateOrder({ order_id: order.order_id, observations: this.observations() })
      .pipe(
        finalize(() => this.validating.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (response) => {
          this.snackBar.open(response.message, 'Dismiss', { duration: 4500 });
          this.selectedId.set(null);
          this.observations.set('');
          this.load();
        },
        error: (error: unknown) => this.actionError.set(this.describeError(error)),
      });
  }

  private describeError(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      const body = error.error as { message?: string } | null;
      return body?.message ?? `Request failed with status ${error.status}.`;
    }
    return 'The request could not be completed.';
  }
}
