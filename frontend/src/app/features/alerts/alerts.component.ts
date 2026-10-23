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
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { finalize } from 'rxjs/operators';
import {
  Alert,
  AlertSeverity,
  MonitoringService,
  describeMonitoringError,
} from '../../core/api/monitoring.service';
import { AuthService } from '../../core/auth/auth.service';

/**
 * Pantalla de alertas derivadas (M6).
 *
 * Una alerta no es una fila persistida: se deriva del estado real en cada
 * consulta y solo su acuse se guarda. Por eso el acuse no elimina la alerta de
 * la lista: la marca como acusada, con autor y fecha.
 */
@Component({
  selector: 'app-alerts',
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
    MatSnackBarModule,
  ],
  templateUrl: './alerts.component.html',
  styleUrl: './alerts.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AlertsComponent {
  private readonly api = inject(MonitoringService);
  private readonly auth = inject(AuthService);
  private readonly snackBar = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);

  readonly alerts = signal<Alert[]>([]);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  /** Evidencia desplegada por id de alerta (texto literal de la API). */
  readonly expandedIds = signal<ReadonlySet<string>>(new Set<string>());

  // Acuse
  readonly showAck = signal(false);
  readonly acking = signal(false);
  readonly ackError = signal<string | null>(null);
  ackTarget: Alert | null = null;
  ackNote = '';

  // Paridad con ACK_ALERTS (backend/jwt_validator.py): administrador de
  // plataforma Y MFA acreditada. El auditor solo lee.
  readonly canAck = computed(
    () => this.auth.hasAnyRole(['ROLE_PLATFORM_ADMIN']) && this.auth.mfaVerified(),
  );

  readonly totalCount = computed(() => this.alerts().length);
  readonly pendingCount = computed(
    () => this.alerts().filter((alert) => !alert.acknowledged).length,
  );
  readonly criticalCount = computed(
    () => this.alerts().filter((alert) => alert.severity === 'CRITICA').length,
  );

  constructor() {
    this.loadData();
  }

  loadData(): void {
    this.loading.set(true);
    this.error.set(null);
    this.api
      .listAlerts()
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => this.alerts.set(res.alerts || []),
        error: (err: unknown) => this.error.set(describeMonitoringError(err)),
      });
  }

  isExpanded(alertId: string): boolean {
    return this.expandedIds().has(alertId);
  }

  toggleEvidence(alertId: string): void {
    const current = new Set(this.expandedIds());
    if (current.has(alertId)) {
      current.delete(alertId);
    } else {
      current.add(alertId);
    }
    this.expandedIds.set(current);
  }

  openAck(alert: Alert): void {
    this.ackTarget = alert;
    this.ackNote = '';
    this.ackError.set(null);
    this.showAck.set(true);
  }

  cancelAck(): void {
    this.showAck.set(false);
    this.ackTarget = null;
    this.ackNote = '';
    this.ackError.set(null);
  }

  confirmAck(): void {
    const target = this.ackTarget;
    const note = this.ackNote.trim();
    if (!target) {
      this.ackError.set('No hay una alerta seleccionada para acusar.');
      return;
    }
    if (!note) {
      this.ackError.set('La nota del acuse es obligatoria.');
      return;
    }

    this.acking.set(true);
    this.ackError.set(null);
    this.api
      .acknowledgeAlert(target.id, note)
      .pipe(
        finalize(() => this.acking.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          const ack = res.alert;
          // La alerta sigue derivandose del estado real: se actualiza en su
          // sitio con el acuse que confirmo la API, no se retira de la lista.
          this.alerts.update((list) =>
            list.map((alert) =>
              alert.id === ack.alert_id
                ? {
                    ...alert,
                    acknowledged: true,
                    acknowledged_by: ack.acknowledged_by,
                    acknowledged_at: ack.acknowledged_at,
                  }
                : alert,
            ),
          );
          this.snackBar.open(
            `Alerta ${ack.alert_id} acusada por ${ack.acknowledged_by}`,
            'Cerrar',
            { duration: 4000 },
          );
          this.showAck.set(false);
          this.ackTarget = null;
          this.ackNote = '';
        },
        error: (err: unknown) => this.ackError.set(describeMonitoringError(err)),
      });
  }

  /** La API entrega segundos epoch; DatePipe espera milisegundos. */
  toDate(seconds: number | null): Date | null {
    if (seconds === null || seconds === undefined) return null;
    return new Date(Number(seconds) * 1000);
  }

  severityClass(severity: AlertSeverity): string {
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
}
