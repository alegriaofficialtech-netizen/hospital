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
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { finalize } from 'rxjs/operators';
import {
  EvidenceElement,
  EvidenceGroup,
  REPORT_OBJECTIVES,
  REPORT_OBJECTIVE_LABELS,
  ReportObjective,
  UNDECLARED_EVIDENCE_SOURCE,
  ValidationService,
  describeValidationError,
} from '../../core/api/validation.service';

/** Opcion del selector: un objetivo concreto o el inventario completo. */
type ObjectiveFilter = ReportObjective | 'ALL';

/**
 * Inventario de evidencia por objetivo (O1..O4).
 *
 * La evidencia es DERIVADA: no existe como tabla propia y desaparece si su
 * fuente desaparece. Por eso cada elemento declara `reference` (id o codigo
 * real) y `source` (la operacion real que lo produce, o 'undeclared').
 *
 * Se carga el inventario completo para poder mostrar el recuento real de los
 * cuatro objetivos; el selector solo filtra la vista, no inventa grupos.
 */
@Component({
  selector: 'app-evidence',
  standalone: true,
  imports: [
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatSelectModule,
  ],
  templateUrl: './evidence.component.html',
  styleUrl: './evidence.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class EvidenceComponent {
  private readonly api = inject(ValidationService);
  private readonly destroyRef = inject(DestroyRef);

  readonly groups = signal<EvidenceGroup[]>([]);
  readonly total = signal(0);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  readonly objective = signal<ObjectiveFilter>('ALL');
  readonly expandedKeys = signal<ReadonlySet<string>>(new Set<string>());

  readonly objectives = REPORT_OBJECTIVES;
  readonly objectiveLabels = REPORT_OBJECTIVE_LABELS;

  readonly visibleGroups = computed(() => {
    const filter = this.objective();
    const groups = this.groups();
    return filter === 'ALL'
      ? groups
      : groups.filter((group) => group.objective === filter);
  });

  readonly emptyGroups = computed(() => this.groups().filter((group) => group.empty).length);

  constructor() {
    this.loadData();
  }

  loadData(): void {
    this.loading.set(true);
    this.error.set(null);
    this.api
      .listEvidence()
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          this.groups.set(res.objectives || []);
          this.total.set(res.total ?? 0);
        },
        error: (err: unknown) => this.error.set(describeValidationError(err)),
      });
  }

  countFor(objective: ReportObjective): number {
    return this.groups().find((group) => group.objective === objective)?.count ?? 0;
  }

  declarationFor(objective: ReportObjective): 'CON_EVIDENCIA' | 'SIN_EVIDENCIA' {
    return this.groups().find((group) => group.objective === objective)?.declaration ?? 'SIN_EVIDENCIA';
  }

  /** Clave estable para desplegar el origen: objetivo + posicion en el grupo. */
  evidenceKey(group: EvidenceGroup, index: number): string {
    return `${group.objective}:${index}`;
  }

  isExpanded(group: EvidenceGroup, index: number): boolean {
    return this.expandedKeys().has(this.evidenceKey(group, index));
  }

  toggleSource(group: EvidenceGroup, index: number): void {
    const key = this.evidenceKey(group, index);
    const current = new Set(this.expandedKeys());
    if (current.has(key)) {
      current.delete(key);
    } else {
      current.add(key);
    }
    this.expandedKeys.set(current);
  }

  /** El centinela 'undeclared' se declara como limitacion, no se oculta. */
  isUndeclared(element: EvidenceElement): boolean {
    return element.source === UNDECLARED_EVIDENCE_SOURCE;
  }

  /**
   * La API puede devolver una fecha ISO completa o YYYY-MM-DD. Se muestra el
   * dia declarado tal cual, sin reinterpretar la zona horaria.
   */
  dateLabel(element: EvidenceElement): string {
    const date = element.date;
    if (!date) return 'sin fecha declarada';
    return date.length >= 10 ? date.slice(0, 10) : date;
  }

  syntheticLabel(element: EvidenceElement): string {
    if (element.synthetic === null || element.synthetic === undefined) {
      return 'sinteticidad no declarada';
    }
    return element.synthetic === 1 ? 'elemento sintético' : 'elemento no sintético';
  }
}
