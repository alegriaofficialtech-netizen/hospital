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
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { finalize } from 'rxjs/operators';
import {
  CreateInstrumentRequest,
  INSTRUMENT_STATUSES,
  Instrument,
  InstrumentItem,
  InstrumentStatus,
  VALIDATION_DIMENSIONS,
  VALIDATION_DIMENSION_LABELS,
  ValidationDimension,
  ValidationService,
  describeValidationError,
} from '../../core/api/validation.service';
import { AuthService } from '../../core/auth/auth.service';

/** Fila editable del alta: se envia tal cual salvo el peso opcional. */
interface InstrumentItemDraft {
  code: string;
  dimension: ValidationDimension;
  statement: string;
  weight: number;
}

/** Items del detalle agrupados por dimension, conservando el orden de la API. */
interface DimensionGroup {
  dimension: ValidationDimension;
  label: string;
  items: InstrumentItem[];
}

/**
 * Instrumentos de validacion (M9).
 *
 * Un instrumento es una HERRAMIENTA de medida: declara que se observa y con que
 * peso, no como resulta la observacion. El alta exige administrador de
 * plataforma y MFA acreditada (MANAGE_INSTRUMENTS); el auditor solo lee.
 */
@Component({
  selector: 'app-instruments',
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
    MatSelectModule,
    MatSnackBarModule,
    MatTableModule,
  ],
  templateUrl: './instruments.component.html',
  styleUrl: './instruments.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class InstrumentsComponent {
  private readonly api = inject(ValidationService);
  private readonly auth = inject(AuthService);
  private readonly snackBar = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);

  readonly instruments = signal<Instrument[]>([]);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  readonly selected = signal<Instrument | null>(null);
  readonly loadingDetail = signal(false);

  readonly showForm = signal(false);
  readonly saving = signal(false);
  readonly formError = signal<string | null>(null);

  formCode = '';
  formName = '';
  formDescription = '';
  formVersion = '1.0';
  formScaleMin = 1;
  formScaleMax = 5;
  formStatus: InstrumentStatus = 'BORRADOR';

  /** Fila inicial vacia: el alta siempre exige al menos un item. */
  readonly draftItems = signal<InstrumentItemDraft[]>([this.emptyItem()]);

  // Paridad con MANAGE_INSTRUMENTS: administrador de plataforma Y MFA.
  readonly canManage = computed(
    () => this.auth.hasAnyRole(['ROLE_PLATFORM_ADMIN']) && this.auth.mfaVerified(),
  );

  readonly statuses = INSTRUMENT_STATUSES;
  readonly dimensions = VALIDATION_DIMENSIONS;
  readonly dimensionLabels = VALIDATION_DIMENSION_LABELS;

  readonly totalItems = computed(() =>
    this.instruments().reduce((sum, instrument) => sum + (instrument.item_count ?? 0), 0),
  );

  readonly displayedColumns: string[] = [
    'code',
    'name',
    'version',
    'status',
    'scale',
    'item_count',
    'actions',
  ];

  constructor() {
    this.loadData();
  }

  loadData(): void {
    this.loading.set(true);
    this.error.set(null);
    this.api
      .listInstruments()
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => this.instruments.set(res.instruments || []),
        error: (err: unknown) => this.error.set(describeValidationError(err)),
      });
  }

  selectInstrument(instrument: Instrument): void {
    this.selected.set(instrument);
    this.loadDetail(instrument.id);
  }

  loadDetail(idOrCode: string): void {
    this.loadingDetail.set(true);
    this.api
      .getInstrument(idOrCode)
      .pipe(
        finalize(() => this.loadingDetail.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => this.selected.set(res.instrument),
        error: (err: unknown) => {
          this.snackBar.open(
            `No se pudo cargar el instrumento: ${describeValidationError(err)}`,
            'Cerrar',
            { duration: 4500 },
          );
        },
      });
  }

  clearSelection(): void {
    this.selected.set(null);
  }

  openForm(): void {
    this.formCode = '';
    this.formName = '';
    this.formDescription = '';
    this.formVersion = '1.0';
    this.formScaleMin = 1;
    this.formScaleMax = 5;
    this.formStatus = 'BORRADOR';
    this.draftItems.set([this.emptyItem()]);
    this.formError.set(null);
    this.showForm.set(true);
  }

  cancelForm(): void {
    this.showForm.set(false);
    this.formError.set(null);
  }

  addItem(): void {
    this.draftItems.update((items) => [...items, this.emptyItem()]);
  }

  removeItem(index: number): void {
    this.draftItems.update((items) => items.filter((_, position) => position !== index));
  }

  patchItem(index: number, patch: Partial<InstrumentItemDraft>): void {
    this.draftItems.update((items) =>
      items.map((item, position) => (position === index ? { ...item, ...patch } : item)),
    );
  }

  /**
   * Validacion local de lo obvio (escala coherente, al menos un item, codigos
   * unicos). No sustituye a la API: el backend vuelve a validar todo.
   */
  saveInstrument(): void {
    const code = this.formCode.trim();
    const name = this.formName.trim();
    const version = this.formVersion.trim();
    if (
      this.formScaleMin === null ||
      this.formScaleMin === undefined ||
      this.formScaleMax === null ||
      this.formScaleMax === undefined
    ) {
      this.formError.set('La escala minima y maxima son obligatorias.');
      return;
    }
    const scaleMin = Number(this.formScaleMin);
    const scaleMax = Number(this.formScaleMax);
    const items = this.draftItems();

    if (code.length < 3) {
      this.formError.set('El codigo del instrumento debe tener al menos 3 caracteres.');
      return;
    }
    if (name.length < 3) {
      this.formError.set('El nombre del instrumento debe tener al menos 3 caracteres.');
      return;
    }
    if (!version) {
      this.formError.set('La version del instrumento es obligatoria.');
      return;
    }
    if (!Number.isInteger(scaleMin) || !Number.isInteger(scaleMax)) {
      this.formError.set('La escala minima y maxima deben ser numeros enteros.');
      return;
    }
    if (scaleMin < 0) {
      this.formError.set('La escala minima no puede ser negativa.');
      return;
    }
    if (scaleMin >= scaleMax) {
      this.formError.set('La escala minima debe ser menor que la escala maxima.');
      return;
    }
    if (items.length === 0) {
      this.formError.set('El instrumento debe declarar al menos un item de medida.');
      return;
    }

    const seen = new Set<string>();
    for (const item of items) {
      const itemCode = item.code.trim();
      if (!itemCode) {
        this.formError.set('Todos los items deben declarar un codigo.');
        return;
      }
      if (seen.has(itemCode)) {
        this.formError.set(`El codigo de item '${itemCode}' esta duplicado en el instrumento.`);
        return;
      }
      seen.add(itemCode);
      if (!item.statement.trim()) {
        this.formError.set(`El item '${itemCode}' no declara un enunciado verificable.`);
        return;
      }
      if (!Number.isFinite(Number(item.weight)) || Number(item.weight) <= 0) {
        this.formError.set(`El peso del item '${itemCode}' debe ser mayor que cero.`);
        return;
      }
    }

    const payload: CreateInstrumentRequest = {
      code,
      name,
      description: this.formDescription.trim(),
      version,
      scale_min: scaleMin,
      scale_max: scaleMax,
      status: this.formStatus,
      items: items.map((item) => ({
        code: item.code.trim(),
        dimension: item.dimension,
        statement: item.statement.trim(),
        weight: Number(item.weight),
      })),
      // synthetic no se envia: el servidor lo impone.
    };

    this.saving.set(true);
    this.formError.set(null);
    this.api
      .createInstrument(payload)
      .pipe(
        finalize(() => this.saving.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          this.snackBar.open(
            `Instrumento ${res.instrument.code} registrado con exito`,
            'Cerrar',
            { duration: 4000 },
          );
          this.showForm.set(false);
          this.selected.set(res.instrument);
          this.loadData();
        },
        error: (err: unknown) => this.formError.set(describeValidationError(err)),
      });
  }

  /** Items del detalle agrupados por dimension, en el orden que entrega la API. */
  groupedItems(): DimensionGroup[] {
    const groups: DimensionGroup[] = [];
    const index = new Map<ValidationDimension, DimensionGroup>();
    for (const item of this.selected()?.items ?? []) {
      let group = index.get(item.dimension);
      if (!group) {
        group = {
          dimension: item.dimension,
          label: VALIDATION_DIMENSION_LABELS[item.dimension] ?? item.dimension,
          items: [],
        };
        index.set(item.dimension, group);
        groups.push(group);
      }
      group.items.push(item);
    }
    return groups;
  }

  /** La API entrega segundos epoch; DatePipe espera milisegundos. */
  toDate(seconds: number | null): Date | null {
    if (seconds === null || seconds === undefined) return null;
    return new Date(Number(seconds) * 1000);
  }

  statusClass(status: InstrumentStatus): string {
    switch (status) {
      case 'ACTIVO':
        return 'st-activo';
      case 'BORRADOR':
        return 'st-borrador';
      case 'ARCHIVADO':
        return 'st-archivado';
      default:
        return '';
    }
  }

  private emptyItem(): InstrumentItemDraft {
    return { code: '', dimension: 'identidad', statement: '', weight: 1 };
  }
}
