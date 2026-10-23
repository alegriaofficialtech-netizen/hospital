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
  EXPERT_VERDICTS,
  EXPERT_VERDICT_LABELS,
  ExpertReview,
  ExpertReviewAnswer,
  ExpertVerdict,
  Instrument,
  InstrumentItem,
  SubmitValidationRequest,
  VALIDATION_DIMENSION_LABELS,
  ValidationDimension,
  ValidationService,
  describeValidationError,
} from '../../core/api/validation.service';
import { AuthService } from '../../core/auth/auth.service';

/** Borrador de respuesta: se guarda por item_id hasta enviar el dictamen. */
interface AnswerDraft {
  itemId: string;
  itemCode: string;
  dimension: ValidationDimension;
  statement: string;
  weight: number;
  score: number | null;
  comment: string;
}

/** Respuestas del detalle agrupadas por dimension. */
interface AnswerGroup {
  dimension: ValidationDimension;
  label: string;
  answers: ExpertReviewAnswer[];
}

/**
 * Validacion por expertos (M9).
 *
 * El sistema REGISTRA el dictamen de un experto humano; no lo genera. El
 * veredicto (NO_CUMPLE / CUMPLE_PARCIALMENTE / CUMPLE) llega declarado por el
 * experto y se guarda tal cual. La puntuacion es una media ponderada
 * descriptiva: se muestra como dato auxiliar y nunca decide el veredicto.
 *
 * El registro exige administrador de plataforma y MFA acreditada
 * (SUBMIT_VALIDATION); el auditor solo lee.
 */
@Component({
  selector: 'app-validation',
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
  templateUrl: './validation.component.html',
  styleUrl: './validation.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ValidationComponent {
  private readonly api = inject(ValidationService);
  private readonly auth = inject(AuthService);
  private readonly snackBar = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);

  readonly validations = signal<ExpertReview[]>([]);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  readonly instruments = signal<Instrument[]>([]);
  readonly instrumentsError = signal<string | null>(null);

  readonly selected = signal<ExpertReview | null>(null);
  readonly loadingDetail = signal(false);

  readonly showForm = signal(false);
  readonly saving = signal(false);
  readonly formError = signal<string | null>(null);
  readonly loadingItems = signal(false);
  readonly formInstrument = signal<Instrument | null>(null);

  formInstrumentId: string | null = null;
  formExpertName = '';
  formExpertRole = '';
  formExpertAffiliation = '';
  formScope = '';
  formVerdict: ExpertVerdict | null = null;
  formObservations = '';
  formReviewedAt = this.today();

  readonly answers = signal<AnswerDraft[]>([]);

  // Paridad con SUBMIT_VALIDATION: administrador de plataforma Y MFA.
  readonly canManage = computed(
    () => this.auth.hasAnyRole(['ROLE_PLATFORM_ADMIN']) && this.auth.mfaVerified(),
  );

  /** Solo un instrumento ACTIVO admite dictamenes (lo exige la API). */
  readonly activeInstruments = computed(() =>
    this.instruments().filter((instrument) => instrument.status === 'ACTIVO'),
  );

  readonly verdicts = EXPERT_VERDICTS;
  readonly verdictLabels = EXPERT_VERDICT_LABELS;

  readonly reviewedCount = computed(() => this.validations().length);
  readonly partialCount = computed(
    () => this.validations().filter((review) => review.verdict === 'CUMPLE_PARCIALMENTE').length,
  );
  readonly notCompliantCount = computed(
    () => this.validations().filter((review) => review.verdict === 'NO_CUMPLE').length,
  );

  readonly answeredCount = computed(
    () => this.answers().filter((answer) => this.hasScore(answer)).length,
  );

  /**
   * Vista previa DESCRIPTIVA: misma media ponderada que calcula el backend,
   * sobre las respuestas ya emitidas. No es el veredicto ni lo sugiere.
   */
  readonly previewScore = computed<number | null>(() => {
    const answered = this.answers().filter((answer) => this.hasScore(answer));
    if (answered.length === 0) return null;
    let totalWeight = 0;
    let accumulated = 0;
    for (const answer of answered) {
      const weight = Number(answer.weight) || 1;
      totalWeight += weight;
      accumulated += Number(answer.score) * weight;
    }
    if (totalWeight <= 0) return null;
    return Math.round((accumulated / totalWeight) * 100) / 100;
  });

  readonly displayedColumns: string[] = [
    'code',
    'expert',
    'scope',
    'verdict',
    'reviewed_at',
    'score',
    'actions',
  ];

  constructor() {
    this.loadData();
    this.loadInstruments();
  }

  loadData(): void {
    this.loading.set(true);
    this.error.set(null);
    this.api
      .listValidations()
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => this.validations.set(res.validations || []),
        error: (err: unknown) => this.error.set(describeValidationError(err)),
      });
  }

  loadInstruments(): void {
    this.instrumentsError.set(null);
    this.api
      .listInstruments()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (res) => this.instruments.set(res.instruments || []),
        error: (err: unknown) => {
          this.instruments.set([]);
          this.instrumentsError.set(describeValidationError(err));
        },
      });
  }

  selectReview(review: ExpertReview): void {
    this.selected.set(review);
    this.loadDetail(review.id);
  }

  loadDetail(idOrCode: string): void {
    this.loadingDetail.set(true);
    this.api
      .getValidation(idOrCode)
      .pipe(
        finalize(() => this.loadingDetail.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => this.selected.set(res.validation),
        error: (err: unknown) => {
          this.snackBar.open(
            `No se pudo cargar el dictamen: ${describeValidationError(err)}`,
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
    this.formInstrumentId = null;
    this.formExpertName = '';
    this.formExpertRole = '';
    this.formExpertAffiliation = '';
    this.formScope = '';
    this.formVerdict = null;
    this.formObservations = '';
    this.formReviewedAt = this.today();
    this.formInstrument.set(null);
    this.answers.set([]);
    this.formError.set(null);
    this.showForm.set(true);
  }

  cancelForm(): void {
    this.showForm.set(false);
    this.formError.set(null);
  }

  /** Carga los items del instrumento elegido y prepara una respuesta por item. */
  onInstrumentChange(instrumentId: string | null): void {
    this.formInstrumentId = instrumentId;
    this.formInstrument.set(null);
    this.answers.set([]);
    if (!instrumentId) return;

    this.loadingItems.set(true);
    this.api
      .getInstrument(instrumentId)
      .pipe(
        finalize(() => this.loadingItems.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          this.formInstrument.set(res.instrument);
          this.answers.set((res.instrument.items ?? []).map((item) => this.toDraft(item)));
        },
        error: (err: unknown) => this.formError.set(describeValidationError(err)),
      });
  }

  patchAnswer(index: number, patch: Partial<AnswerDraft>): void {
    this.answers.update((answers) =>
      answers.map((answer, position) =>
        position === index ? { ...answer, ...patch } : answer,
      ),
    );
  }

  /**
   * Validacion local: datos del experto, veredicto declarado y una respuesta
   * por item dentro de la escala. La API vuelve a validar todo.
   */
  saveValidation(): void {
    const instrument = this.formInstrument();
    const expertName = this.formExpertName.trim();
    const expertRole = this.formExpertRole.trim();
    const verdict = this.formVerdict;
    const reviewedAt = this.formReviewedAt.trim();
    const answers = this.answers();

    if (!this.formInstrumentId || !instrument) {
      this.formError.set('Seleccione el instrumento que el experto respondió.');
      return;
    }
    if (!expertName) {
      this.formError.set('Registre el nombre del experto que emite el dictamen.');
      return;
    }
    if (!expertRole) {
      this.formError.set('Registre el rol o cargo del experto.');
      return;
    }
    if (!verdict) {
      this.formError.set('El veredicto debe declararlo el experto: seleccione uno.');
      return;
    }
    if (!reviewedAt) {
      this.formError.set('Indique la fecha del dictamen (YYYY-MM-DD).');
      return;
    }
    if (answers.length === 0) {
      this.formError.set('El instrumento seleccionado no tiene items que responder.');
      return;
    }
    for (const answer of answers) {
      if (!this.hasScore(answer)) {
        this.formError.set(`Falta la respuesta del item '${answer.itemCode}'.`);
        return;
      }
      const score = Number(answer.score);
      if (score < instrument.scale_min || score > instrument.scale_max) {
        this.formError.set(
          `La respuesta del item '${answer.itemCode}' (${score}) queda fuera de la escala ${instrument.scale_min}..${instrument.scale_max}.`,
        );
        return;
      }
      if (!Number.isInteger(score)) {
        this.formError.set(`La respuesta del item '${answer.itemCode}' debe ser un entero.`);
        return;
      }
    }

    const payload: SubmitValidationRequest = {
      instrument_id: instrument.id,
      expert_name: expertName,
      expert_role: expertRole,
      expert_affiliation: this.formExpertAffiliation.trim(),
      scope: this.formScope.trim(),
      verdict,
      observations: this.formObservations.trim(),
      reviewed_at: reviewedAt,
      answers: answers.map((answer) => ({
        item_id: answer.itemId,
        score: Number(answer.score),
        comment: answer.comment.trim(),
      })),
      // synthetic no se envia: el servidor lo impone.
    };

    this.saving.set(true);
    this.formError.set(null);
    this.api
      .submitValidation(payload)
      .pipe(
        finalize(() => this.saving.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (res) => {
          this.snackBar.open(
            `Dictamen ${res.validation.code} registrado. Veredicto declarado por el experto: ${res.validation.verdict}`,
            'Cerrar',
            { duration: 5000 },
          );
          this.showForm.set(false);
          this.selected.set(res.validation);
          this.loadData();
        },
        error: (err: unknown) => this.formError.set(describeValidationError(err)),
      });
  }

  /** Respuestas del detalle agrupadas por dimension, en el orden de la API. */
  groupedAnswers(review: ExpertReview): AnswerGroup[] {
    const groups: AnswerGroup[] = [];
    const index = new Map<ValidationDimension, AnswerGroup>();
    for (const answer of review.answers ?? []) {
      let group = index.get(answer.dimension);
      if (!group) {
        group = {
          dimension: answer.dimension,
          label: VALIDATION_DIMENSION_LABELS[answer.dimension] ?? answer.dimension,
          answers: [],
        };
        index.set(answer.dimension, group);
        groups.push(group);
      }
      group.answers.push(answer);
    }
    return groups;
  }

  verdictLabel(verdict: ExpertVerdict): string {
    return EXPERT_VERDICT_LABELS[verdict] ?? verdict;
  }

  verdictClass(verdict: ExpertVerdict): string {
    switch (verdict) {
      case 'CUMPLE':
        return 'vd-cumple';
      case 'CUMPLE_PARCIALMENTE':
        return 'vd-parcial';
      case 'NO_CUMPLE':
        return 'vd-no-cumple';
      default:
        return '';
    }
  }

  /** Puntuacion descriptiva con dos decimales; null significa "sin calcular". */
  scoreLabel(review: ExpertReview): string {
    if (review.score === null || review.score === undefined) {
      return 'sin puntuación';
    }
    return Number(review.score).toFixed(2);
  }

  /**
   * Escala del instrumento del dictamen, si el listado de instrumentos la
   * conoce. Devuelve null para no inventar un rango que la API no confirmo.
   */
  instrumentScale(review: ExpertReview): string | null {
    const instrument = this.instruments().find((item) => item.id === review.instrument_id);
    if (!instrument) return null;
    return `${instrument.scale_min}–${instrument.scale_max}`;
  }

  /** Formato de la escala del instrumento cargado en el formulario. */
  scaleLabel(): string {
    const instrument = this.formInstrument();
    return instrument ? `${instrument.scale_min} a ${instrument.scale_max}` : 'sin escala';
  }

  /** La API entrega segundos epoch; DatePipe espera milisegundos. */
  toDate(seconds: number | null): Date | null {
    if (seconds === null || seconds === undefined) return null;
    return new Date(Number(seconds) * 1000);
  }

  private toDraft(item: InstrumentItem): AnswerDraft {
    return {
      itemId: item.id,
      itemCode: item.code,
      dimension: item.dimension,
      statement: item.statement,
      weight: item.weight,
      score: null,
      comment: '',
    };
  }

  private hasScore(answer: AnswerDraft): boolean {
    return answer.score !== null && answer.score !== undefined && Number.isFinite(Number(answer.score));
  }

  private today(): string {
    return new Date().toISOString().slice(0, 10);
  }
}
