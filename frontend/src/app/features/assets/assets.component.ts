import { DatePipe } from '@angular/common';
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
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { firstValueFrom, forkJoin } from 'rxjs';
import { finalize } from 'rxjs/operators';
import { AuthService } from '../../core/auth/auth.service';
import {
  ASSET_CLASSIFICATIONS,
  ASSET_CRITICALITIES,
  ASSET_SOURCES,
  Asset,
  AssetClassification,
  AssetCriticality,
  AssetEvaluation,
  AssetFilters,
  AssetsService,
  AssetSource,
  AssetSummary,
  CreateAssetRequest,
  CreateEvaluationRequest,
} from '../../core/api/assets.service';

/** Reparto de un indicador de la API: clave tecnica y valor. */
interface BreakdownEntry {
  key: string;
  value: number;
}

/** Modo del formulario de alta y edicion. */
type AssetFormMode = 'create' | 'edit';

/** Error devuelto por la API: mensaje, codigo y detalle por campo. */
interface ApiFailure {
  message: string;
  code: string;
  fields: Record<string, string>;
}

/**
 * Pantalla M3: inventario de activos del laboratorio F11.
 *
 * El inventario describe lo que existe: la tabla, el detalle y los indicadores
 * salen de la API. El alta, la edicion y el registro de evaluaciones son
 * acciones sensibles y solo se ofrecen al administrador de plataforma con MFA
 * acreditada.
 */
@Component({
  selector: 'app-assets',
  standalone: true,
  imports: [
    DatePipe,
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatProgressSpinnerModule,
    MatSelectModule,
    MatSnackBarModule,
    MatTableModule,
  ],
  templateUrl: './assets.component.html',
  styleUrl: './assets.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class AssetsComponent {
  private readonly api = inject(AssetsService);
  private readonly auth = inject(AuthService);
  private readonly snackBar = inject(MatSnackBar);
  private readonly destroyRef = inject(DestroyRef);

  /** Entorno declarado por la API; el laboratorio F11 se identifica como f11-local. */
  readonly environment = signal('f11-local');

  readonly assets = signal<Asset[]>([]);
  readonly summary = signal<AssetSummary | null>(null);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  readonly classificationFilter = signal<AssetClassification | 'ALL'>('ALL');
  readonly criticalityFilter = signal<AssetCriticality | 'ALL'>('ALL');
  readonly sourceFilter = signal<AssetSource | 'ALL'>('ALL');

  readonly selectedAssetId = signal<string | null>(null);
  readonly selectedAsset = signal<Asset | null>(null);
  readonly evaluations = signal<AssetEvaluation[]>([]);
  readonly detailLoading = signal(false);
  readonly detailError = signal<string | null>(null);

  readonly formMode = signal<AssetFormMode | null>(null);
  readonly formError = signal<string | null>(null);
  readonly fieldErrors = signal<Record<string, string>>({});
  readonly saving = signal(false);

  readonly formName = signal('');
  readonly formClassification = signal<AssetClassification | ''>('');
  readonly formCriticality = signal<AssetCriticality | ''>('');
  readonly formOwner = signal('');
  readonly formSource = signal<AssetSource | ''>('');
  readonly formVersion = signal('');
  readonly formDescription = signal('');

  readonly evaluationCriticality = signal<AssetCriticality | ''>('');
  readonly evaluationNotes = signal('');
  readonly evaluationError = signal<string | null>(null);
  readonly evaluationFieldErrors = signal<Record<string, string>>({});
  readonly savingEvaluation = signal(false);

  readonly classifications = ASSET_CLASSIFICATIONS;
  readonly criticalities = ASSET_CRITICALITIES;
  readonly sources = ASSET_SOURCES;

  readonly assetColumns = [
    'name',
    'classification',
    'criticality',
    'owner',
    'source',
    'version',
    'synthetic',
    'revision',
    'updated',
  ];
  readonly evaluationColumns = ['evaluated', 'evaluator', 'criticality', 'findings', 'notes'];

  /** La gestion del inventario es una accion sensible: administrador con MFA. */
  readonly canManage = computed(
    () => this.auth.hasAnyRole(['ROLE_PLATFORM_ADMIN']) && this.auth.mfaVerified(),
  );

  /** Motivo por el que la gestion no esta disponible, si no lo esta. */
  readonly manageBlockedReason = computed(() => {
    if (this.canManage()) {
      return null;
    }
    if (!this.auth.hasAnyRole(['ROLE_PLATFORM_ADMIN'])) {
      return 'La gestion del inventario esta reservada al administrador de plataforma.';
    }
    return 'La gestion del inventario exige MFA acreditada en esta sesion.';
  });

  readonly classificationBreakdown = computed(() =>
    this.toBreakdown(this.summary()?.by_classification),
  );
  readonly criticalityBreakdown = computed(() =>
    this.toBreakdown(this.summary()?.by_criticality),
  );
  readonly sourceBreakdown = computed(() => this.toBreakdown(this.summary()?.by_source));

  /** Si hay algun filtro activo sobre el inventario. */
  readonly hasActiveFilters = computed(
    () =>
      this.classificationFilter() !== 'ALL' ||
      this.criticalityFilter() !== 'ALL' ||
      this.sourceFilter() !== 'ALL',
  );

  constructor() {
    this.load();
  }

  /** Carga el inventario con los filtros activos y su resumen. */
  load(): void {
    this.loading.set(true);
    this.error.set(null);
    forkJoin({
      assets: this.api.listAssets(this.buildFilters()),
      summary: this.api.summary(),
    })
      .pipe(
        finalize(() => this.loading.set(false)),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (payload) => {
          this.assets.set(payload.assets.assets);
          this.summary.set(payload.assets.summary);
          this.captureEnvironment(payload.assets.environment);
        },
        error: (error: unknown) => this.fail(error),
      });
  }

  setClassificationFilter(value: AssetClassification | 'ALL'): void {
    this.classificationFilter.set(value);
    this.load();
  }

  setCriticalityFilter(value: AssetCriticality | 'ALL'): void {
    this.criticalityFilter.set(value);
    this.load();
  }

  setSourceFilter(value: AssetSource | 'ALL'): void {
    this.sourceFilter.set(value);
    this.load();
  }

  /** Muestra el detalle de un activo con su historial de evaluaciones. */
  async selectAsset(assetId: string): Promise<void> {
    this.selectedAssetId.set(assetId);
    this.detailLoading.set(true);
    this.detailError.set(null);
    try {
      const detail = await firstValueFrom(this.api.getAsset(assetId));
      this.selectedAsset.set(detail.asset);
      this.evaluations.set(detail.evaluations);
      this.captureEnvironment(detail.environment);
      this.prepareEvaluation(detail.asset);
    } catch (error) {
      this.selectedAsset.set(null);
      this.evaluations.set([]);
      this.detailError.set(this.describe(error));
    } finally {
      this.detailLoading.set(false);
    }
  }

  clearSelection(): void {
    this.selectedAssetId.set(null);
    this.selectedAsset.set(null);
    this.evaluations.set([]);
    this.detailError.set(null);
    this.closeForm();
  }

  /** Abre el formulario de alta con el formulario vacio. */
  openCreateForm(): void {
    this.formMode.set('create');
    this.formError.set(null);
    this.fieldErrors.set({});
    this.formName.set('');
    this.formClassification.set('');
    this.formCriticality.set('');
    this.formOwner.set('');
    this.formSource.set('');
    this.formVersion.set('');
    this.formDescription.set('');
  }

  /** Abre el formulario de edicion con los datos que devuelve la API. */
  openEditForm(asset: Asset): void {
    this.formMode.set('edit');
    this.formError.set(null);
    this.fieldErrors.set({});
    this.formName.set(asset.name ?? '');
    this.formClassification.set(asset.classification ?? '');
    this.formCriticality.set(asset.criticality ?? '');
    this.formOwner.set(asset.owner ?? '');
    this.formSource.set(asset.source ?? '');
    this.formVersion.set(asset.version ?? '');
    this.formDescription.set(asset.description ?? '');
  }

  closeForm(): void {
    this.formMode.set(null);
    this.formError.set(null);
    this.fieldErrors.set({});
  }

  /** Valida en cliente con las mismas reglas que aplica el backend. */
  private validateAssetForm(): Record<string, string> {
    const errors: Record<string, string> = {};
    const name = this.formName().trim();
    if (!name) {
      errors['name'] = 'El nombre del activo es obligatorio.';
    } else if (name.length < 3 || name.length > 80) {
      errors['name'] = 'El nombre debe tener entre 3 y 80 caracteres.';
    } else if (!/^[A-Za-z0-9._-]+$/.test(name)) {
      errors['name'] =
        'El nombre solo admite letras, digitos, guion, guion bajo y punto.';
    }

    if (!this.formClassification()) {
      errors['classification'] = 'Selecciona una clasificacion.';
    }
    if (!this.formCriticality()) {
      errors['criticality'] = 'Selecciona una criticidad.';
    }

    const owner = this.formOwner().trim();
    if (!owner) {
      errors['owner'] = 'El propietario es obligatorio y debe ser un rol o un equipo.';
    } else if (owner.length < 3 || owner.length > 80) {
      errors['owner'] = 'El propietario debe tener entre 3 y 80 caracteres.';
    }

    if (!this.formSource()) {
      errors['source'] = 'Selecciona un origen.';
    }

    const version = this.formVersion().trim();
    if (version.length > 64) {
      errors['version'] = 'La version no puede superar los 64 caracteres.';
    }

    const description = this.formDescription().trim();
    if (!description) {
      errors['description'] = 'La descripcion es obligatoria.';
    } else if (description.length < 10 || description.length > 600) {
      errors['description'] = 'La descripcion debe tener entre 10 y 600 caracteres.';
    }

    return errors;
  }

  /** Guarda el alta o la edicion del activo. */
  async saveAsset(): Promise<void> {
    if (!this.canManage() || this.saving()) {
      return;
    }
    const clientErrors = this.validateAssetForm();
    if (Object.keys(clientErrors).length) {
      this.fieldErrors.set(clientErrors);
      this.formError.set('Revisa los campos marcados antes de guardar.');
      return;
    }
    this.saving.set(true);
    this.formError.set(null);
    this.fieldErrors.set({});
    const mode = this.formMode();
    const payload = this.buildPayload();
    try {
      let savedAssetId = this.selectedAssetId();
      if (mode === 'edit') {
        if (!savedAssetId) {
          throw new Error('No hay ningun activo seleccionado para editar.');
        }
        const result = await firstValueFrom(this.api.updateAsset(savedAssetId, payload));
        savedAssetId = result.asset.id;
        this.notify(
          `Activo ${result.asset.name} actualizado (revision ${result.asset.revision}).`,
        );
      } else {
        const result = await firstValueFrom(this.api.createAsset(payload));
        savedAssetId = result.asset.id;
        this.notify(`Activo ${result.asset.name} dado de alta.`);
      }
      this.closeForm();
      await this.reloadAssets();
      if (savedAssetId) {
        await this.selectAsset(savedAssetId);
      }
    } catch (error) {
      const failure = this.toFailure(error);
      this.fieldErrors.set(failure.fields);
      this.formError.set(
        failure.code ? `${failure.message} (${failure.code})` : failure.message,
      );
      this.notify(failure.message);
    } finally {
      this.saving.set(false);
    }
  }

  /** Registra una evaluacion de criticidad sobre el activo seleccionado. */
  async saveEvaluation(): Promise<void> {
    const assetId = this.selectedAssetId();
    if (!this.canManage() || this.savingEvaluation() || !assetId) {
      return;
    }
    const criticality = this.evaluationCriticality();
    const notes = this.evaluationNotes().trim();
    const errors: Record<string, string> = {};
    if (!criticality) {
      errors['criticality'] = 'Selecciona la criticidad de la evaluacion.';
    }
    if (!notes) {
      errors['notes'] = 'Las notas de la evaluacion son obligatorias.';
    } else if (notes.length > 600) {
      errors['notes'] = 'Las notas no pueden superar los 600 caracteres.';
    }
    if (Object.keys(errors).length) {
      this.evaluationFieldErrors.set(errors);
      this.evaluationError.set('Revisa los campos marcados antes de registrar.');
      return;
    }
    this.savingEvaluation.set(true);
    this.evaluationError.set(null);
    this.evaluationFieldErrors.set({});
    const payload: CreateEvaluationRequest = {
      criticality: criticality as AssetCriticality,
      notes,
    };
    try {
      await firstValueFrom(this.api.createEvaluation(assetId, payload));
      this.evaluationNotes.set('');
      this.notify('Evaluacion registrada.');
      await this.selectAsset(assetId);
      await this.reloadAssets();
    } catch (error) {
      const failure = this.toFailure(error);
      this.evaluationFieldErrors.set(failure.fields);
      this.evaluationError.set(
        failure.code ? `${failure.message} (${failure.code})` : failure.message,
      );
      this.notify(failure.message);
    } finally {
      this.savingEvaluation.set(false);
    }
  }

  /** Marca la criticidad vigente del activo como valor inicial de la evaluacion. */
  prepareEvaluation(asset: Asset): void {
    this.evaluationCriticality.set(asset.criticality ?? '');
    this.evaluationNotes.set('');
    this.evaluationError.set(null);
    this.evaluationFieldErrors.set({});
  }

  isSynthetic(asset: Asset): boolean {
    return asset.synthetic === 1 || asset.synthetic === true;
  }

  /** Convierte la marca de tiempo de la API (segundos epoch) en milisegundos. */
  toDate(value: number | string | null | undefined): number | null {
    if (value === null || value === undefined || value === '') {
      return null;
    }
    if (typeof value === 'number') {
      return Number.isFinite(value) ? value * 1000 : null;
    }
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }

  private async reloadAssets(): Promise<void> {
    const response = await firstValueFrom(this.api.listAssets(this.buildFilters()));
    this.assets.set(response.assets);
    this.summary.set(response.summary);
    this.captureEnvironment(response.environment);
  }

  private buildFilters(): AssetFilters {
    const classification = this.classificationFilter();
    const criticality = this.criticalityFilter();
    const source = this.sourceFilter();
    return {
      classification: classification === 'ALL' ? null : classification,
      criticality: criticality === 'ALL' ? null : criticality,
      source: source === 'ALL' ? null : source,
    };
  }

  private buildPayload(): CreateAssetRequest {
    const version = this.formVersion().trim();
    return {
      name: this.formName().trim(),
      classification: this.formClassification() as AssetClassification,
      criticality: this.formCriticality() as AssetCriticality,
      owner: this.formOwner().trim(),
      source: this.formSource() as AssetSource,
      // An empty version is sent as null on purpose: the backend tells "not
      // sent" from "sent as null" and a null version clears the stored value.
      // That is why the field can be emptied from the form and the change
      // really reaches the inventory.
      version: version ? version : null,
      description: this.formDescription().trim(),
    };
  }

  private captureEnvironment(value: string | undefined): void {
    if (value) {
      this.environment.set(value);
    }
  }

  private toBreakdown(source: Record<string, number> | null | undefined): BreakdownEntry[] {
    if (!source) {
      return [];
    }
    return Object.entries(source).map(([key, value]) => ({ key, value: Number(value) }));
  }

  private fail(error: unknown): void {
    const message = this.describe(error);
    this.error.set(message);
    this.notify(message);
  }

  private notify(message: string): void {
    this.snackBar.open(message, 'Cerrar', { duration: 7000 });
  }

  private describe(error: unknown): string {
    const failure = this.toFailure(error);
    return failure.code ? `${failure.message} (${failure.code})` : failure.message;
  }

  private toFailure(error: unknown): ApiFailure {
    if (error instanceof HttpErrorResponse) {
      const body = error.error as
        | { message?: string; code?: string; fields?: Record<string, string> }
        | null;
      return {
        message: body?.message ?? `La peticion fallo con el estado ${error.status}.`,
        code: body?.code ?? '',
        fields: body?.fields ?? {},
      };
    }
    if (error instanceof Error) {
      return { message: error.message, code: '', fields: {} };
    }
    return { message: 'No se pudo completar la operacion.', code: '', fields: {} };
  }
}
