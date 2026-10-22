import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';

/**
 * Cliente del inventario de activos (M3).
 *
 * El inventario describe lo que hay en el laboratorio: la interfaz solo
 * muestra lo que devuelve la API y no completa ningun campo por su cuenta.
 */

/** Clasificacion admitida por el backend. */
export type AssetClassification =
  | 'container'
  | 'service'
  | 'dataset'
  | 'identity_store'
  | 'code'
  | 'configuration';

/** Criticidad admitida por el backend. */
export type AssetCriticality = 'critical' | 'high' | 'medium' | 'low';

/** Origen admitido por el backend. */
export type AssetSource = 'compose' | 'runtime' | 'manual';

/** Clasificaciones admitidas por el backend. */
export const ASSET_CLASSIFICATIONS: readonly AssetClassification[] = [
  'container',
  'service',
  'dataset',
  'identity_store',
  'code',
  'configuration',
];

/** Criticidades admitidas por el backend. */
export const ASSET_CRITICALITIES: readonly AssetCriticality[] = [
  'critical',
  'high',
  'medium',
  'low',
];

/** Origenes admitidos por el backend. */
export const ASSET_SOURCES: readonly AssetSource[] = ['compose', 'runtime', 'manual'];

/** Activo registrado en el inventario. */
export interface Asset {
  id: string;
  name: string;
  classification: AssetClassification;
  criticality: AssetCriticality;
  owner: string;
  source: AssetSource;
  version: string | null;
  environment: string;
  synthetic: number | boolean | null;
  description: string;
  created_at: number | null;
  updated_at: number | null;
  revision: number;
}

/** Evaluacion de criticidad registrada sobre un activo. */
export interface AssetEvaluation {
  id: string;
  asset_id: string;
  evaluated_at: number | null;
  evaluated_by: string;
  criticality: AssetCriticality;
  notes: string;
  findings_count: number;
}

/** Resumen de indicadores del inventario. */
export interface AssetSummary {
  total: number;
  by_classification: Record<string, number>;
  by_criticality: Record<string, number>;
  by_source: Record<string, number>;
}

/** Filtros admitidos por el listado de activos. */
export interface AssetFilters {
  classification?: AssetClassification | null;
  criticality?: AssetCriticality | null;
  source?: AssetSource | null;
  environment?: string | null;
}

/** Respuesta del listado de activos con su resumen. */
export interface AssetsResponse {
  assets: Asset[];
  summary: AssetSummary;
  environment: string;
}

/** Respuesta del detalle de un activo con su historial de evaluaciones. */
export interface AssetDetailResponse {
  asset: Asset;
  evaluations: AssetEvaluation[];
  environment: string;
}

/** Cuerpo del alta de un activo. */
export interface CreateAssetRequest {
  name: string;
  classification: AssetClassification;
  criticality: AssetCriticality;
  owner: string;
  source: AssetSource;
  version?: string | null;
  description: string;
}

/** Cuerpo de la actualizacion parcial de un activo. */
export interface UpdateAssetRequest {
  name?: string;
  classification?: AssetClassification;
  criticality?: AssetCriticality;
  owner?: string;
  source?: AssetSource;
  version?: string | null;
  description?: string;
}

/** Cuerpo del registro de una evaluacion. */
export interface CreateEvaluationRequest {
  criticality: AssetCriticality;
  notes: string;
}

/**
 * Cliente HTTP del inventario de activos.
 *
 * La gestion del inventario es una accion sensible: la resuelve el backend con
 * el rol de administrador de plataforma y MFA acreditada.
 */
@Injectable({ providedIn: 'root' })
export class AssetsService {
  private readonly http = inject(HttpClient);

  /** Activos del inventario con filtros opcionales y el resumen global. */
  listAssets(filters: AssetFilters = {}): Observable<AssetsResponse> {
    let params = new HttpParams();
    if (filters.classification) {
      params = params.set('classification', filters.classification);
    }
    if (filters.criticality) {
      params = params.set('criticality', filters.criticality);
    }
    if (filters.source) {
      params = params.set('source', filters.source);
    }
    if (filters.environment) {
      params = params.set('environment', filters.environment);
    }
    return this.http.get<AssetsResponse>('/api/v1/assets', { params });
  }

  /** Resumen del inventario sin el detalle de los activos. */
  summary(): Observable<AssetSummary> {
    return this.http
      .get<{ summary: AssetSummary; environment: string }>('/api/v1/assets/summary')
      .pipe(map((payload) => payload.summary));
  }

  /** Detalle de un activo con su historial de evaluaciones. */
  getAsset(assetId: string): Observable<AssetDetailResponse> {
    return this.http.get<AssetDetailResponse>(
      `/api/v1/assets/${encodeURIComponent(assetId)}`,
    );
  }

  /** Da de alta un activo en el inventario. */
  createAsset(payload: CreateAssetRequest): Observable<{ asset: Asset; environment: string }> {
    return this.http.post<{ asset: Asset; environment: string }>('/api/v1/assets', payload);
  }

  /** Actualiza parcialmente un activo: el backend incrementa la revision. */
  updateAsset(
    assetId: string,
    payload: UpdateAssetRequest,
  ): Observable<{ asset: Asset; environment: string }> {
    return this.http.post<{ asset: Asset; environment: string }>(
      `/api/v1/assets/${encodeURIComponent(assetId)}`,
      payload,
    );
  }

  /** Registra una evaluacion de criticidad sobre un activo. */
  createEvaluation(
    assetId: string,
    payload: CreateEvaluationRequest,
  ): Observable<{ evaluation: AssetEvaluation; environment: string }> {
    return this.http.post<{ evaluation: AssetEvaluation; environment: string }>(
      `/api/v1/assets/${encodeURIComponent(assetId)}/evaluations`,
      payload,
    );
  }
}
