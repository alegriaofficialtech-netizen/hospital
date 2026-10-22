import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';

/**
 * Cliente de Gestion de Riesgos (M4, O2 de tesis).
 *
 * Conecta con el backend Zero Trust para consultar y administrar la matriz 5x5
 * de riesgos tecnicos, amenazas, vulnerabilidades y tratamientos.
 */

export type RiskCategory =
  | 'infraestructura'
  | 'identidad'
  | 'software'
  | 'datos'
  | 'gobernanza';

export type RiskTreatment = 'MITIGAR' | 'ACEPTAR' | 'TRANSFERIR' | 'EVITAR';

export type RiskLevel = 'CRITICO' | 'ALTO' | 'MEDIO' | 'BAJO';

export type RiskStatus =
  | 'IDENTIFICADO'
  | 'EVALUADO'
  | 'EN_TRATAMIENTO'
  | 'CONTROLADO'
  | 'RESIDUAL';

export const RISK_CATEGORIES: readonly RiskCategory[] = [
  'infraestructura',
  'identidad',
  'software',
  'datos',
  'gobernanza',
];

export const RISK_TREATMENTS: readonly RiskTreatment[] = [
  'MITIGAR',
  'ACEPTAR',
  'TRANSFERIR',
  'EVITAR',
];

export const RISK_LEVELS: readonly RiskLevel[] = [
  'CRITICO',
  'ALTO',
  'MEDIO',
  'BAJO',
];

export const RISK_STATUSES: readonly RiskStatus[] = [
  'IDENTIFICADO',
  'EVALUADO',
  'EN_TRATAMIENTO',
  'CONTROLADO',
  'RESIDUAL',
];

export interface Risk {
  id: string;
  code: string;
  name: string;
  description: string;
  category: RiskCategory;
  asset_name: string | null;
  finding_checker: string | null;
  threat: string;
  vulnerability: string;
  probability_inherent: number;
  impact_inherent: number;
  inherent_risk_score: number;
  inherent_risk_level: RiskLevel;
  treatment: RiskTreatment;
  probability_residual: number;
  impact_residual: number;
  residual_risk_score: number;
  residual_risk_level: RiskLevel;
  owner_role: string;
  status: RiskStatus;
  synthetic: number | boolean | null;
  revision: number;
  created_at: number | null;
  updated_at: number | null;
}

export interface RiskSummary {
  total: number;
  by_category: Record<string, number>;
  by_inherent_level: Record<string, number>;
  by_residual_level: Record<string, number>;
  by_treatment: Record<string, number>;
  by_status: Record<string, number>;
}

export interface RiskFilters {
  category?: RiskCategory | null;
  inherent_level?: RiskLevel | null;
  residual_level?: RiskLevel | null;
  treatment?: RiskTreatment | null;
  status?: RiskStatus | null;
}

export interface RisksResponse {
  risks: Risk[];
  summary: RiskSummary;
  timestamp: number;
}

export interface RiskDetailResponse {
  risk: Risk;
  linked_controls: any[];
}

export interface CreateRiskRequest {
  code: string;
  name: string;
  description: string;
  category: RiskCategory;
  asset_name?: string | null;
  finding_checker?: string | null;
  threat: string;
  vulnerability: string;
  probability_inherent: number;
  impact_inherent: number;
  treatment: RiskTreatment;
  probability_residual?: number | null;
  impact_residual?: number | null;
  owner_role?: string;
  status?: RiskStatus;
  synthetic?: number;
}

export interface UpdateRiskRequest {
  name?: string;
  description?: string;
  category?: RiskCategory;
  asset_name?: string | null;
  finding_checker?: string | null;
  threat?: string;
  vulnerability?: string;
  probability_inherent?: number;
  impact_inherent?: number;
  treatment?: RiskTreatment;
  probability_residual?: number | null;
  impact_residual?: number | null;
  owner_role?: string;
  status?: RiskStatus;
}

@Injectable({ providedIn: 'root' })
export class RisksService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1/risks';

  listRisks(filters: RiskFilters = {}): Observable<RisksResponse> {
    let params = new HttpParams();
    if (filters.category) params = params.set('category', filters.category);
    if (filters.inherent_level) params = params.set('inherent_level', filters.inherent_level);
    if (filters.residual_level) params = params.set('residual_level', filters.residual_level);
    if (filters.treatment) params = params.set('treatment', filters.treatment);
    if (filters.status) params = params.set('status', filters.status);

    return this.http.get<RisksResponse>(this.baseUrl, { params });
  }

  getSummary(): Observable<RiskSummary> {
    return this.http
      .get<{ summary: RiskSummary }>(`${this.baseUrl}/summary`)
      .pipe(map((res) => res.summary));
  }

  getRisk(idOrCode: string): Observable<RiskDetailResponse> {
    return this.http.get<RiskDetailResponse>(`${this.baseUrl}/${encodeURIComponent(idOrCode)}`);
  }

  createRisk(payload: CreateRiskRequest): Observable<{ risk: Risk }> {
    return this.http.post<{ risk: Risk }>(this.baseUrl, payload);
  }

  updateRisk(id: string, payload: UpdateRiskRequest): Observable<{ risk: Risk }> {
    return this.http.post<{ risk: Risk }>(
      `${this.baseUrl}/${encodeURIComponent(id)}`,
      payload,
    );
  }

  linkControl(
    riskId: string,
    controlId: string,
    coverage: string = 'TOTAL',
    notes: string = '',
  ): Observable<{ linked: boolean; link: any }> {
    return this.http.post<{ linked: boolean; link: any }>(
      `${this.baseUrl}/${encodeURIComponent(riskId)}/controls`,
      {
        control_id: controlId,
        coverage,
        notes,
      },
    );
  }
}
