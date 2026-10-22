import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';

/**
 * Cliente de Gestion de Controles (M5, O3 de tesis).
 *
 * Catalogo de controles alineados a ISO/IEC 27001:2022, NIST SP 800-207 y CISA ZTM.
 * Registra estados PROPUESTO, IMPLEMENTADO y VERIFICADO (con evidencia real obligatoria).
 */

export type ControlFramework =
  | 'ISO_27001_2022'
  | 'NIST_SP_800_207'
  | 'CISA_ZTM';

export type ControlStatus = 'PROPUESTO' | 'IMPLEMENTADO' | 'VERIFICADO';

export type ControlEffectiveness =
  | 'ALTA'
  | 'MEDIA'
  | 'BAJA'
  | 'NO_EVALUADA';

export type ControlEvidenceType =
  | 'test_suite'
  | 'checker'
  | 'audit_log'
  | 'manual_review';

export const CONTROL_FRAMEWORKS: readonly ControlFramework[] = [
  'ISO_27001_2022',
  'NIST_SP_800_207',
  'CISA_ZTM',
];

export const CONTROL_STATUSES: readonly ControlStatus[] = [
  'PROPUESTO',
  'IMPLEMENTADO',
  'VERIFICADO',
];

export const CONTROL_EFFECTIVENESS_LEVELS: readonly ControlEffectiveness[] = [
  'ALTA',
  'MEDIA',
  'BAJA',
  'NO_EVALUADA',
];

export const CONTROL_EVIDENCE_TYPES: readonly ControlEvidenceType[] = [
  'test_suite',
  'checker',
  'audit_log',
  'manual_review',
];

export interface ControlEvidence {
  id: string;
  control_id: string;
  evidence_type: ControlEvidenceType;
  evidence_source: string;
  reference_id: string;
  observed_result: string;
  verified_by: string;
  verified_at: number;
  hash: string;
}

export interface Control {
  id: string;
  code: string;
  framework: ControlFramework;
  clause_or_pillar: string;
  name: string;
  description: string;
  owner_role: string;
  status: ControlStatus;
  effectiveness: ControlEffectiveness;
  evidence_type: ControlEvidenceType | null;
  evidence_reference: string | null;
  synthetic: number | boolean | null;
  revision: number;
  created_at: number | null;
  updated_at: number | null;
}

export interface ControlSummary {
  total_controls: number;
  by_framework: Record<string, number>;
  by_status: Record<string, number>;
  compliance_percentage: number;
  verified_count: number;
  implemented_count: number;
  proposed_count: number;
}

export interface ControlFilters {
  framework?: ControlFramework | null;
  status?: ControlStatus | null;
  effectiveness?: ControlEffectiveness | null;
}

export interface ControlsResponse {
  controls: Control[];
  summary: ControlSummary;
  timestamp: number;
}

export interface ControlDetailResponse {
  control: Control;
  linked_risks: any[];
  evidences: ControlEvidence[];
}

export interface CreateControlRequest {
  code: string;
  framework: ControlFramework;
  clause_or_pillar: string;
  name: string;
  description: string;
  owner_role?: string;
  status?: ControlStatus;
  effectiveness?: ControlEffectiveness;
  evidence_type?: ControlEvidenceType | null;
  evidence_reference?: string | null;
  synthetic?: number;
}

export interface UpdateControlRequest {
  framework?: ControlFramework;
  clause_or_pillar?: string;
  name?: string;
  description?: string;
  owner_role?: string;
  status?: ControlStatus;
  effectiveness?: ControlEffectiveness;
  evidence_type?: ControlEvidenceType | null;
  evidence_reference?: string | null;
}

export interface VerifyControlRequest {
  evidence_source: string;
  reference_id: string;
  observed_result: string;
  evidence_type?: ControlEvidenceType;
}

@Injectable({ providedIn: 'root' })
export class ControlsService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1/controls';

  listControls(filters: ControlFilters = {}): Observable<ControlsResponse> {
    let params = new HttpParams();
    if (filters.framework) params = params.set('framework', filters.framework);
    if (filters.status) params = params.set('status', filters.status);
    if (filters.effectiveness) params = params.set('effectiveness', filters.effectiveness);

    return this.http.get<ControlsResponse>(this.baseUrl, { params });
  }

  getSummary(): Observable<ControlSummary> {
    return this.http
      .get<{ summary: ControlSummary }>(`${this.baseUrl}/summary`)
      .pipe(map((res) => res.summary));
  }

  getControl(idOrCode: string): Observable<ControlDetailResponse> {
    return this.http.get<ControlDetailResponse>(
      `${this.baseUrl}/${encodeURIComponent(idOrCode)}`,
    );
  }

  createControl(payload: CreateControlRequest): Observable<{ control: Control }> {
    return this.http.post<{ control: Control }>(this.baseUrl, payload);
  }

  updateControl(id: string, payload: UpdateControlRequest): Observable<{ control: Control }> {
    return this.http.post<{ control: Control }>(
      `${this.baseUrl}/${encodeURIComponent(id)}`,
      payload,
    );
  }

  verifyControl(
    id: string,
    payload: VerifyControlRequest,
  ): Observable<{ verified: boolean; control: Control; evidence: ControlEvidence }> {
    return this.http.post<{
      verified: boolean;
      control: Control;
      evidence: ControlEvidence;
    }>(`${this.baseUrl}/${encodeURIComponent(id)}/verify`, payload);
  }
}
