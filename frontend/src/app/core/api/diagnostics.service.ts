import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';

/**
 * Cliente del diagnostico de seguridad (M2).
 *
 * La pantalla no decide el estado de nada: solo pinta lo que devuelve la API.
 * Los identificadores de comprobador, los objetivos y los codigos de error se
 * viajan y se muestran tal cual, sin traducir.
 */

/** Severidad de un hallazgo del diagnostico de seguridad. */
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low';

/** Estado de un hallazgo del diagnostico de seguridad. */
export type FindingStatus = 'passed' | 'failed' | 'warning';

/** Severidades admitidas por el backend. */
export const FINDING_SEVERITIES: readonly FindingSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
];

/** Estados admitidos por el backend. */
export const FINDING_STATUSES: readonly FindingStatus[] = ['passed', 'failed', 'warning'];

/** Catalogo de comprobadores ejecutables. */
export interface DiagnosticChecker {
  id: string;
  title: string;
  objective: string;
  severity: FindingSeverity;
  description: string;
}

/** Ejecucion registrada del diagnostico. */
export interface DiagnosticRun {
  id: string;
  started_at: number | null;
  finished_at: number | null;
  status: string;
  checker_count: number;
  passed: number;
  failed: number;
  warnings: number;
  triggered_by: string;
  environment: string;
  notes: string;
}

/** Hallazgo de seguridad con su evidencia completa. */
export interface SecurityFinding {
  id: string;
  run_id: string;
  checker_id: string;
  title: string;
  objective: string;
  severity: FindingSeverity;
  status: FindingStatus;
  asset_ref: string | null;
  evidence_command: string | null;
  evidence_output: string | null;
  remediation: string | null;
  detected_at: number | null;
}

/** Ultimo estado registrado de un comprobador. */
export interface CheckerState {
  checker_id: string;
  title: string;
  status: FindingStatus;
  objective: string;
}

/** Resumen de indicadores del diagnostico. */
export interface DiagnosticsSummary {
  total_findings: number;
  open_findings: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  by_objective: Record<string, number>;
  by_checker: CheckerState[];
  runs_total: number;
  last_run: DiagnosticRun | null;
  environment: string;
}

/** Filtros admitidos por la consulta de hallazgos. */
export interface FindingFilters {
  status?: FindingStatus | null;
  severity?: FindingSeverity | null;
  objective?: string | null;
  checker_id?: string | null;
  run_id?: string | null;
  limit?: number;
}

/** Respuesta de la consulta de hallazgos. */
export interface FindingListResponse {
  findings: SecurityFinding[];
  total: number;
  environment: string;
}

/** Respuesta del detalle de una ejecucion. */
export interface RunDetailResponse {
  run: DiagnosticRun;
  findings: SecurityFinding[];
  environment: string;
}

/**
 * Cliente HTTP del diagnostico de seguridad.
 *
 * No ejecuta comprobadores en el navegador: el diagnostico corre en el backend
 * del laboratorio F11 y aqui solo se consultan sus resultados y su evidencia.
 */
@Injectable({ providedIn: 'root' })
export class DiagnosticsService {
  private readonly http = inject(HttpClient);

  /** Catalogo de comprobadores ejecutables. */
  listCheckers(): Observable<DiagnosticChecker[]> {
    return this.http
      .get<{ checkers: DiagnosticChecker[]; environment: string }>('/api/v1/diagnostics/checkers')
      .pipe(map((payload) => payload.checkers));
  }

  /** Ejecuciones mas recientes del diagnostico. */
  listRuns(limit = 20): Observable<DiagnosticRun[]> {
    const params = new HttpParams().set('limit', String(limit));
    return this.http
      .get<{ runs: DiagnosticRun[]; environment: string }>('/api/v1/diagnostics/runs', { params })
      .pipe(map((payload) => payload.runs));
  }

  /** Detalle de una ejecucion con los hallazgos que produjo. */
  getRun(runId: string): Observable<RunDetailResponse> {
    return this.http.get<RunDetailResponse>(
      `/api/v1/diagnostics/runs/${encodeURIComponent(runId)}`,
    );
  }

  /** Hallazgos con filtros opcionales. */
  listFindings(filters: FindingFilters = {}): Observable<FindingListResponse> {
    let params = new HttpParams();
    if (filters.status) {
      params = params.set('status', filters.status);
    }
    if (filters.severity) {
      params = params.set('severity', filters.severity);
    }
    if (filters.objective) {
      params = params.set('objective', filters.objective);
    }
    if (filters.checker_id) {
      params = params.set('checker_id', filters.checker_id);
    }
    if (filters.run_id) {
      params = params.set('run_id', filters.run_id);
    }
    params = params.set('limit', String(filters.limit ?? 100));
    return this.http.get<FindingListResponse>('/api/v1/diagnostics/findings', { params });
  }

  /** Indicadores agregados del diagnostico. */
  summary(): Observable<DiagnosticsSummary> {
    return this.http.get<DiagnosticsSummary>('/api/v1/diagnostics/summary');
  }

  /**
   * Ejecuta el diagnostico en el backend.
   *
   * `checker_ids` a null ejecuta todos los comprobadores del catalogo.
   */
  runDiagnostics(checkerIds: string[] | null): Observable<RunDetailResponse> {
    return this.http.post<RunDetailResponse>('/api/v1/diagnostics/runs', {
      checker_ids: checkerIds,
    });
  }
}
