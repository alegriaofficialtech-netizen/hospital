import { HttpClient, HttpErrorResponse, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

/**
 * Cliente de validacion por expertos (M9) e informes de evidencia (F5).
 *
 * Contrato copiado de la API real:
 * - GET  /api/v1/instruments             -> {"instruments": [], "count": n, "environment": "..."}
 * - GET  /api/v1/instruments/{id|code}   -> {"instrument": {}, "environment": "..."}
 * - POST /api/v1/instruments             -> 201 {"instrument": {}, "environment": "..."}
 * - GET  /api/v1/validations             -> {"validations": [], "count": n, "environment": "..."}
 * - GET  /api/v1/validations/{id|code}   -> {"validation": {}, "environment": "..."}
 * - POST /api/v1/validations             -> 201 {"validation": {}, "environment": "..."}
 * - GET  /api/v1/evidence[?objective=]   -> {"objectives": [], "total": n, "objective_filter": ..., "environment": "..."}
 * - GET  /api/v1/reports                 -> {"reports": [], "count": n, "environment": "..."}
 * - GET  /api/v1/reports/{id|code}       -> {"report": {}, "environment": "..."}
 * - POST /api/v1/reports                 -> 201 {"report": {}, "environment": "..."}
 *
 * El sistema REGISTRA dictamenes, no los genera: el veredicto (verdict) llega
 * siempre declarado por el experto. El campo score es una media ponderada
 * DESCRIPTIVA de las respuestas y no decide ni sustituye ese veredicto.
 *
 * Las marcas de tiempo de revisiones e informes son segundos epoch (float).
 * Las fechas de revision y de periodo son cadenas YYYY-MM-DD.
 */

export type InstrumentStatus = 'BORRADOR' | 'ACTIVO' | 'ARCHIVADO';

export const INSTRUMENT_STATUSES: readonly InstrumentStatus[] = [
  'BORRADOR',
  'ACTIVO',
  'ARCHIVADO',
];

/** Las seis dimensiones del modelo, copiadas de VALIDATION_DIMENSIONS. */
export type ValidationDimension =
  | 'identidad'
  | 'dispositivo'
  | 'red'
  | 'aplicacion'
  | 'datos'
  | 'monitoreo';

export const VALIDATION_DIMENSIONS: readonly ValidationDimension[] = [
  'identidad',
  'dispositivo',
  'red',
  'aplicacion',
  'datos',
  'monitoreo',
];

/** Etiquetas de presentacion; los identificadores tecnicos no se traducen. */
export const VALIDATION_DIMENSION_LABELS: Record<ValidationDimension, string> = {
  identidad: 'Identidad',
  dispositivo: 'Dispositivo',
  red: 'Red',
  aplicacion: 'Aplicación',
  datos: 'Datos',
  monitoreo: 'Monitoreo',
};

/** Veredictos admitidos por el backend (VERDICTS). Los declara el experto. */
export type ExpertVerdict = 'NO_CUMPLE' | 'CUMPLE_PARCIALMENTE' | 'CUMPLE';

export const EXPERT_VERDICTS: readonly ExpertVerdict[] = [
  'NO_CUMPLE',
  'CUMPLE_PARCIALMENTE',
  'CUMPLE',
];

export const EXPERT_VERDICT_LABELS: Record<ExpertVerdict, string> = {
  NO_CUMPLE: 'No cumple',
  CUMPLE_PARCIALMENTE: 'Cumple parcialmente',
  CUMPLE: 'Cumple',
};

/** Objetivos de tesis admitidos por el backend (REPORT_OBJECTIVES). */
export type ReportObjective = 'O1' | 'O2' | 'O3' | 'O4';

export const REPORT_OBJECTIVES: readonly ReportObjective[] = ['O1', 'O2', 'O3', 'O4'];

export const REPORT_OBJECTIVE_LABELS: Record<ReportObjective, string> = {
  O1: 'O1 · Diagnóstico y hallazgos',
  O2: 'O2 · Riesgos y evaluación de activos',
  O3: 'O3 · Controles y su evidencia',
  O4: 'O4 · Incidentes, auditoría e indicadores',
};

/** Origen no declarado: centinela del backend, no es una consulta real. */
export const UNDECLARED_EVIDENCE_SOURCE = 'undeclared';

/** Item de un instrumento de medida (instrument_items). */
export interface InstrumentItem {
  id: string;
  instrument_id: string;
  code: string;
  dimension: ValidationDimension;
  statement: string;
  /** Peso declarado en el instrumento; no es una puntuacion. */
  weight: number;
  position: number;
}

/**
 * Instrumento de validacion. Es una HERRAMIENTA de medida, no una evaluacion.
 * El listado trae item_count; el detalle trae items y no item_count.
 */
export interface Instrument {
  id: string;
  code: string;
  name: string;
  description: string;
  version: string;
  scale_min: number;
  scale_max: number;
  status: InstrumentStatus;
  synthetic: number;
  created_by: string;
  /** Segundos epoch. */
  created_at: number;
  /** Segundos epoch. */
  updated_at: number;
  /** Solo en el listado (subconsulta real de la API). */
  item_count?: number;
  /** Solo en el detalle. */
  items?: InstrumentItem[];
}

export interface InstrumentsResponse {
  instruments: Instrument[];
  count: number;
  environment: string;
}

export interface InstrumentDetailResponse {
  instrument: Instrument;
  environment: string;
}

export interface CreateInstrumentItemRequest {
  code: string;
  dimension: ValidationDimension;
  statement: string;
  weight?: number;
}

export interface CreateInstrumentRequest {
  code: string;
  name: string;
  description?: string;
  version: string;
  scale_min: number;
  scale_max: number;
  /** La API aplica BORRADOR si se omite. */
  status?: InstrumentStatus;
  items: CreateInstrumentItemRequest[];
  // synthetic no se envia: el servidor impone synthetic = 1.
}

/**
 * Respuesta del experto a un item, resuelta por la API con los datos del item
 * (code, dimension, statement y weight) para no tener que recomponerla.
 */
export interface ExpertReviewAnswer {
  id: string;
  review_id: string;
  item_id: string;
  score: number;
  comment: string;
  item_code: string;
  dimension: ValidationDimension;
  statement: string;
  weight: number;
}

/**
 * Dictamen de un experto (expert_reviews).
 *
 * `verdict` es la declaracion del experto y se guarda tal cual. `score` es una
 * media ponderada descriptiva de las respuestas: dato auxiliar, nunca el
 * veredicto.
 */
export interface ExpertReview {
  id: string;
  code: string;
  instrument_id: string;
  instrument_version: string;
  expert_name: string;
  expert_role: string;
  expert_affiliation: string;
  scope: string;
  verdict: ExpertVerdict;
  observations: string;
  score: number | null;
  /** Fecha declarada por el experto (YYYY-MM-DD). */
  reviewed_at: string;
  synthetic: number;
  created_by: string;
  /** Segundos epoch. */
  created_at: number;
  /** Solo en el listado. */
  answers_count?: number;
  /** Solo en el detalle. */
  answers?: ExpertReviewAnswer[];
}

export interface ValidationsResponse {
  validations: ExpertReview[];
  count: number;
  environment: string;
}

export interface ValidationDetailResponse {
  validation: ExpertReview;
  environment: string;
}

export interface SubmitValidationAnswerRequest {
  item_id: string;
  score: number;
  comment?: string;
}

export interface SubmitValidationRequest {
  code?: string;
  instrument_id: string;
  expert_name: string;
  expert_role: string;
  expert_affiliation?: string;
  scope?: string;
  /** Veredicto declarado por el experto: la interfaz no lo calcula. */
  verdict: ExpertVerdict;
  observations?: string;
  /** YYYY-MM-DD; la API usa la fecha del dia si se omite. */
  reviewed_at?: string;
  answers: SubmitValidationAnswerRequest[];
  // synthetic no se envia: el servidor impone synthetic = 1.
}

/**
 * Elemento del inventario de evidencia. Es DERIVADO: no existe como tabla y
 * desaparece si su fuente desaparece. `reference` es un id o codigo real y
 * `source` la operacion real que lo produce (o el centinela 'undeclared').
 */
export interface EvidenceElement {
  objective: ReportObjective;
  module: string;
  kind: string;
  reference: string;
  description: string;
  /** ISO 8601 o YYYY-MM-DD; null si la fuente no declara fecha. */
  date: string | null;
  source: string;
  synthetic: number | null;
  links?: Record<string, string | number | null>;
}

/** Grupo por objetivo. `empty` y `declaration` los fija la API. */
export interface EvidenceGroup {
  objective: ReportObjective;
  items: EvidenceElement[];
  count: number;
  empty: boolean;
  declaration: 'CON_EVIDENCIA' | 'SIN_EVIDENCIA';
}

export interface EvidenceResponse {
  objectives: EvidenceGroup[];
  total: number;
  objective_filter: ReportObjective | null;
  environment: string;
}

/** Informe tal como lo devuelve el listado (sin contenido). */
export interface ReportSummary {
  id: string;
  code: string;
  title: string;
  objective: ReportObjective;
  period_from: string;
  period_to: string;
  content_hash: string;
  generated_by: string;
  /** Segundos epoch. */
  generated_at: number;
  synthetic: number;
}

/** Informe con su Markdown integro: sha256(content) === content_hash. */
export interface Report extends ReportSummary {
  content: string;
}

export interface ReportsResponse {
  reports: ReportSummary[];
  count: number;
  environment: string;
}

export interface ReportDetailResponse {
  report: Report;
  environment: string;
}

export interface GenerateReportRequest {
  objective: ReportObjective;
  /** YYYY-MM-DD, inclusivo. */
  period_from: string;
  period_to: string;
  /** Opcional: la API genera un titulo si se omite. */
  title?: string;
  // El contenido NO se envia: lo construye el backend con datos reales.
}

/** Codigos estables que la API usa para que la pantalla explique el fallo. */
export const VALIDATION_ERROR_CODES: readonly string[] = [
  'INSTRUMENT_NOT_FOUND',
  'INSTRUMENT_INVALID',
  'INSTRUMENT_ALREADY_EXISTS',
  'VALIDATION_NOT_FOUND',
  'VALIDATION_INVALID',
  'VALIDATION_ALREADY_EXISTS',
  'EVIDENCE_OBJECTIVE_INVALID',
  'REPORT_NOT_FOUND',
  'REPORT_INVALID',
  'INSTRUMENTS_ROLE_REQUIRED',
  'VALIDATIONS_ROLE_REQUIRED',
  'EVIDENCE_ROLE_REQUIRED',
  'REPORTS_ROLE_REQUIRED',
  'PLATFORM_ADMIN_ROLE_REQUIRED',
  'MFA_AUTHENTICATION_REQUIRED',
];

/** Codigo estable del backend, sin reinterpretarlo. */
export function validationErrorCode(err: unknown): string | null {
  if (err instanceof HttpErrorResponse) {
    const body = err.error as { code?: unknown } | null;
    return typeof body?.code === 'string' ? body.code : null;
  }
  return null;
}

/**
 * Mensaje util en espanol para la pantalla, conservando el codigo estable.
 * Se usa el mensaje de la API (autoridad) y se anexa el codigo.
 */
export function describeValidationError(err: unknown): string {
  if (!(err instanceof HttpErrorResponse)) {
    return 'No se pudo completar la operación de validación.';
  }
  const code = validationErrorCode(err);
  const body = err.error as { message?: unknown; fields?: unknown } | null;
  const apiMessage = typeof body?.message === 'string' ? body.message : null;

  let fallback = `La solicitud de validación falló con el estado ${err.status}.`;
  if (err.status === 403) {
    fallback =
      code === 'MFA_AUTHENTICATION_REQUIRED'
        ? 'Operación rechazada: se requiere segundo factor (MFA) acreditado.'
        : 'Acceso denegado: rol insuficiente para esta operación de validación.';
  } else if (err.status === 404) {
    fallback = 'El recurso solicitado no existe en la API.';
  } else if (err.status === 409) {
    fallback = 'La operación entra en conflicto con el estado actual.';
  } else if (err.status === 400) {
    fallback = 'La API rechazó los datos enviados.';
  }

  // La API detalla en `fields` los campos rechazados del instrumento: se
  // anexan para que el formulario explique el motivo real, no solo el codigo.
  let fieldDetail = '';
  const rawFields = body?.fields;
  if (rawFields && typeof rawFields === 'object' && !Array.isArray(rawFields)) {
    const entries = Object.entries(rawFields as Record<string, unknown>)
      .filter(([, value]) => typeof value === 'string')
      .slice(0, 6)
      .map(([field, value]) => `${field}: ${String(value)}`);
    if (entries.length > 0) {
      fieldDetail = ` Campos rechazados: ${entries.join('; ')}.`;
    }
  }

  const message = apiMessage ?? fallback;
  return `${code ? `${message} [${code}]` : message}${fieldDetail}`;
}

@Injectable({ providedIn: 'root' })
export class ValidationService {
  private readonly http = inject(HttpClient);
  private readonly instrumentsUrl = '/api/v1/instruments';
  private readonly validationsUrl = '/api/v1/validations';
  private readonly evidenceUrl = '/api/v1/evidence';
  private readonly reportsUrl = '/api/v1/reports';

  listInstruments(): Observable<InstrumentsResponse> {
    return this.http.get<InstrumentsResponse>(this.instrumentsUrl);
  }

  getInstrument(idOrCode: string): Observable<InstrumentDetailResponse> {
    return this.http.get<InstrumentDetailResponse>(
      `${this.instrumentsUrl}/${encodeURIComponent(idOrCode)}`,
    );
  }

  createInstrument(payload: CreateInstrumentRequest): Observable<InstrumentDetailResponse> {
    return this.http.post<InstrumentDetailResponse>(this.instrumentsUrl, payload);
  }

  listValidations(): Observable<ValidationsResponse> {
    return this.http.get<ValidationsResponse>(this.validationsUrl);
  }

  getValidation(idOrCode: string): Observable<ValidationDetailResponse> {
    return this.http.get<ValidationDetailResponse>(
      `${this.validationsUrl}/${encodeURIComponent(idOrCode)}`,
    );
  }

  submitValidation(payload: SubmitValidationRequest): Observable<ValidationDetailResponse> {
    return this.http.post<ValidationDetailResponse>(this.validationsUrl, payload);
  }

  /**
   * Evidencia derivada por objetivo. Sin argumento la API devuelve los cuatro
   * objetivos, cada uno con su declaracion CON_EVIDENCIA / SIN_EVIDENCIA.
   */
  listEvidence(objective?: ReportObjective | null): Observable<EvidenceResponse> {
    let params = new HttpParams();
    if (objective) params = params.set('objective', objective);
    return this.http.get<EvidenceResponse>(this.evidenceUrl, { params });
  }

  listReports(): Observable<ReportsResponse> {
    return this.http.get<ReportsResponse>(this.reportsUrl);
  }

  getReport(idOrCode: string): Observable<ReportDetailResponse> {
    return this.http.get<ReportDetailResponse>(
      `${this.reportsUrl}/${encodeURIComponent(idOrCode)}`,
    );
  }

  generateReport(payload: GenerateReportRequest): Observable<ReportDetailResponse> {
    return this.http.post<ReportDetailResponse>(this.reportsUrl, payload);
  }
}
