import { HttpClient, HttpErrorResponse, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

/**
 * Cliente de Monitorizacion de seguridad (M6) e indicadores M8 (F4).
 *
 * Contrato copiado de la API real:
 * - GET  /api/v1/incidents            -> {"incidents": [], "count": n, "environment": "..."}
 * - GET  /api/v1/incidents/{id|code}  -> {"incident": {}, "updates": [], "environment": "..."}
 * - POST /api/v1/incidents            -> 201 {"incident": {}, "environment": "..."}
 * - POST /api/v1/incidents/{id}       -> 200 {"incident": {}, "environment": "..."}
 * - GET  /api/v1/alerts               -> {"alerts": [], "count": n, "environment": "..."}
 * - POST /api/v1/alerts/{id}/ack      -> 200 {"alert": {}, "environment": "..."}
 * - GET  /api/v1/indicators           -> {"indicators": [], "count": n, "environment": "..."}
 *
 * Las marcas de tiempo de la API son segundos epoch (float), no milisegundos:
 * la vista las convierte antes de pasarlas al DatePipe.
 */

/** Severidad admitida por el backend (INCIDENT_SEVERITIES). */
export type IncidentSeverity = 'BAJA' | 'MEDIA' | 'ALTA' | 'CRITICA';

/** Estado del ciclo de vida admitido por el backend (INCIDENT_STATUSES). */
export type IncidentStatus = 'ABIERTO' | 'EN_INVESTIGACION' | 'MITIGADO' | 'CERRADO';

export const INCIDENT_SEVERITIES: readonly IncidentSeverity[] = [
  'BAJA',
  'MEDIA',
  'ALTA',
  'CRITICA',
];

export const INCIDENT_STATUSES: readonly IncidentStatus[] = [
  'ABIERTO',
  'EN_INVESTIGACION',
  'MITIGADO',
  'CERRADO',
];

/**
 * Diagrama de transiciones validas, copia de INCIDENT_TRANSITIONS
 * (backend/database.py). CERRADO es terminal. La interfaz solo ofrece estos
 * destinos; la API sigue siendo la autoridad y responde 409
 * INCIDENT_TRANSITION_INVALID si la transicion no es valida.
 */
export const INCIDENT_TRANSITIONS: Record<IncidentStatus, readonly IncidentStatus[]> = {
  ABIERTO: ['EN_INVESTIGACION', 'MITIGADO', 'CERRADO'],
  EN_INVESTIGACION: ['MITIGADO', 'CERRADO'],
  MITIGADO: ['CERRADO', 'EN_INVESTIGACION'],
  CERRADO: [],
};

/**
 * Severidad de una alerta derivada (backend/alert_management.py).
 *
 * Se declara como tipo propio para no mezclar el contrato de alertas con el de
 * incidentes, aunque hoy compartan el mismo vocabulario.
 */
export type AlertSeverity = 'BAJA' | 'MEDIA' | 'ALTA' | 'CRITICA';

/** Estados posibles de un indicador M8. */
export type IndicatorStatus = 'OK' | 'ATENCION' | 'CRITICO';

/** Origen no declarado: centinela del backend, no es una consulta real. */
export const UNDECLARED_SOURCE = 'undeclared';

/** Incidente tal como lo devuelve la API (fila completa de incidents). */
export interface Incident {
  id: string;
  code: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  /** Segundos epoch. */
  detected_at: number;
  /** Segundos epoch, o null mientras el incidente no esta cerrado. */
  closed_at: number | null;
  asset_id: string | null;
  risk_id: string | null;
  control_id: string | null;
  owner_role: string;
  synthetic: number;
  revision: number;
  created_by: string;
  /** Segundos epoch. */
  created_at: number;
  /** Segundos epoch. */
  updated_at: number;
}

/** Fila inmutable del historial de transiciones (incident_updates). */
export interface IncidentUpdate {
  id: string;
  incident_id: string;
  from_status: string | null;
  to_status: string;
  note: string;
  actor: string;
  /** Segundos epoch. */
  occurred_at: number;
}

export interface IncidentFilters {
  status?: IncidentStatus | null;
  severity?: IncidentSeverity | null;
}

export interface IncidentsResponse {
  incidents: Incident[];
  count: number;
  /** La API siempre devuelve el entorno de evidencia. */
  environment: string;
}

export interface IncidentDetailResponse {
  incident: Incident;
  /** Historial completo, en orden ascendente por occurred_at. */
  updates: IncidentUpdate[];
  environment: string;
}

export interface CreateIncidentRequest {
  code: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  /** Opcional: la API aplica ABIERTO por defecto. */
  status?: IncidentStatus;
  /** Segundos epoch. Si se omite, la API usa el instante del alta. */
  detected_at?: number | null;
  asset_id?: string | null;
  risk_id?: string | null;
  control_id?: string | null;
  owner_role?: string;
  // synthetic no se envia: el servidor lo impone (synthetic = 1) e ignora
  // cualquier valor que llegue del navegador.
}

export interface TransitionIncidentRequest {
  to_status: IncidentStatus;
  /** Obligatoria en la interfaz: toda transicion deja rastro auditable. */
  note: string;
}

export interface IncidentCreateResponse {
  incident: Incident;
  environment: string;
}

export interface IncidentTransitionResponse {
  incident: Incident;
  environment: string;
}

/**
 * Alerta derivada del estado real.
 *
 * No es una fila persistida: se calcula en cada consulta y solo el acuse vive
 * en alert_acknowledgements. `evidence` es texto literal (consulta ejecutada y
 * su resultado): se muestra tal cual, sin reformatear.
 */
export interface Alert {
  /** Id determinista: ALR- + sha1(regla|sujeto)[:8]. */
  id: string;
  rule: string;
  severity: AlertSeverity;
  title: string;
  subject: string;
  evidence: string;
  /** Segundos epoch. */
  detected_at: number;
  acknowledged: boolean;
  acknowledged_by: string | null;
  /** Segundos epoch, o null si no esta acusada. */
  acknowledged_at: number | null;
}

export interface AlertsResponse {
  alerts: Alert[];
  count: number;
  environment: string;
}

/** Fila de alert_acknowledgements devuelta por el acuse. */
export interface AlertAcknowledgement {
  alert_id: string;
  acknowledged_by: string;
  /** Segundos epoch. */
  acknowledged_at: number;
  note: string;
}

export interface AcknowledgeAlertResponse {
  alert: AlertAcknowledgement;
  environment: string;
}

/** Indicador M8 con el origen real del dato. */
export interface Indicator {
  code: string;
  name: string;
  /** null significa "sin dato": la vista no debe pintar un cero. */
  value: number | string | null;
  unit: string | null;
  status: IndicatorStatus;
  /** Consulta u operacion real que produce el dato, o 'undeclared'. */
  source: string;
  /** Solo viene cuando el backend declara un objetivo. */
  target?: number | string | null;
}

export interface IndicatorsResponse {
  indicators: Indicator[];
  count: number;
  environment: string;
}

/** Codigos estables que la API usa para que la pantalla explique el fallo. */
export const MONITORING_ERROR_CODES: readonly string[] = [
  'INCIDENT_NOT_FOUND',
  'INCIDENT_TRANSITION_INVALID',
  'INCIDENT_ALREADY_EXISTS',
  'INCIDENT_INVALID',
  'ALERT_NOT_FOUND',
  'INCIDENTS_ROLE_REQUIRED',
  'ALERTS_ROLE_REQUIRED',
  'INDICATORS_ROLE_REQUIRED',
  'PLATFORM_ADMIN_ROLE_REQUIRED',
  'MFA_AUTHENTICATION_REQUIRED',
];

/**
 * Codigo estable del backend, sin reinterpretarlo.
 *
 * La pantalla decide con este codigo (por ejemplo, no tocar el estado mostrado
 * ante INCIDENT_TRANSITION_INVALID). Devolver null cuando el cuerpo no trae
 * codigo evita inventar una causa.
 */
export function monitoringErrorCode(err: unknown): string | null {
  if (err instanceof HttpErrorResponse) {
    const body = err.error as { code?: unknown } | null;
    return typeof body?.code === 'string' ? body.code : null;
  }
  return null;
}

/**
 * Mensaje util en espanol para la pantalla, conservando el codigo estable.
 *
 * Se usa el mensaje de la API (autoridad) y se anexa el codigo para que el
 * operador pueda citarlo en la auditoria.
 */
export function describeMonitoringError(err: unknown): string {
  if (!(err instanceof HttpErrorResponse)) {
    return 'No se pudo completar la operacion de monitorizacion.';
  }
  const code = monitoringErrorCode(err);
  const body = err.error as { message?: unknown } | null;
  const apiMessage = typeof body?.message === 'string' ? body.message : null;

  // Mensajes propios solo cuando la API no explica el motivo.
  let fallback = `La solicitud de monitorizacion fallo con el estado ${err.status}.`;
  if (err.status === 403) {
    fallback =
      code === 'MFA_AUTHENTICATION_REQUIRED'
        ? 'Operacion rechazada: se requiere segundo factor (MFA) acreditado.'
        : 'Acceso denegado: rol insuficiente para esta operacion de monitorizacion.';
  } else if (err.status === 404) {
    fallback = 'El recurso solicitado no existe en la API.';
  } else if (err.status === 409) {
    fallback = 'La operacion entra en conflicto con el estado actual.';
  } else if (err.status === 400) {
    fallback = 'La API rechazo los datos enviados.';
  }

  const message = apiMessage ?? fallback;
  return code ? `${message} [${code}]` : message;
}

@Injectable({ providedIn: 'root' })
export class MonitoringService {
  private readonly http = inject(HttpClient);
  private readonly incidentsUrl = '/api/v1/incidents';
  private readonly alertsUrl = '/api/v1/alerts';
  private readonly indicatorsUrl = '/api/v1/indicators';

  listIncidents(filters: IncidentFilters = {}): Observable<IncidentsResponse> {
    let params = new HttpParams();
    if (filters.status) params = params.set('status', filters.status);
    if (filters.severity) params = params.set('severity', filters.severity);

    return this.http.get<IncidentsResponse>(this.incidentsUrl, { params });
  }

  getIncident(idOrCode: string): Observable<IncidentDetailResponse> {
    return this.http.get<IncidentDetailResponse>(
      `${this.incidentsUrl}/${encodeURIComponent(idOrCode)}`,
    );
  }

  createIncident(payload: CreateIncidentRequest): Observable<IncidentCreateResponse> {
    return this.http.post<IncidentCreateResponse>(this.incidentsUrl, payload);
  }

  transitionIncident(
    idOrCode: string,
    payload: TransitionIncidentRequest,
  ): Observable<IncidentTransitionResponse> {
    return this.http.post<IncidentTransitionResponse>(
      `${this.incidentsUrl}/${encodeURIComponent(idOrCode)}`,
      payload,
    );
  }

  listAlerts(): Observable<AlertsResponse> {
    return this.http.get<AlertsResponse>(this.alertsUrl);
  }

  acknowledgeAlert(alertId: string, note: string): Observable<AcknowledgeAlertResponse> {
    return this.http.post<AcknowledgeAlertResponse>(
      `${this.alertsUrl}/${encodeURIComponent(alertId)}/ack`,
      { note },
    );
  }

  listIndicators(): Observable<IndicatorsResponse> {
    return this.http.get<IndicatorsResponse>(this.indicatorsUrl);
  }
}
