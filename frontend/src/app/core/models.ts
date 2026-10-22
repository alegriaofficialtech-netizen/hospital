export type UserRole =
  | 'ROLE_RECEPTION'
  | 'ROLE_LAB_TECH'
  | 'ROLE_PATHOLOGIST'
  | 'ROLE_SECURITY_AUDITOR' | 'ROLE_PLATFORM_ADMIN';;

export const USER_ROLES: readonly UserRole[] = [
  'ROLE_RECEPTION',
  'ROLE_LAB_TECH',
  'ROLE_PATHOLOGIST',
  'ROLE_SECURITY_AUDITOR',
  'ROLE_PLATFORM_ADMIN',
];

export const ROLE_LABELS: Record<UserRole, string> = {
  ROLE_RECEPTION: 'Recepción',
  ROLE_LAB_TECH: 'Técnico de laboratorio',
  ROLE_PATHOLOGIST: 'Patólogo',
  ROLE_SECURITY_AUDITOR: 'Auditor de seguridad',
  ROLE_PLATFORM_ADMIN: 'Administrador de plataforma',
};

export type OrderStatus =
  | 'CREATED'
  | 'SAMPLE_COLLECTED'
  | 'ANALYZED'
  | 'VALIDATED_AND_RELEASED';

export const ORDER_STATUSES: readonly OrderStatus[] = [
  'CREATED',
  'SAMPLE_COLLECTED',
  'ANALYZED',
  'VALIDATED_AND_RELEASED',
];

export const ORDER_STATUS_LABELS: Record<OrderStatus, string> = {
  CREATED: 'Creada',
  SAMPLE_COLLECTED: 'Muestra recogida',
  ANALYZED: 'Analizada',
  VALIDATED_AND_RELEASED: 'Validada y liberada',
};

export const TEST_TYPES = [
  'HEMOGLOBIN COMPLETE',
  'GLUCOSE',
  'LIPID PROFILE',
  'RENAL FUNCTION',
] as const;

export type TestType = (typeof TEST_TYPES)[number];

export interface ClinicalOrder {
  order_id: string;
  patient_dni: string;
  test_type: string;
  status: OrderStatus;
  created_by: string;
  measurements: Record<string, number>;
  validated_by?: string | null;
  created_at: string;
  version: number;
  observations?: string;
  validated_at?: string;
  integrity_seal?: string;
  integrity_verified?: boolean | null;
}

export interface AuditEvent {
  timestamp: string;
  action: string;
  actor: string;
  role: string;
  status: string;
  ip_source: string;
  details: string;
  mfa_verified: boolean;
  prev_hash: string;
  hash: string;
}

export interface HealthResponse {
  status: 'HEALTHY';
  system: string;
  timestamp: number;
}

export interface OrdersResponse {
  orders: ClinicalOrder[];
  count: number;
}

export interface CreateOrderRequest {
  order_id: string;
  patient_dni: string;
  test_type: string;
}

export interface CreateOrderResponse {
  status: 'CREATED';
  order: ClinicalOrder;
}

export interface ValidateOrderRequest {
  order_id: string;
  observations: string;
}

export interface ValidateOrderResponse {
  status: 'SUCCESS';
  message: string;
  order: ClinicalOrder;
}

export interface AuditEventsResponse {
  audit_chain_valid: boolean;
  chain_error: string | null;
  total_events: number;
  events: AuditEvent[];
}

export interface SessionUser {
  username: string;
  displayName: string;
  roles: UserRole[];
  mfaVerified: boolean;
  authMode: 'demo' | 'keycloak';
}

export interface DashboardMetrics {
  totalOrders: number;
  pendingValidation: number;
  released: number;
  auditChainValid: boolean | null;
  auditEvents: number;
}

export function orderStatusSlug(status: OrderStatus): string {
  return status.toLowerCase().replace(/_/g, '-');
}
