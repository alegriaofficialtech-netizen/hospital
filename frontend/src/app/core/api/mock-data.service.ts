import { Injectable, inject } from '@angular/core';
import {
  AuditEvent,
  AuditEventsResponse,
  ClinicalOrder,
  CreateOrderRequest,
  CreateOrderResponse,
  HealthResponse,
  OrdersResponse,
  SessionUser,
  ValidateOrderRequest,
  ValidateOrderResponse,
} from '../models';
import { AuthService } from '../auth/auth.service';

const ZERO_HASH = '0'.repeat(64);

export class MockApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'MockApiError';
  }
}

function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function cloneOrder(order: ClinicalOrder): ClinicalOrder {
  return { ...order, measurements: { ...order.measurements } };
}

@Injectable({ providedIn: 'root' })
export class MockDataService {
  private readonly auth = inject(AuthService);
  private readonly orders: ClinicalOrder[] = this.seedOrders();
  private readonly events: AuditEvent[] = [];
  private orderSequence = this.orders.length + 1;

  constructor() {
    this.seedAuditEvents();
  }

  listOrders(): OrdersResponse {
    const orders = this.orders.map(cloneOrder);
    return { orders, count: orders.length };
  }

  createOrder(body: CreateOrderRequest): CreateOrderResponse {
    const orderId = (body.order_id ?? '').trim().toUpperCase();
    const patientDni = (body.patient_dni ?? '').trim().toUpperCase();
    const testType = (body.test_type ?? '').trim();

    if (!orderId || !patientDni || !testType) {
      throw new MockApiError(
        400,
        'VALIDATION_ERROR',
        'order_id, patient_dni and test_type are required.',
      );
    }
    if (this.orders.some((order) => order.order_id.toUpperCase() === orderId)) {
      throw new MockApiError(
        409,
        'ORDER_ALREADY_EXISTS',
        `Order ${orderId} already exists: overwriting is not allowed.`,
      );
    }

    const session = this.requireSession();
    const order: ClinicalOrder = {
      order_id: orderId,
      patient_dni: patientDni,
      test_type: testType,
      status: 'SAMPLE_COLLECTED',
      created_by: session.username,
      measurements: {},
      validated_by: null,
      created_at: isoNow(),
      version: 1,
    };
    this.orders.push(order);
    this.appendAuditEvent(
      'CREATE_ORDER',
      session,
      'ALLOWED',
      `Synthetic order ${orderId} created for ${testType}.`,
    );
    return { status: 'CREATED', order: cloneOrder(order) };
  }

  validateOrder(body: ValidateOrderRequest): ValidateOrderResponse {
    const session = this.requireSession();
    if (!session.mfaVerified) {
      throw new MockApiError(
        403,
        'MFA_AUTHENTICATION_REQUIRED',
        'La validación clínica exige un factor MFA verificado.',
      );
    }

    const order = this.orders.find((candidate) => candidate.order_id === body.order_id);
    if (!order) {
      throw new MockApiError(404, 'ORDER_NOT_FOUND', `Order ${body.order_id} was not found.`);
    }
    if (order.status !== 'ANALYZED') {
      throw new MockApiError(
        409,
        'INVALID_STATUS_TRANSITION',
        `Only ANALYZED orders can be validated. Current status: ${order.status}.`,
      );
    }

    order.status = 'VALIDATED_AND_RELEASED';
    order.observations = body.observations?.trim() || 'Valores analíticos dentro del rango de referencia.';
    order.validated_by = session.username;
    order.validated_at = isoNow();
    order.version += 1;
    order.integrity_seal = `mock-seal-${this.hash(`${order.order_id}:${order.version}`)}`;
    order.integrity_verified = true;

    this.appendAuditEvent(
      'VALIDATE_ORDER',
      session,
      'ALLOWED',
      `Synthetic report ${order.order_id} validated with MFA.`,
    );
    return {
      status: 'SUCCESS',
      message: `Order ${order.order_id} validated and released.`,
      order: cloneOrder(order),
    };
  }

  getAuditEvents(): AuditEventsResponse {
    const events = this.events.map((event) => ({ ...event }));
    const valid = this.isChainValid(events);
    return {
      audit_chain_valid: valid,
      chain_error: valid ? null : 'Mock audit chain hash linkage mismatch.',
      total_events: events.length,
      events,
    };
  }

  health(): HealthResponse {
    return {
      status: 'HEALTHY',
      system: 'SGSI-ZTA Hospital LIS (Mock)',
      timestamp: Date.now(),
    };
  }

  suggestOrderId(): string {
    const year = new Date().getFullYear();
    return `ORD-${year}-${String(this.orderSequence++).padStart(4, '0')}`;
  }

  private requireSession(): SessionUser {
    const session = this.auth.session();
    if (!session) {
      throw new MockApiError(401, 'UNAUTHENTICATED', 'Authentication is required.');
    }
    return session;
  }

  private appendAuditEvent(
    action: string,
    session: SessionUser,
    status: string,
    details: string,
  ): void {
    const previous = this.events[this.events.length - 1];
    const record = {
      timestamp: isoNow(),
      action,
      actor: session.username,
      role: session.roles.join(','),
      status,
      ip_source: '127.0.0.1',
      details,
      mfa_verified: session.mfaVerified,
      prev_hash: previous?.hash ?? ZERO_HASH,
    };
    this.events.push({ ...record, hash: this.hash(record) });
  }

  private isChainValid(events: AuditEvent[]): boolean {
    let expectedPrevious = ZERO_HASH;
    for (const event of events) {
      if (event.prev_hash !== expectedPrevious) {
        return false;
      }
      expectedPrevious = event.hash;
    }
    return true;
  }

  private hash(payload: unknown): string {
    const text = JSON.stringify(payload);
    let output = '';
    for (let round = 0; round < 8; round += 1) {
      let hash = (2166136261 ^ (round * 2654435761)) >>> 0;
      for (let index = 0; index < text.length; index += 1) {
        hash ^= text.charCodeAt(index);
        hash = Math.imul(hash, 16777619) >>> 0;
      }
      output += hash.toString(16).padStart(8, '0');
    }
    return output.slice(0, 64);
  }

  private seedAuditEvents(): void {
    const seeds = [
      {
        action: 'CREATE_ORDER',
        actor: 'demo.reception',
        role: 'ROLE_RECEPTION',
        status: 'ALLOWED',
        details: 'Synthetic order ORD-2026-0001 created.',
        mfa: false,
        timestamp: '2026-10-14T08:10:00Z',
      },
      {
        action: 'VALIDATE_ORDER',
        actor: 'demo.pathologist',
        role: 'ROLE_PATHOLOGIST',
        status: 'ALLOWED',
        details: 'Synthetic report ORD-2026-0001 validated with MFA.',
        mfa: true,
        timestamp: '2026-10-14T11:45:00Z',
      },
      {
        action: 'GET_ORDERS',
        actor: 'demo.lab.tech',
        role: 'ROLE_LAB_TECH',
        status: 'ALLOWED',
        details: 'Lista de órdenes sintéticas consultada.',
        mfa: false,
        timestamp: '2026-10-15T09:20:00Z',
      },
      {
        action: 'GET_AUDIT_LOGS',
        actor: 'demo.security.auditor',
        role: 'ROLE_SECURITY_AUDITOR',
        status: 'ALLOWED',
        details: 'Cadena de auditoría sintética revisada.',
        mfa: true,
        timestamp: '2026-10-15T10:05:00Z',
      },
    ];

    let previousHash = ZERO_HASH;
    for (const seed of seeds) {
      const record = {
        timestamp: seed.timestamp,
        action: seed.action,
        actor: seed.actor,
        role: seed.role,
        status: seed.status,
        ip_source: '127.0.0.1',
        details: seed.details,
        mfa_verified: seed.mfa,
        prev_hash: previousHash,
      };
      const event: AuditEvent = { ...record, hash: this.hash(record) };
      this.events.push(event);
      previousHash = event.hash;
    }
  }

  private seedOrders(): ClinicalOrder[] {
    return [
      {
        order_id: 'ORD-2026-0001',
        patient_dni: 'DEMO-0001',
        test_type: 'HEMOGRAMA COMPLETO',
        status: 'ANALYZED',
        created_by: 'demo.reception',
        measurements: {
          hemoglobina_g_dl: 13.4,
          leucocitos_mil_ul: 6.8,
          plaquetas_mil_ul: 245,
        },
        validated_by: null,
        created_at: '2026-10-14T08:10:00Z',
        version: 2,
        integrity_verified: null,
      },
      {
        order_id: 'ORD-2026-0002',
        patient_dni: 'DEMO-0002',
        test_type: 'HEMOGLOBIN COMPLETE',
        status: 'ANALYZED',
        created_by: 'demo.reception',
        measurements: {
          hemoglobina_g_dl: 11.9,
          leucocitos_mil_ul: 8.2,
          plaquetas_mil_ul: 190,
        },
        validated_by: null,
        created_at: '2026-10-18T09:30:00Z',
        version: 2,
        integrity_verified: null,
      },
      {
        order_id: 'ORD-2026-0003',
        patient_dni: 'DEMO-0003',
        test_type: 'GLUCOSE',
        status: 'SAMPLE_COLLECTED',
        created_by: 'demo.reception',
        measurements: {},
        validated_by: null,
        created_at: '2026-10-19T10:15:00Z',
        version: 1,
      },
      {
        order_id: 'ORD-2026-0004',
        patient_dni: 'DEMO-0004',
        test_type: 'PERFIL LIPÍDICO',
        status: 'CREATED',
        created_by: 'demo.reception',
        measurements: {},
        validated_by: null,
        created_at: '2026-10-20T08:05:00Z',
        version: 1,
      },
      {
        order_id: 'ORD-2026-0005',
        patient_dni: 'DEMO-0005',
        test_type: 'FUNCIÓN RENAL',
        status: 'VALIDATED_AND_RELEASED',
        created_by: 'demo.reception',
        measurements: {
          creatinina_mg_dl: 0.9,
          sodio_mmol_l: 140,
          potasio_mmol_l: 4.2,
        },
        validated_by: 'demo.pathologist',
        observations: 'Panel renal sintético dentro del rango de referencia.',
        created_at: '2026-10-16T12:00:00Z',
        validated_at: '2026-10-16T16:25:00Z',
        version: 3,
        integrity_seal: 'mock-seed-seal-0005',
        integrity_verified: true,
      },
      {
        order_id: 'ORD-2026-0006',
        patient_dni: 'DEMO-0006',
        test_type: 'GLUCOSE',
        status: 'VALIDATED_AND_RELEASED',
        created_by: 'demo.reception',
        measurements: { glucosa_mg_dl: 94 },
        validated_by: 'demo.pathologist',
        observations: 'Resultado de glucosa sintético liberado.',
        created_at: '2026-10-17T14:40:00Z',
        validated_at: '2026-10-17T18:10:00Z',
        version: 3,
        integrity_seal: 'mock-seed-seal-0006',
        integrity_verified: true,
      },
    ];
  }
}
