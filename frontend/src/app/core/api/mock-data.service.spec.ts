import { TestBed } from '@angular/core/testing';
import { AuthService } from '../auth/auth.service';
import { MockApiError, MockDataService } from './mock-data.service';

describe('MockDataService', () => {
  let service: MockDataService;
  let auth: AuthService;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(MockDataService);
    auth = TestBed.inject(AuthService);
    auth.loginDemo('ROLE_RECEPTION', 'demo.reception');
  });

  it('seeds six synthetic orders across all statuses', () => {
    const response = service.listOrders();

    expect(response.count).toBe(6);
    expect(new Set(response.orders.map((order) => order.status))).toEqual(
      new Set(['CREATED', 'SAMPLE_COLLECTED', 'ANALYZED', 'VALIDATED_AND_RELEASED']),
    );

    const analyzed = response.orders.filter((order) => order.status === 'ANALYZED');
    expect(analyzed).toHaveLength(2);
    for (const order of analyzed) {
      expect(order.measurements['hemoglobina_g_dl']).toBeGreaterThan(0);
      expect(order.measurements['leucocitos_mil_ul']).toBeGreaterThan(0);
      expect(order.measurements['plaquetas_mil_ul']).toBeGreaterThan(0);
    }
  });

  it('creates an order as SAMPLE_COLLECTED and appends an audit event', () => {
    const auditBefore = service.getAuditEvents().total_events;

    const response = service.createOrder({
      order_id: 'ORD-2026-0100',
      patient_dni: 'DEMO-0100',
      test_type: 'GLUCOSE',
    });

    expect(response.status).toBe('CREATED');
    expect(response.order.status).toBe('SAMPLE_COLLECTED');
    expect(response.order.version).toBe(1);
    expect(response.order.created_by).toBe('demo.reception');
    expect(service.listOrders().count).toBe(7);

    const audit = service.getAuditEvents();
    expect(audit.total_events).toBe(auditBefore + 1);
    expect(audit.events[audit.events.length - 1].action).toBe('CREATE_ORDER');
  });

  it('rejects duplicate order IDs with status 409', () => {
    try {
      service.createOrder({
        order_id: 'ORD-2026-0001',
        patient_dni: 'DEMO-0001',
        test_type: 'GLUCOSE',
      });
      expect.unreachable('duplicate order should throw');
    } catch (error) {
      expect(error).toBeInstanceOf(MockApiError);
      expect((error as MockApiError).status).toBe(409);
      expect((error as MockApiError).code).toBe('ORDER_ALREADY_EXISTS');
    }
  });

  it('requires MFA before validation', () => {
    const analyzed = service.listOrders().orders.find((order) => order.status === 'ANALYZED');
    expect(analyzed).toBeDefined();

    expect(() =>
      service.validateOrder({ order_id: analyzed!.order_id, observations: 'Synthetic' }),
    ).toThrowError(MockApiError);
  });

  it('validates only ANALYZED orders and releases them with observations', () => {
    auth.loginDemo('ROLE_PATHOLOGIST', 'demo.pathologist');
    auth.markMfaVerified();
    const analyzed = service.listOrders().orders.find((order) => order.status === 'ANALYZED')!;

    const response = service.validateOrder({
      order_id: analyzed.order_id,
      observations: 'Valores sintéticos revisados.',
    });

    expect(response.status).toBe('SUCCESS');
    expect(response.order.status).toBe('VALIDATED_AND_RELEASED');
    expect(response.order.observations).toBe('Valores sintéticos revisados.');
    expect(response.order.validated_by).toBe('demo.pathologist');
    expect(response.order.validated_at).toBeTruthy();
    expect(response.order.version).toBe(analyzed.version + 1);
    expect(response.order.integrity_verified).toBe(true);
  });

  it('rejects validation of non-ANALYZED orders with status 409', () => {
    auth.loginDemo('ROLE_PATHOLOGIST', 'demo.pathologist');
    auth.markMfaVerified();
    const collected = service
      .listOrders()
      .orders.find((order) => order.status === 'SAMPLE_COLLECTED')!;

    try {
      service.validateOrder({ order_id: collected.order_id, observations: 'Synthetic' });
      expect.unreachable('non-analyzed order should throw');
    } catch (error) {
      expect(error).toBeInstanceOf(MockApiError);
      expect((error as MockApiError).status).toBe(409);
      expect((error as MockApiError).code).toBe('INVALID_STATUS_TRANSITION');
    }
  });

  it('builds a linked, valid mock audit chain', () => {
    const audit = service.getAuditEvents();

    expect(audit.audit_chain_valid).toBe(true);
    expect(audit.chain_error).toBeNull();
    expect(audit.total_events).toBe(4);
    expect(audit.events.map((event) => event.action)).toEqual([
      'CREATE_ORDER',
      'VALIDATE_ORDER',
      'GET_ORDERS',
      'GET_AUDIT_LOGS',
    ]);
    expect(audit.events[0].prev_hash).toBe('0'.repeat(64));
    for (let index = 1; index < audit.events.length; index += 1) {
      expect(audit.events[index].prev_hash).toBe(audit.events[index - 1].hash);
    }
  });
});
