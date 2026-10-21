import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { AuditEventsResponse } from '../../core/models';
import { DashboardComponent } from './dashboard.component';

const AUDIT_RESPONSE: AuditEventsResponse = {
  audit_chain_valid: true,
  chain_error: null,
  total_events: 1,
  events: [],
};

describe('DashboardComponent', () => {
  let httpMock: HttpTestingController;
  let auth: AuthService;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      imports: [DashboardComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
        provideRouter([]),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('does not request clinical orders for the auditor role', () => {
    auth.loginDemo('ROLE_SECURITY_AUDITOR', 'demo.auditor');
    const fixture = TestBed.createComponent(DashboardComponent);
    fixture.detectChanges();

    const auditRequest = httpMock.expectOne('/api/v1/audit/events');
    auditRequest.flush(AUDIT_RESPONSE);
    fixture.detectChanges();

    expect(fixture.componentInstance.canViewOrders()).toBe(false);
    expect(fixture.nativeElement.textContent).toContain('Cadena de auditoría');
  });

  it('requests orders for a clinical role', () => {
    auth.loginDemo('ROLE_RECEPTION', 'demo.reception');
    const fixture = TestBed.createComponent(DashboardComponent);
    fixture.detectChanges();

    const ordersRequest = httpMock.expectOne('/api/v1/orders');
    ordersRequest.flush({ orders: [], count: 0 });
    fixture.detectChanges();

    expect(fixture.componentInstance.canViewOrders()).toBe(true);
  });
});
