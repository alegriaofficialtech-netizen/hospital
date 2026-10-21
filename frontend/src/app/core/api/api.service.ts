import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import {
  AuditEventsResponse,
  CreateOrderRequest,
  CreateOrderResponse,
  HealthResponse,
  OrdersResponse,
  ValidateOrderRequest,
  ValidateOrderResponse,
} from '../models';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = environment.apiBaseUrl.replace(/\/$/, '');

  getHealth(): Observable<HealthResponse> {
    return this.http.get<HealthResponse>(`${this.baseUrl}/health`);
  }

  listOrders(): Observable<OrdersResponse> {
    return this.http.get<OrdersResponse>(`${this.baseUrl}/api/v1/orders`);
  }

  createOrder(body: CreateOrderRequest): Observable<CreateOrderResponse> {
    return this.http.post<CreateOrderResponse>(`${this.baseUrl}/api/v1/orders`, body);
  }

  validateOrder(body: ValidateOrderRequest): Observable<ValidateOrderResponse> {
    return this.http.post<ValidateOrderResponse>(
      `${this.baseUrl}/api/v1/orders/validate`,
      body,
    );
  }

  getAuditEvents(): Observable<AuditEventsResponse> {
    return this.http.get<AuditEventsResponse>(`${this.baseUrl}/api/v1/audit/events`);
  }
}
