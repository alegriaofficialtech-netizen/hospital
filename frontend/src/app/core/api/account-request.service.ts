import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export interface AccountRequest {
  full_name: string;
  email: string;
  justification: string;
}

export interface AccountRequestResponse {
  request_id: string;
  status: string;
  message: string;
}

/**
 * Account request channel.
 *
 * The request grants no access: it is recorded in the audit trail and an
 * administrator authorizes it and creates the identity in Keycloak from the
 * F1b module. There is no public self-registration in the realm.
 */
@Injectable({ providedIn: 'root' })
export class AccountRequestService {
  private readonly http = inject(HttpClient);

  submit(request: AccountRequest): Observable<AccountRequestResponse> {
    return this.http.post<AccountRequestResponse>('/api/v1/identity-requests', request);
  }
}