import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { map, Observable } from 'rxjs';

export interface ClinicalIdentity {
  id: string;
  username: string;
  enabled: boolean;
  synthetic: boolean;
  realm_roles: string[];
  email_verified: boolean;
}

export interface IdentitySummary {
  total: number;
  enabled: number;
  disabled: number;
  mfa_required: number;
  by_role: Record<string, number>;
}

export interface RealmRole {
  id: string;
  name: string;
  description: string;
  composite: boolean;
}

export interface CreatedIdentity {
  identity: ClinicalIdentity;
  credential_file: string;
  note: string;
}

export interface ResetCredential {
  id: string;
  credential_file: string;
  note: string;
}

/**
 * Cliente de la administracion de identidades.
 *
 * No maneja ninguna credencial administrativa: el backend es el proxy de
 * confianza hacia Keycloak. Tampoco devuelve contrasenas al navegador: la
 * credencial generada queda en un fichero protegido en el servidor y aqui solo
 * se conoce su ruta.
 */
@Injectable({ providedIn: 'root' })
export class AdminService {
  private readonly http = inject(HttpClient);

  listIdentities(): Observable<ClinicalIdentity[]> {
    return this.http
      .get<{ identities: ClinicalIdentity[] }>('/api/v1/admin/identities')
      .pipe(map((payload) => payload.identities));
  }

  summary(): Observable<IdentitySummary> {
    return this.http
      .get<{ summary: IdentitySummary }>('/api/v1/admin/identities')
      .pipe(map((payload) => payload.summary));
  }

  listRoles(): Observable<RealmRole[]> {
    return this.http.get<{ roles: RealmRole[] }>('/api/v1/admin/roles').pipe(mapRoles());
  }

  createIdentity(payload: {
    username: string;
    roles: string[];
    require_mfa: boolean;
  }): Observable<CreatedIdentity> {
    return this.http.post<CreatedIdentity>('/api/v1/admin/identities', payload);
  }

  setIdentityState(
    id: string,
    payload: { enabled?: boolean; roles?: string[] },
  ): Observable<{ id: string; enabled: boolean | null; roles: string[] | null }> {
    return this.http.post<{ id: string; enabled: boolean | null; roles: string[] | null }>(
      `/api/v1/admin/identities/${encodeURIComponent(id)}/state`,
      payload,
    );
  }

  resetPassword(id: string): Observable<ResetCredential> {
    return this.http.post<ResetCredential>(
      `/api/v1/admin/identities/${encodeURIComponent(id)}/password`,
      {},
    );
  }
}
