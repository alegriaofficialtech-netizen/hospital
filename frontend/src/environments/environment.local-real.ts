/**
 * Local real-integration profile.
 *
 * This profile is intentionally separate from both the mock default and the
 * production build. It targets only the isolated local Keycloak/backend stack
 * documented in `infra/local-test/README.md`.
 */
export const environment = {
  production: false,
  useMockApi: false,
  useMockAuth: false,
  apiBaseUrl: '',
  keycloak: {
    url: 'http://127.0.0.1:8085',
    realm: 'hospital-lab-local',
    clientId: 'clinical-poc',
  },
};
