export const environment = {
  production: true,
  useMockApi: false,
  useMockAuth: false,
  apiBaseUrl: '',
  keycloak: {
    // Placeholder for the canonical public issuer. Replace with the deployment URL.
    url: 'https://servidor-1.tailb0f78a.ts.net:8443',
    realm: 'hospital-lab',
    clientId: 'clinical-poc',
  },
};
