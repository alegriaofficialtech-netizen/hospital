import { defineConfig } from '@playwright/test';

/**
 * UI E2E for the isolated local real-mode stack.
 *
 * Start the stack first:
 *   infra/local-test/start-local.ps1 -SkipRealmSetup
 *   cd frontend; npm run start:real
 *
 * Then:
 *   cd frontend; npm run e2e:real
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 300_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://127.0.0.1:4200',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },
});
