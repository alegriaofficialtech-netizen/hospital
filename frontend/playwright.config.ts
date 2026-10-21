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
 *
 * F11 overrides:
 *   F11_BASE_URL, F11_API_BASE_URL, F11_CREDENTIALS_FILE, F11_SECRETS_FILE.
 * The E2E container sets F11_CHROMIUM_NO_SANDBOX=1 only for its isolated root
 * Chromium process.
 */
const baseURL = process.env.F11_BASE_URL ?? 'http://127.0.0.1:4200';
const launchOptions =
  process.env.F11_CHROMIUM_NO_SANDBOX === '1'
    ? { args: ['--no-sandbox'] }
    : {};

export default defineConfig({
  testDir: './e2e',
  timeout: 300_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL,
    launchOptions,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },
});
