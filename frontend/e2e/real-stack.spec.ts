import { expect, test, type Page } from '@playwright/test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const REPO_ROOT = path.resolve(process.cwd(), '..');
const CREDENTIALS_FILE =
  process.env.F11_CREDENTIALS_FILE ??
  path.join(REPO_ROOT, 'infra/local-test/.test-credentials.local.json');
const SECRETS_FILE =
  process.env.F11_SECRETS_FILE ??
  path.join(REPO_ROOT, 'infra/local-test/runtime/backend-secrets.json');
const API_BASE_URL = process.env.F11_API_BASE_URL ?? 'http://127.0.0.1:8000';

interface LocalCredentials {
  users: Record<string, { password: string; totp_secret?: string }>;
}

function readJson<T>(file: string): T {
  if (!fs.existsSync(file)) {
    throw new Error(
      `Missing ${file}. Start the stack or set F11_CREDENTIALS_FILE/F11_SECRETS_FILE.`,
    );
  }
  return JSON.parse(fs.readFileSync(file, 'utf8')) as T;
}

function base32Decode(value: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = value.replace(/=+$/g, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0;
  let buffer = 0;
  const output: number[] = [];
  for (const character of clean) {
    const index = alphabet.indexOf(character);
    if (index < 0) {
      throw new Error(`Invalid Base32 character in TOTP secret: ${character}`);
    }
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function generateTotp(secret: string): string {
  const counter = Math.floor(Date.now() / 1000 / 30);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto
    .createHmac('sha1', base32Decode(secret))
    .update(buffer)
    .digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 1_000_000).padStart(6, '0');
}

async function waitForFreshTotpWindow(): Promise<void> {
  const seconds = (Date.now() / 1000) % 30;
  // Wait until roughly five seconds into the next time step. Keycloak and the
  // host clocks can drift slightly, and a code from the previous step is
  // rejected as a replay.
  const waitMilliseconds = Math.max(0, (35 - seconds) * 1000);
  await new Promise((resolve) => setTimeout(resolve, waitMilliseconds));
}

async function signIn(
  page: Page,
  username: string,
  password: string,
  totpSecret?: string,
): Promise<void> {
  await page.goto('/login');
  await expect(page.getByRole('button', { name: 'Sign in with Keycloak' })).toBeVisible();
  await expect(page.getByText('Demo roles')).toHaveCount(0);
  await page.getByRole('button', { name: 'Sign in with Keycloak' }).click();

  await expect(page.locator('#username')).toBeVisible();
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  await page.locator('#kc-login').click();

  if (totpSecret) {
    await expect(page.locator('#otp')).toBeVisible();
    await waitForFreshTotpWindow();
    await page.locator('#otp').fill(generateTotp(totpSecret));
    await page.locator('#kc-login').click();

    // A replay of the enrollment step can be rejected. Retry once in the next
    // 30-second window rather than masking the failure.
    if (await page.locator('#otp').isVisible().catch(() => false)) {
      await waitForFreshTotpWindow();
      await page.locator('#otp').fill(generateTotp(totpSecret));
      await page.locator('#kc-login').click();
    }
  }

  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 });
}

async function signOut(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/login/, { timeout: 30_000 });
}

function uniqueOrder(): { orderId: string; patientDni: string } {
  const suffix = String(Math.floor(Math.random() * 10_000)).padStart(4, '0');
  return { orderId: `ORD-2026-${suffix}`, patientDni: `DEMO-${suffix}` };
}

test('local real stack: admission, TOTP release, audit, denied access', async ({
  page,
  request,
}) => {
  const credentials = readJson<LocalCredentials>(CREDENTIALS_FILE);
  const secrets = readJson<{ iomtDeviceId: string; iomtDeviceKey: string }>(SECRETS_FILE);
  const { orderId, patientDni } = uniqueOrder();

  await test.step('reception signs in with Keycloak PKCE', async () => {
    await signIn(
      page,
      'recepcion.test',
      credentials.users['recepcion.test'].password,
    );
    await expect(page.getByText('Reception').first()).toBeVisible();
  });

  await test.step('reception creates an order through the UI', async () => {
    await page.getByRole('link', { name: 'Admission' }).click();
    await expect(page.getByRole('heading', { name: 'Admission' })).toBeVisible();
    await page.getByLabel('Order ID').fill(orderId);
    await page.getByLabel('Patient DNI').fill(patientDni);
    await page.getByRole('button', { name: 'Create order' }).click();
    await expect(page.locator('table')).toContainText(orderId);
    await expect(page.locator('table')).toContainText(patientDni);
  });

  await test.step('synthetic analyzer posts results with HMAC', async () => {
    const body = JSON.stringify({
      order_id: orderId,
      measurements: {
        hemoglobina_g_dl: 13.7,
        hematocrito_pct: 41.2,
        leucocitos_mm3: 7200,
        plaquetas_k_ul: 240,
      },
    });
    const timestamp = String(Date.now() / 1000);
    const nonce = crypto.randomBytes(16).toString('hex');
    const signingInput = `${secrets.iomtDeviceId}\n${timestamp}\n${nonce}\n${body}`;
    const signature = crypto
      .createHmac('sha256', secrets.iomtDeviceKey)
      .update(signingInput)
      .digest('hex');
    const response = await request.post(`${API_BASE_URL}/api/v1/iomt/results`, {
      data: body,
      headers: {
        'Content-Type': 'application/json',
        'X-Device-Id': secrets.iomtDeviceId,
        'X-Device-Timestamp': timestamp,
        'X-Device-Nonce': nonce,
        'X-Device-Signature': signature,
      },
    });
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
      order_id: orderId,
      order_status: 'ANALYZED',
    });
  });

  await test.step('pathologist signs in with TOTP', async () => {
    await signOut(page);
    await signIn(
      page,
      'medico.test',
      credentials.users['medico.test'].password,
      credentials.users['medico.test'].totp_secret,
    );
    await expect(page.getByText('Pathologist').first()).toBeVisible();
  });

  await test.step('pathologist validates and releases the order', async () => {
    await page.getByRole('link', { name: 'Medical validation' }).click();
    await expect(page.getByRole('heading', { name: 'Medical validation' })).toBeVisible();
    await page.getByText(orderId).click();
    await expect(page.getByText('Analyzed').first()).toBeVisible();
    await expect(page.getByText('TOTP verified', { exact: true })).toBeVisible();
    await page.getByLabel('Observations').fill('Synthetic UI E2E release');
    await page.getByRole('button', { name: 'Validate and release' }).click();
    await expect(
      page.getByText(
        'Resultado clinico validado y liberado con garantia de autenticacion MFA',
      ),
    ).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText(orderId)).toHaveCount(0);
  });

  await test.step('auditor reads the hash-chained audit trail', async () => {
    await signOut(page);
    await signIn(
      page,
      'auditor.test',
      credentials.users['auditor.test'].password,
    );
    await page.getByRole('link', { name: 'Audit trail' }).click();
    await expect(page.getByRole('heading', { name: 'Audit trail' })).toBeVisible();
    await expect(page.getByText('Chain integrity')).toBeVisible();
    await expect(page.getByText('Valid', { exact: true })).toBeVisible();
    await expect(page.getByText('VALIDATE_ORDER').first()).toBeVisible();
  });

  await test.step('reception cannot reach the auditor route', async () => {
    await signOut(page);
    await signIn(
      page,
      'recepcion.test',
      credentials.users['recepcion.test'].password,
    );
    await page.goto('/auditoria');
    await expect(page).toHaveURL(/\/dashboard/);
  });
});
