// SPDX-License-Identifier: Apache-2.0
// Check host verification and explicit helper installation through the UI contract.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { login, mockLiveSession, node } from './support.mjs';

async function setup(page, changes = {}) {
  let enrolled = false, submitted = null;
  const sample = node();
  await mockLiveSession(page);
  await page.route('**/api/v1/profiles', route => route.fulfill({ json: { profiles: [{ id: 'sample', label: 'Sample SSH profile' }] } }));
  await page.route('**/api/v1/node-previews', route => route.fulfill({ json: {
    preview_id: 'a'.repeat(32), name: 'Test machine', profile: 'sample', host: 'sample.example', account: 'operator',
    fingerprint: sample.fingerprint, expires_at: Date.now() / 1000 + 300, trust: 'trusted',
    helper_version: null, helper_install_required: true, warnings: [], ...changes,
  } }));
  await page.route('**/api/v1/nodes', route => {
    if (route.request().method() === 'POST') {
      submitted = route.request().postDataJSON(); enrolled = true;
      return route.fulfill({ json: sample });
    }
    return route.fulfill({ json: { nodes: enrolled ? [sample] : [] } });
  });
  await login(page);
  await page.getByRole('button', { name: 'Enroll node' }).click();
  await page.getByLabel('Machine name', { exact: true }).fill('Test machine');
  await page.getByRole('button', { name: 'Inspect host identity' }).click();
  await expect(page.getByText(sample.fingerprint, { exact: true })).toBeVisible();
  return { sample, submitted: () => submitted };
}

test('enrollment requires a matching fingerprint and explicit helper consent', async ({ page }) => {
  const fixture = await setup(page);
  const confirm = page.getByRole('button', { name: 'Confirm enrollment' });
  await expect(confirm).toBeDisabled();
  await page.getByLabel('I verified this fingerprint', { exact: false }).check();
  await page.getByLabel('Enter the verified fingerprint').fill('SHA256:WrongFingerprint');
  await page.getByLabel('Install the FICC helper', { exact: false }).check();
  await expect(confirm).toBeDisabled();
  await page.getByLabel('Enter the verified fingerprint').fill(fixture.sample.fingerprint);
  await expect(confirm).toBeEnabled();
  await page.getByLabel('Install the FICC helper', { exact: false }).uncheck();
  await expect(confirm).toBeDisabled();
  await page.getByLabel('Install the FICC helper', { exact: false }).check();
  await confirm.click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(fixture.submitted()).toEqual({ preview_id: 'a'.repeat(32), expected_fingerprint: fixture.sample.fingerprint, install_helper: true });
  await expect(page.getByRole('button', { name: fixture.sample.name, exact: true })).toBeVisible();
});

test('an untrusted key cannot be enrolled through confirmation', async ({ page }) => {
  const fixture = await setup(page, { trust: 'untrusted' });
  await expect(page.getByText('This host key is not trusted.', { exact: false })).toBeVisible();
  await page.getByLabel('I verified this fingerprint', { exact: false }).check();
  await page.getByLabel('Enter the verified fingerprint').fill(fixture.sample.fingerprint);
  await page.getByLabel('Install the FICC helper', { exact: false }).check();
  await expect(page.getByRole('button', { name: 'Confirm enrollment' })).toBeDisabled();
  expect(fixture.submitted()).toBeNull();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', { name: 'Enroll node' })).toBeFocused();
});

test('expired trust previews require a new inspection', async ({ page }) => {
  const fixture = await setup(page, { expires_at: Date.now() / 1000 - 1 });
  await page.getByLabel('I verified this fingerprint', { exact: false }).check();
  await page.getByLabel('Enter the verified fingerprint').fill(fixture.sample.fingerprint);
  await page.getByLabel('Install the FICC helper', { exact: false }).check();
  await expect(page.getByRole('button', { name: 'Confirm enrollment' })).toBeDisabled();
});

test('a changed host key error remains visible and does not claim enrollment', async ({ page }) => {
  const fixture = await setup(page);
  await page.route('**/api/v1/nodes', route => route.request().method() === 'POST' ?
    route.fulfill({ status: 409, json: { error: { code: 'host_key_changed', message: 'The host key changed. Inspect it again.' } } }) :
    route.fulfill({ json: { nodes: [] } }));
  await page.getByLabel('I verified this fingerprint', { exact: false }).check();
  await page.getByLabel('Enter the verified fingerprint').fill(fixture.sample.fingerprint);
  await page.getByLabel('Install the FICC helper', { exact: false }).check();
  await page.getByRole('button', { name: 'Confirm enrollment' }).click();
  await expect(page.getByText('The host key changed. Inspect it again.', { exact: true })).toBeVisible();
  await expect(page.getByRole('dialog')).toBeVisible();
  expect(fixture.submitted()).toBeNull();
});
