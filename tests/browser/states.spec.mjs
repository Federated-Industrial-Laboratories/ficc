// SPDX-License-Identifier: Apache-2.0
// Check empty, stale, disconnected and hostile data using API contract fixtures.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, login, mockNodes, node } from './support.mjs';

for (const count of [1, 64]) {
  test(`distinct machine selection works for a ${count}-node inventory`, async ({ page }) => {
    await mockNodes(page, Array.from({ length: count }, (_, index) => node(index + 1)));
    await login(page);
    await expect(page.locator('tbody tr')).toHaveCount(count);
    await page.getByRole('button', { name: `Sample machine ${count}`, exact: true }).click();
    await expect(page.getByRole('heading', { name: `Sample machine ${count}`, exact: true })).toBeVisible();
    await expect(page.getByText('24.5%', { exact: true }).last()).toBeVisible();
    await expect(page.getByText('512.0 GiB', { exact: true })).toBeVisible();
    await expect(page.getByText('Available of 1.0 TiB total', { exact: true })).toBeVisible();
    await expect(page.getByText('[object HTMLDivElement]', { exact: false })).toHaveCount(0);
  });
}

test('an empty inventory states what the operator can do next', async ({ page }) => {
  await mockNodes(page, []);
  await login(page);
  await expect(page.getByRole('heading', { name: 'No machines enrolled' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'No machine selected' })).toBeVisible();
  await capture(page, 'empty-inventory');
});

test('loading is visible before an inventory response arrives', async ({ page }) => {
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  await page.route('**/api/v1/nodes', async route => { await pending; await route.fulfill({ json: { nodes: [] } }); });
  await login(page);
  await expect(page.getByRole('heading', { name: 'Loading machines' })).toBeVisible();
  release();
  await expect(page.getByRole('heading', { name: 'No machines enrolled' })).toBeVisible();
});

test('a stale resource sample stays labelled after selection', async ({ page }) => {
  await mockNodes(page, [node(1, { last_seen: Date.now() / 1000 - 90, stale: true, state: 'degraded' })]);
  await login(page);
  await expect(page.getByText('Stale sample.', { exact: false })).toBeVisible();
  await expect(page.getByText('degraded / stale', { exact: true })).toHaveCount(2);
  await expect(page.getByText('24.5%', { exact: true }).last()).toBeVisible();
});

test('missing resources never appear as zero use', async ({ page }) => {
  await mockNodes(page, [node(1, { resources: null, state: 'unreachable', last_seen: null,
    error: { code: 'unreachable', message: 'The connection could not be established.' } })]);
  await login(page);
  await expect(page.getByRole('heading', { name: 'Resources unknown' })).toBeVisible();
  await expect(page.getByText('0.0%', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Unknown', { exact: true })).toHaveCount(2);
});

test('connection loss keeps cached observations explicitly stale', async ({ page }) => {
  let available = true;
  await page.route('**/api/v1/nodes', route => available ? route.fulfill({ json: { nodes: [node()] } }) : route.abort('connectionfailed'));
  await login(page);
  await expect(page.getByRole('table', { name: 'Enrolled machines' })).toBeVisible();
  available = false;
  await page.getByRole('button', { name: 'Refresh samples' }).click();
  await expect(page.getByRole('heading', { name: 'Service disconnected' })).toBeVisible();
  await expect(page.getByText('Cached samples are shown below.', { exact: false })).toBeVisible();
  await expect(page.getByText('Stale sample.', { exact: false })).toBeVisible();
  available = true;
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Service disconnected' })).toHaveCount(0);
  await capture(page, 'reconnected');
});

test('permission loss removes cached inventory', async ({ page }) => {
  let denied = false;
  await page.route('**/api/v1/nodes', route => denied ? route.fulfill({ status: 403,
    json: { error: { code: 'denied', message: 'This account cannot read machines.' } } }) : route.fulfill({ json: { nodes: [node()] } }));
  await login(page);
  await expect(page.getByRole('table', { name: 'Enrolled machines' })).toBeVisible();
  denied = true;
  await page.getByRole('button', { name: 'Refresh samples' }).click();
  await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible();
  await expect(page.getByRole('table', { name: 'Enrolled machines' })).toHaveCount(0);
  await capture(page, 'access-denied');
});

test('session expiry clears the operator view', async ({ page }) => {
  await login(page);
  await expect(page.getByRole('table', { name: 'Enrolled machines' })).toBeVisible();
  await page.route('**/api/v1/nodes', route => route.fulfill({ status: 401,
    json: { error: { code: 'unauthenticated', message: 'Session expired.' } } }));
  await page.getByRole('button', { name: 'Refresh samples' }).click();
  await expect(page.getByRole('heading', { name: 'Console locked' })).toBeVisible();
  await expect(page.getByText('Your session expired or was revoked.', { exact: false })).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(0);
});

test('machine labels and audit targets are rendered as text', async ({ page }) => {
  const hostile = '<img src=x onerror="window.injected=true">';
  await mockNodes(page, [node(1, { name: hostile, host: '<script>window.injected=true</script>' })]);
  await page.route('**/api/v1/audit', route => route.fulfill({ json: { events: [{ id: 'event-1',
    at: Date.now() / 1000, action: 'inspect', target: hostile, outcome: 'denied' }] } }));
  await login(page);
  await expect(page.getByRole('button', { name: hostile, exact: true })).toBeVisible();
  expect(await page.evaluate(() => Boolean(window.injected))).toBe(false);
  await page.getByRole('button', { name: 'Activity', exact: false }).click();
  await expect(page.getByRole('cell', { name: hostile, exact: true })).toBeVisible();
  expect(await page.evaluate(() => Boolean(window.injected))).toBe(false);
});

test('automatic inventory refresh preserves keyboard selection', async ({ page }) => {
  await mockNodes(page, [node(1), node(2)]);
  await login(page);
  const chosen = page.getByRole('button', { name: 'Sample machine 2', exact: true });
  await chosen.click();
  await expect(chosen).toBeFocused();
  await expect(chosen).toHaveAttribute('aria-pressed', 'true');
  await page.waitForResponse(response => response.url().endsWith('/api/v1/nodes'));
  await expect(chosen).toBeFocused();
  await expect(chosen).toHaveAttribute('aria-pressed', 'true');
});
