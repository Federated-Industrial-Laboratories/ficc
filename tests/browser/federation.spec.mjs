// SPDX-License-Identifier: Apache-2.0
// Verify installed federation navigation and refuse an unconfigured local companion.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, login } from './support.mjs';

test('federation setup requires a real private companion and exposes recovery help', async ({ page }) => {
  test.skip(Boolean(process.env.FICC_TEST_FEDERATION_PEER_LABEL), 'The connected workflow uses the configured companion.');
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await login(page);
  await page.locator('[data-view=federation]').click();
  await expect(page.getByRole('heading', { name: 'Federation', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Pair a cluster', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Configure connection', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Companion directory', { exact: true }).fill('/nonexistent/ficc-test-companion');
  await dialog.getByRole('button', { name: 'Verify and connect', exact: true }).click();
  await expect(dialog.getByRole('alert')).toBeVisible();
  await expect(dialog).toBeVisible();
  await capture(page, 'federation-companion-refusal');
  await dialog.getByRole('button', { name: 'Close', exact: true }).click();
  const popup = page.waitForEvent('popup');
  await page.getByRole('link', { name: 'Setup and recovery guide', exact: true }).click();
  const help = await popup;
  await expect(help.getByRole('heading', { name: 'Connect clusters through HyperNet', exact: true })).toBeVisible();
  await help.close();
  expect(errors).toEqual([]);
});

test('a paired cluster exposes a real remote service and streams its answer', async ({ page }) => {
  const label = process.env.FICC_TEST_FEDERATION_PEER_LABEL;
  const alias = process.env.FICC_TEST_FEDERATION_SERVICE_ALIAS;
  test.skip(!label || !alias, 'Supply a real paired peer and a ready shared service.');
  test.setTimeout(180000);
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await login(page);
  await page.locator('[data-view=federation]').click();
  const peer = page.locator('section.panel').filter({ has: page.getByRole('heading', { name: label, exact: true }) }).last();
  const unavailable = 'The remote companion could not prepare the stream.';
  const failDiscovery = route => route.request().postDataJSON()?.operation === 'discover'
    ? route.fulfill({ status: 503, json: { error: { code: 'hypernet_connect', message: unavailable } } })
    : route.continue();
  await page.route('**/api/v1/federation/peers/*/request', failDiscovery);
  await peer.getByRole('button', { name: 'Browse shared resources', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: unavailable })).toBeVisible();
  await page.waitForResponse(value => value.url().endsWith('/api/v1/federation') && value.request().method() === 'GET');
  await expect(page.getByRole('alert').filter({ hasText: unavailable })).toBeVisible();
  await page.unroute('**/api/v1/federation/peers/*/request', failDiscovery);
  const discovered = page.waitForResponse(value => value.url().endsWith('/request') && value.request().postDataJSON()?.operation === 'discover');
  await peer.getByRole('button', { name: 'Browse shared resources', exact: true }).click();
  const discovery = await discovered;
  const resources = await discovery.json();
  expect(discovery.ok(), resources.error?.message || 'Remote discovery must succeed.').toBeTruthy();
  expect(resources.services.some(service => service.alias === alias && service.state === 'ready')).toBeTruthy();
  const shared = page.getByRole('dialog').filter({ has: page.getByRole('heading', { name: label, exact: true }) });
  await expect(shared).toBeVisible({ timeout: 60000 });
  const row = shared.getByRole('row').filter({ hasText: alias });
  await expect(row).toContainText('ready');
  await capture(page, 'federation-shared-service');
  await row.getByRole('button', { name: 'Try prompt', exact: true }).click();
  const prompt = page.getByRole('dialog').filter({ has: page.getByLabel('Remote test prompt', { exact: true }) });
  await prompt.getByLabel('Remote test prompt', { exact: true }).fill('Reply with one sentence about a cat. /no_think');
  const response = page.waitForResponse(value => value.url().includes('/v1/chat/completions') && value.request().method() === 'POST');
  await prompt.getByRole('button', { name: 'Send prompt', exact: true }).click();
  const answer = await response;
  expect(answer.ok()).toBeTruthy();
  expect(await answer.finished()).toBeNull();
  await expect(prompt.locator('pre')).not.toBeEmpty({ timeout: 90000 });
  await expect(prompt.locator('pre')).not.toContainText('failed');
  await capture(page, 'federation-remote-answer');
  await page.setViewportSize({ width: 430, height: 932 });
  await expect(prompt.getByRole('button', { name: 'Cancel request', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await capture(page, 'federation-remote-answer-narrow');
  await prompt.getByRole('button', { name: 'Cancel request', exact: true }).click();
  await prompt.getByRole('button', { name: 'Close', exact: true }).click();
  await shared.getByRole('button', { name: 'Close', exact: true }).click();
  expect(errors).toEqual([]);
});
