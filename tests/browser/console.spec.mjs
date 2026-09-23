// SPDX-License-Identifier: Apache-2.0
// Check the authenticated console against the isolated running service.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { capture, cli, login, origin } from './support.mjs';

for (const width of [390, 768, 1280, 1920]) {
  test(`authenticated layout at ${width} pixels`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1080 });
    const faults = [];
    page.on('pageerror', error => faults.push(error.message));
    await login(page);
    await expect(page.locator('#mode-banner')).toContainText('All machines and resource values are simulated');
    await expect(page.getByRole('table', { name: 'Enrolled machines' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Enroll node' })).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole('button', { name: 'Lab machine 2', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Lab machine 2', exact: true })).toBeVisible();
    await expect(page.getByText('Stale sample.', { exact: false })).toBeVisible();
    await capture(page, `overview-${width}`);
    await page.getByRole('button', { name: 'Access', exact: false }).click();
    await expect(page.getByRole('heading', { name: 'Effective permissions' })).toBeVisible();
    await page.getByRole('button', { name: 'Activity', exact: false }).click();
    await expect(page.getByRole('heading', { name: 'Audit record' })).toBeVisible();
    expect(faults).toEqual([]);
  });
}

test('keyboard navigation and reduced motion preserve all controls', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await login(page);
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to console' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main')).toBeFocused();
  await page.getByRole('button', { name: 'Access', exact: false }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Access and credentials' })).toBeVisible();
  await expect(page.locator('#main')).toBeFocused();
  expect(await page.evaluate(() => document.getAnimations().length)).toBe(0);
});

test('two hundred percent layout remains readable and operable', async ({ page }) => {
  await login(page);
  await page.evaluate(() => { document.documentElement.style.zoom = '2'; });
  await expect(page.getByRole('heading', { name: 'Cluster overview', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole('button', { name: 'Access', exact: false }).click();
  await expect(page.getByRole('heading', { name: 'Effective permissions' })).toBeVisible();
  await capture(page, 'access-200-percent');
});

test('session sign-out locks the console and invalidates its cookie', async ({ page }) => {
  await login(page);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Console locked' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Overview', exact: false })).toBeDisabled();
  const status = await page.evaluate(async () => (await fetch('/api/v1/nodes')).status);
  expect(status).toBe(401);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
});

test('the local console uses local assets and a restrictive content policy', async ({ page }) => {
  const destinations = new Set();
  page.on('request', request => destinations.add(new URL(request.url()).origin));
  const response = await page.goto(origin);
  expect(response.headers()['content-security-policy']).toContain("script-src 'self'");
  expect(response.headers()['content-security-policy']).not.toContain('unsafe-inline');
  await login(page);
  await page.evaluate(() => document.fonts.ready);
  expect([...destinations]).toEqual([origin]);
  expect(await page.evaluate(() => document.fonts.check('16px Barlow'))).toBe(true);
});

test('credential revocation prevents an existing bearer token from reading inventory', async ({ page }) => {
  const folder = await mkdtemp(join(tmpdir(), 'ficc-browser-token-'));
  const file = join(folder, 'credential');
  try {
    cli(['token-create', '--label', 'Browser revocation check', '--scope', 'nodes:read', '--output', file]);
    const token = (await readFile(file, 'utf8')).trim();
    const before = await fetch(`${origin}/api/v1/nodes`, { headers: { Authorization: `Bearer ${token}` } });
    expect(before.status).toBe(200);
    await login(page);
    await page.getByRole('button', { name: 'Access', exact: false }).click();
    await page.getByRole('button', { name: 'Revoke Browser revocation check', exact: true }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.getByRole('button', { name: 'Revoke credential', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    const after = await fetch(`${origin}/api/v1/nodes`, { headers: { Authorization: `Bearer ${token}` } });
    expect(after.status).toBe(401);
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test('the primary text palette meets the normal text contrast threshold', async () => {
  function luminance(hex) {
    const channels = hex.match(/\w\w/g).map(value => parseInt(value, 16) / 255)
      .map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
    return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
  }
  const pairs = [['202327', 'f6f4ef'], ['505862', 'ffffff'], ['202327', 'd97a12'],
    ['24583d', 'edf6ef'], ['76400b', 'fff2df'], ['8f2923', 'fcefed'], ['ffffff', '30363d'],
    ['633805', 'fff0db'], ['24445c', 'eff6fb']];
  for (const [foreground, background] of pairs) {
    const first = luminance(foreground), second = luminance(background);
    expect((Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05)).toBeGreaterThanOrEqual(4.5);
  }
});
