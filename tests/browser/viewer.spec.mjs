// SPDX-License-Identifier: Apache-2.0
// Qualify display rendering and input release on an explicitly selected disposable VM.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, login } from './support.mjs';
import { activateViewerFixture, restoreViewerFixture, viewerFixture } from './viewer-fixture.mjs';

const activations = new WeakMap();
test.afterEach(async ({ page }) => restoreViewerFixture(page, activations.get(page)));

test('real VM display, nested fullscreen, input release and revocation', async ({ page }) => {
  test.skip(process.env.FICC_VIEWER_FIXTURE !== '1', 'Requires the installed disposable VM module and native viewer runtime.');
  test.setTimeout(180000);
  const fixture = viewerFixture();
  const faults = [], keys = [];
  page.on('pageerror', error => faults.push(error.message));
  page.on('websocket', socket => socket.on('framesent', event => {
    try {
      const value = JSON.parse(String(event.payload));
      if (value.type === 'input' && value.instruction.startsWith('3.key,')) keys.push(value.instruction);
    } catch { /* Binary display output is not recorded. */ }
  }));
  await login(page);
  const original = await activateViewerFixture(page, fixture);
  activations.set(page, original);
  await page.locator('[data-view=workspaces]').click();
  await page.getByLabel('Saved workspace', { exact: true }).selectOption(original.workspace);
  await page.getByRole('button', { name: 'Open', exact: true }).click();
  if (fixture.provider === 'proxmox') {
    await page.getByRole('button', { name: 'VM providers', exact: true }).click();
    const profiles = page.getByRole('dialog', { name: 'VM provider profiles', exact: true });
    const profile = profiles.getByRole('row').filter({ hasText: 'Disposable Proxmox fixture' }).filter({ hasText: 'Proxmox VE' });
    await expect(profile).toContainText('Proxmox VE');
    await expect(profile).toContainText('Enabled');
    await capture(page, 'viewer-provider-profile');
    await profiles.getByRole('button', { name: 'Close', exact: true }).click();
  }
  const panel = page.getByRole('tabpanel', { name: fixture.panel, exact: true });
  if (fixture.packaged) {
    await panel.getByRole('button', { name: 'Read provider profiles', exact: true }).click();
    const profiles = panel.getByLabel('Provider profile', { exact: true });
    await expect(profiles.locator(`option[value="${fixture.profile}"]`)).toHaveCount(1);
    await profiles.selectOption(fixture.profile);
  }
  await panel.getByRole('button', { name: 'Read VM inventory', exact: true }).click();
  const row = panel.getByRole('row').filter({ has: page.getByRole('cell', { name: fixture.machine, exact: true }) });
  await expect(row).toContainText('running', { timeout: 45000 });
  await row.getByRole('checkbox').check();
  await panel.getByRole('button', { name: 'Open selected console', exact: true }).click();
  await panel.getByRole('button', { name: 'Open display in FICC', exact: true }).click();
  const view = page.getByRole('region', { name: 'FICC remote display', exact: true });
  await expect(view.locator('[role=status]')).toHaveText('Connected. Input is released.', { timeout: 30000 });
  await expect.poll(() => view.locator('canvas').evaluateAll(canvases =>
    canvases.some(canvas => canvas.width >= 640 && canvas.height >= 400)), { timeout: 30000 }).toBe(true);
  expect(keys).toEqual([]);
  await capture(page, 'viewer-connected');
  await view.getByRole('button', { name: 'Capture input', exact: true }).click();
  await page.keyboard.down('Control');
  await page.keyboard.down('Alt');
  await page.keyboard.down('Shift');
  await expect(view).toHaveAttribute('data-input', 'released');
  await page.keyboard.up('Shift'); await page.keyboard.up('Alt'); await page.keyboard.up('Control');
  expect(keys.some(value => value.endsWith('1.1;'))).toBe(true);
  expect(keys.filter(value => value.endsWith('1.0;')).length).toBeGreaterThanOrEqual(2);
  await view.getByRole('button', { name: 'Capture input', exact: true }).click();
  await page.keyboard.down('Shift');
  await view.getByRole('button', { name: 'Release input', exact: true }).click();
  await page.keyboard.up('Shift');
  await expect(view).toHaveAttribute('data-input', 'released');
  await page.getByRole('button', { name: 'Fullscreen', exact: true }).click();
  await view.getByRole('button', { name: 'Fullscreen display', exact: true }).click();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement?.classList.contains('viewer-panel'))).toBe(true);
  await expect.poll(() => view.locator('.viewer-well').evaluate(well => {
    const bounds = well.getBoundingClientRect(), display = well.firstElementChild.getBoundingClientRect();
    return Math.max(display.width / bounds.width, display.height / bounds.height);
  })).toBeGreaterThan(0.95);
  await capture(page, 'viewer-fullscreen');
  await view.getByRole('button', { name: 'Exit display fullscreen', exact: true }).click();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement?.classList.contains('workspaces'))).toBe(true);
  await page.getByRole('button', { name: 'Exit fullscreen', exact: true }).click();
  await view.getByRole('button', { name: 'Expand display', exact: true }).click();
  await page.setViewportSize({ width: 760, height: 620 });
  await view.getByRole('button', { name: 'Restore display', exact: true }).click();
  await expect(view.getByRole('button', { name: 'Capture input', exact: true })).toBeVisible();
  await expect(view.getByRole('button', { name: 'Capture input', exact: true })).toBeInViewport();
  await expect(panel.getByRole('button', { name: 'Float', exact: true })).toBeInViewport();
  await expect.poll(() => panel.evaluate(element => {
    for (let parent = element.parentElement; parent && !parent.classList.contains('workspaces'); parent = parent.parentElement) {
      if (parent.classList.contains('dv-view') && (parent.scrollLeft || parent.scrollTop)) return false;
    }
    return true;
  })).toBe(true);
  await expect(view.locator('[role=status]')).toHaveText('Connected. Input is released.');
  await capture(page, 'viewer-restored-small');
  await page.evaluate(async digest => {
    const { request } = await import('/static/api.js');
    await request(`/modules/${digest}/activation`, { method: 'POST', body: { enabled: false, grants: [] } });
  }, original.digest);
  await expect(view.getByRole('button', { name: 'Capture input', exact: true })).toBeDisabled();
  await expect(view.locator('[role=status]')).not.toHaveText('Connected. Input is released.');
  expect(faults).toEqual([]);
});
