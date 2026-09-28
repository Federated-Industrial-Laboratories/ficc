// SPDX-License-Identifier: Apache-2.0
// Qualify display rendering and input release on an explicitly selected disposable VM.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, login } from './support.mjs';

test('real VM display, nested fullscreen, input release and revocation', async ({ page }) => {
  test.skip(process.env.FICC_VIEWER_FIXTURE !== '1', 'Requires the installed disposable VM module and native viewer runtime.');
  test.setTimeout(90000);
  const provider = process.env.FICC_VIEWER_PROVIDER || 'libvirt';
  const fixture = {
    libvirt: { packageId: 'org.ficc.libvirt', panel: 'Libvirt VMs', machine: 'ficc-vm-a' },
    proxmox: { packageId: 'org.ficc.proxmox', panel: 'Proxmox VMs', machine: 'ficc-pve-a' },
  }[provider];
  expect(fixture).toBeDefined();
  const faults = [], keys = [];
  page.on('pageerror', error => faults.push(error.message));
  page.on('websocket', socket => socket.on('framesent', event => {
    try {
      const value = JSON.parse(String(event.payload));
      if (value.type === 'input' && value.instruction.startsWith('3.key,')) keys.push(value.instruction);
    } catch { /* Binary display output is not recorded. */ }
  }));
  await login(page);
  await page.evaluate(async packageId => {
    const { request } = await import('/static/api.js');
    const { modules } = await request('/modules'), { workspaces } = await request('/workspaces');
    const module = modules.find(value => value.manifest.id === packageId);
    const workspace = workspaces.find(value => value.name === 'VM display qualification');
    const instance = workspace?.instances.find(value => value.digest === module?.digest);
    if (!module || !instance || instance.targets.length !== 1) throw Error('The explicit disposable viewer fixture is missing.');
    await request(`/modules/${module.digest}/activation`, { method: 'POST', body: { enabled: true, grants: [
      { capability: 'workspace:read', target_ids: [workspace.id] },
      { capability: 'vm:read', target_ids: instance.targets }, { capability: 'vm:console', target_ids: instance.targets },
    ] } });
  }, fixture.packageId);
  await page.locator('[data-view=workspaces]').click();
  if (provider === 'proxmox') {
    await page.getByRole('button', { name: 'VM providers', exact: true }).click();
    const profiles = page.getByRole('dialog', { name: 'VM provider profiles', exact: true });
    const profile = profiles.getByRole('row').filter({ hasText: 'Disposable Proxmox fixture' }).filter({ hasText: 'Proxmox VE' });
    await expect(profile).toContainText('Proxmox VE');
    await expect(profile).toContainText('Enabled');
    await capture(page, 'viewer-provider-profile');
    await profiles.getByRole('button', { name: 'Close', exact: true }).click();
  }
  const panel = page.getByRole('tabpanel', { name: fixture.panel, exact: true });
  await panel.getByRole('button', { name: 'Read VM inventory', exact: true }).click();
  const row = panel.getByRole('row').filter({ hasText: fixture.machine });
  await expect(row).toContainText('running');
  await row.getByRole('checkbox').check();
  await panel.getByRole('button', { name: 'Open selected console', exact: true }).click();
  await panel.getByRole('button', { name: 'Open display in FICC', exact: true }).click();
  const view = page.getByRole('region', { name: 'FICC remote display', exact: true });
  await expect(view.locator('[role=status]')).toHaveText('Connected. Input is released.', { timeout: 30000 });
  expect(await view.locator('canvas').evaluateAll(canvases => canvases.some(canvas => canvas.width >= 640 && canvas.height >= 400))).toBe(true);
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
  await expect(view.locator('[role=status]')).toHaveText('Connected. Input is released.');
  await capture(page, 'viewer-restored-small');
  await page.evaluate(async packageId => {
    const { request } = await import('/static/api.js');
    const { modules } = await request('/modules');
    const module = modules.find(value => value.manifest.id === packageId);
    if (!module) throw Error('The disposable VM module is missing.');
    await request(`/modules/${module.digest}/activation`, { method: 'POST', body: { enabled: false, grants: [] } });
  }, fixture.packageId);
  await expect(view.getByRole('button', { name: 'Capture input', exact: true })).toBeDisabled();
  await expect(view.locator('[role=status]')).not.toHaveText('Connected. Input is released.');
  expect(faults).toEqual([]);
});
