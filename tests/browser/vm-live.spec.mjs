// SPDX-License-Identifier: Apache-2.0
// Exercise the installed VM module, provider confirmation and retained action history.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, login } from './support.mjs';

test('real Proxmox graceful shutdown, start and receipt cleanup', async ({ page }) => {
  test.skip(process.env.FICC_VM_FIXTURE !== 'proxmox', 'Requires the explicit disposable Proxmox workspace and ready VM.');
  test.setTimeout(180000);
  const faults = []; page.on('pageerror', error => faults.push(error.message));
  await login(page);
  await page.evaluate(async () => {
    const { request } = await import('/static/api.js');
    const { modules } = await request('/modules'), { workspaces } = await request('/workspaces');
    const module = modules.find(value => value.manifest.id === 'org.ficc.proxmox');
    const workspace = workspaces.find(value => value.name === 'VM display qualification');
    const instance = workspace?.instances.find(value => value.digest === module?.digest);
    if (!module || !instance || instance.targets.length !== 1) throw Error('The explicit disposable VM fixture is missing.');
    await request(`/modules/${module.digest}/activation`, { method: 'POST', body: { enabled: true, grants: [
      { capability: 'workspace:read', target_ids: [workspace.id] },
      { capability: 'vm:read', target_ids: instance.targets }, { capability: 'vm:power', target_ids: instance.targets },
    ] } });
  });
  await page.locator('[data-view=workspaces]').click();
  const panel = page.getByRole('tabpanel', { name: 'Proxmox VMs', exact: true });
  const row = panel.getByRole('row').filter({ hasText: 'ficc-pve-a' });
  const read = async () => {
    await panel.getByRole('button', { name: 'Read VM inventory', exact: true }).click();
    await expect(row).toHaveCount(1);
  };
  await read();
  await expect(row).toContainText('running');
  for (const [action, state] of [['shutdown', 'off'], ['start', 'running']]) {
    await row.getByRole('checkbox').check();
    await panel.getByRole('button', { name: action === 'start' ? 'Preview start' : 'Preview graceful shutdown', exact: true }).click();
    await panel.getByRole('button', { name: 'Review VM action in FICC', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'FICC VM action confirmation', exact: true });
    await expect(dialog).toContainText('ficc-pve-a');
    await expect(dialog).toContainText('Shutdown does not force power off.');
    await capture(page, `proxmox-${action}-confirmation`);
    await dialog.getByRole('button', { name: action === 'start' ? 'Start these VMs' : 'Shut down these VMs', exact: true }).click();
    await expect(dialog).toContainText('Operation ', { timeout: 30000 });
    await expect.poll(async () => {
      if (await dialog.getByRole('cell', { name: 'observed', exact: true }).count()) return true;
      await dialog.getByRole('button', { name: 'Refresh operation', exact: true }).click();
      return (await dialog.getByRole('cell', { name: 'observed', exact: true }).count()) === 1;
    }, { timeout: 60000, intervals: [1000, 2000, 3000] }).toBe(true);
    await dialog.getByRole('button', { name: 'Close', exact: true }).click();
    await panel.getByRole('button', { name: 'VM action history', exact: true }).click();
    const history = page.getByRole('dialog', { name: 'FICC VM action history', exact: true });
    await history.getByRole('button', { name: 'Inspect operation', exact: true }).click();
    await expect(history.getByRole('cell', { name: 'observed', exact: true })).toBeVisible({ timeout: 60000 });
    await capture(page, `proxmox-${action}-observed`);
    await history.getByRole('checkbox').check();
    await history.getByRole('button', { name: 'Remove operation receipt', exact: true }).click();
    await expect(history).toContainText('Operation receipt removed', { timeout: 30000 });
    await history.getByRole('button', { name: 'Close', exact: true }).click();
    await read();
    await expect(row).toContainText(state);
    await expect(panel.getByRole('row').filter({ hasText: 'ficc-pve-b' })).toContainText('off');
  }
  await capture(page, 'proxmox-restored-inventory');
  expect(faults).toEqual([]);
});
