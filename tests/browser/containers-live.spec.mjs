// SPDX-License-Identifier: Apache-2.0
// Qualify container profiles and confirmed scale actions on an explicit disposable lab.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, login } from './support.mjs';

test('real container profiles, inventory, confirmed scale, history and cleanup', async ({ page }) => {
  test.skip(process.env.FICC_CONTAINER_FIXTURE !== '1', 'Requires the explicit disposable container workspace.');
  test.setTimeout(180000);
  const faults = []; page.on('pageerror', error => faults.push(error.message));
  await login(page);
  await page.locator('[data-view=workspaces]').click();
  await page.getByRole('button', { name: 'Container providers', exact: true }).click();
  const profiles = page.getByRole('dialog', { name: 'Container provider profiles', exact: true });
  for (const [provider, label] of [['docker', 'Docker'], ['podman', 'Podman'], ['kubernetes', 'Kubernetes']]) {
    if (await profiles.getByRole('row').filter({ hasText: `Disposable ${label} fixture` }).count()) continue;
    await profiles.getByLabel('Container system', { exact: true }).selectOption({ label: `Disposable ${label} fixture` });
    await profiles.getByLabel('Container provider', { exact: true }).selectOption(provider);
    if (provider === 'kubernetes') {
      await profiles.getByLabel('Kubernetes context', { exact: true }).fill('kind-ficc');
      await profiles.getByLabel('Kubernetes namespace', { exact: true }).fill('ficc-fixture');
    }
    await profiles.getByRole('button', { name: 'Probe and add profile', exact: true }).click();
    await expect(profiles.getByRole('row').filter({ hasText: `Disposable ${label} fixture` })).toContainText('Enabled', { timeout: 30000 });
  }
  await capture(page, 'container-provider-profiles');
  await profiles.getByRole('button', { name: 'Close', exact: true }).click();
  const panel = page.getByRole('tabpanel', { name: 'Container workloads', exact: true });
  await panel.getByRole('button', { name: 'Read workloads', exact: true }).click();
  await expect(panel.getByRole('row').filter({ hasText: 'fixture-a' })).toHaveCount(2);
  await panel.getByLabel('Provider', { exact: true }).selectOption('kubernetes');
  await panel.getByLabel('Kind', { exact: true }).selectOption('deployment');
  await panel.getByRole('button', { name: 'Read workloads', exact: true }).click();
  const row = panel.getByRole('row').filter({ hasText: 'deployment' });
  await expect(row).toHaveCount(1);
  await row.getByRole('checkbox').check();
  const change = async replicas => {
    await panel.getByLabel('Desired replicas (0 to 64)', { exact: true }).fill(String(replicas));
    await panel.getByRole('button', { name: 'Preview scale', exact: true }).click();
    await panel.getByRole('button', { name: 'Review container action in FICC', exact: true }).click();
    const confirm = page.getByRole('dialog', { name: 'FICC container action confirmation', exact: true });
    await expect(confirm).toContainText(`Set desired replicas to ${replicas}.`);
    await capture(page, `container-scale-${replicas}-confirmation`);
    await confirm.getByRole('button', { name: 'Set these replica counts', exact: true }).click();
    await expect(confirm).toContainText('Operation ', { timeout: 40000 });
    await confirm.getByRole('button', { name: 'Refresh operation', exact: true }).click();
    await expect(confirm.getByRole('cell', { name: 'observed', exact: true })).toBeVisible({ timeout: 20000 });
    await confirm.getByRole('button', { name: 'Close', exact: true }).click();
    await panel.getByRole('button', { name: 'Container action history', exact: true }).click();
    const history = page.getByRole('dialog', { name: 'FICC container action history', exact: true });
    await history.getByRole('button', { name: 'Inspect operation', exact: true }).first().click();
    await expect(history).toContainText(`replicas ${replicas}`);
    await history.getByRole('checkbox').check();
    await history.getByRole('button', { name: 'Remove operation receipt', exact: true }).click();
    await expect(history).toContainText('Operation receipt removed', { timeout: 30000 });
    await history.getByRole('button', { name: 'Close', exact: true }).click();
    await panel.getByRole('button', { name: 'Read workloads', exact: true }).click();
  };
  await change(0);
  await change(2);
  await capture(page, 'container-restored-workloads');
  expect(faults).toEqual([]);
});
