// SPDX-License-Identifier: Apache-2.0
// Exercise a disposable systemd service through the installed module and host controls.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, login } from './support.mjs';

test('real administration profile, service actions, logs and receipt cleanup', async ({ page }) => {
  test.skip(process.env.FICC_ADMIN_FIXTURE !== '1', 'Requires the explicit disposable administration workspace.');
  test.setTimeout(180000);
  const faults = []; page.on('pageerror', error => faults.push(error.message));
  await login(page);
  await page.locator('[data-view=workspaces]').click();
  await page.getByRole('button', { name: 'Administration profiles', exact: true }).click();
  const profiles = page.getByRole('dialog', { name: 'Administration profiles', exact: true });
  if (!await profiles.getByRole('row').filter({ hasText: 'Disposable administration fixture' }).count()) {
    await profiles.getByLabel('Administration system', { exact: true }).selectOption({ label: 'Disposable administration fixture' });
    await profiles.getByLabel('Service manager', { exact: true }).selectOption('user');
    await profiles.getByRole('button', { name: 'Probe and add profile', exact: true }).click();
  }
  await expect(profiles.getByRole('row').filter({ hasText: 'Disposable administration fixture' })).toContainText('Enabled', { timeout: 30000 });
  await capture(page, 'administration-profile');
  await profiles.getByRole('button', { name: 'Close', exact: true }).click();
  const panel = page.getByRole('tabpanel', { name: 'System administration', exact: true });
  await panel.getByLabel('Resource kind', { exact: true }).selectOption('service');
  const read = async () => {
    await panel.getByRole('button', { name: 'Read systems and services', exact: true }).click();
    await panel.getByRole('searchbox').fill('ficc-admin-test-00.service');
    await expect(panel.getByRole('row').filter({ hasText: 'ficc-admin-test-00.service' })).toHaveCount(1);
  };
  await read();
  await expect(panel.getByRole('row').filter({ hasText: 'ficc-admin-test-00.service' })).toContainText('inactive');
  for (const [action, state] of [['start', 'active'], ['stop', 'inactive']]) {
    await panel.getByRole('row').filter({ hasText: 'ficc-admin-test-00.service' }).getByRole('checkbox').check();
    await panel.getByRole('button', { name: `Preview ${action}`, exact: true }).click();
    await panel.getByRole('button', { name: 'Review administration action in FICC', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'FICC administration action confirmation', exact: true });
    await expect(dialog).toContainText('ficc-admin-test-00.service');
    await expect(dialog).toContainText('Unit dependencies');
    await capture(page, `administration-${action}-confirmation`);
    await dialog.getByRole('button', { name: action === 'start' ? 'Start these services' : 'Stop these services', exact: true }).click();
    await expect(dialog).toContainText('Operation ', { timeout: 30000 });
    await dialog.getByRole('button', { name: 'Refresh operation', exact: true }).click();
    await expect(dialog.getByRole('cell', { name: 'observed', exact: true })).toBeVisible({ timeout: 20000 });
    await dialog.getByRole('button', { name: 'Close', exact: true }).click();
    await panel.getByRole('button', { name: 'Administration action history', exact: true }).click();
    const history = page.getByRole('dialog', { name: 'FICC administration action history', exact: true });
    await history.getByRole('button', { name: 'Inspect operation', exact: true }).first().click();
    await expect(history).toContainText('observed');
    await history.getByRole('checkbox').check();
    await history.getByRole('button', { name: 'Remove operation receipt', exact: true }).click();
    await expect(history).toContainText('Operation receipt removed', { timeout: 30000 });
    await history.getByRole('button', { name: 'Close', exact: true }).click();
    await read();
    await expect(panel.getByRole('row').filter({ hasText: 'ficc-admin-test-00.service' })).toContainText(state);
    if (action === 'start') {
      await panel.getByRole('row').filter({ hasText: 'ficc-admin-test-00.service' }).getByRole('checkbox').check();
      await panel.getByRole('button', { name: 'Read service logs', exact: true }).click();
      await expect(panel.getByLabel('Service logs', { exact: true })).toContainText('started', { timeout: 20000 });
    }
  }
  await capture(page, 'administration-restored-service');
  expect(faults).toEqual([]);
});
