// SPDX-License-Identifier: Apache-2.0
// Approve an actual node key, inspect its live channel, and revoke and remove it.
import { execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, login } from './support.mjs';

test('approve and revoke an actual contributor through the administration table', async ({ browser }) => {
  const directory = process.env.FICC_TEST_CONTRIBUTOR_DIRECTORY;
  test.skip(!directory, 'Requires the isolated TLS contributor browser runner.');
  test.setTimeout(120000);
  const count = Number(process.env.FICC_TEST_CONTRIBUTOR_COUNT || '1');
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage(), errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const state = join(directory, 'browser-node');
  const invitation = join(directory, 'browser-invitation.json');
  const name = `Operations worker ${randomUUID().slice(0, 8)}`;
  let nodeProcess;
  function command(args) {
    try {
      return JSON.parse(execFileSync(process.env.FICC_CLI, [...args, '--state-dir', state],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000 }));
    } catch { throw new Error('The isolated contributor command failed.'); }
  }
  try {
    await mkdir(state, { mode: 0o700 });
    await login(page);
    await expect(page.locator('#connection')).toHaveText('Secure remote service connected');
    await page.locator('[data-view=contributors]').click();
    await expect(page.getByRole('heading', { name: 'Contributor connections', exact: true })).toBeVisible();
    await page.getByLabel('Contributor name', { exact: true }).fill(name);
    await page.getByLabel('Contributor control mode').selectOption('voluntary');
    const downloaded = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download invitation', exact: true }).click();
    await (await downloaded).saveAs(invitation);
    await chmod(invitation, 0o600);
    const joined = command(['node-join', '--invitation', invitation,
      '--server-ca', process.env.FICC_TEST_CONTRIBUTOR_SERVER_CA]);
    expect(joined.status).toBe('awaiting_approval');
    await page.getByRole('button', { name: 'Refresh contributors', exact: true }).click();
    const table = page.getByRole('table', { name: 'Contributor machines', exact: true });
    const row = table.getByRole('row').filter({ hasText: name });
    await expect(row).toContainText('Awaiting enrollment');
    await page.getByRole('button', { name: `Approve key for ${name}`, exact: true }).click();
    let dialog = page.getByRole('dialog');
    await expect(dialog.getByLabel('Independently verified public key')).toHaveValue('');
    await dialog.getByLabel('Independently verified public key').fill('0'.repeat(64));
    await dialog.getByRole('button', { name: 'Approve this key', exact: true }).click();
    await expect(dialog).toContainText('Reload the current request and confirm its public key.');
    await dialog.getByLabel('Independently verified public key').fill(joined.public_key);
    await dialog.getByRole('button', { name: 'Approve this key', exact: true }).click();
    await expect(dialog).toBeHidden();
    nodeProcess = spawn(process.env.FICC_CLI, ['node-connect', '--state-dir', state],
      { stdio: 'ignore' });
    await expect.poll(async () => {
      try { return JSON.parse(await readFile(join(state, 'connection.json'), 'utf8')).status; }
      catch { return 'starting'; }
    }, { timeout: 20000 }).toBe('connected');
    await page.getByRole('button', { name: 'Refresh contributors', exact: true }).click();
    await expect(row).toContainText('Connected');
    await expect(row).toContainText('persistent');
    await expect(table.getByRole('row')).toHaveCount(count + 1);
    await expect(row).toContainText('Reported by node');
    await capture(page, `contributors-${count}-connected`);
    for (const viewport of [{ width: 1280, height: 720 }, { width: 1920, height: 1080 }]) {
      await page.setViewportSize(viewport);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    }
    await page.getByRole('button', { name: `Revoke ${name}`, exact: true }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Revoke contributor', exact: true }).click();
    await expect(row).toContainText('Revoked');
    await expect.poll(async () => JSON.parse(await readFile(join(state, 'connection.json'), 'utf8')).status,
      { timeout: 10000 }).toBe('disconnected');
    await capture(page, `contributors-${count}-revoked`);
    await page.getByRole('button', { name: `Remove ${name}`, exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Remove contributor', exact: true }).click();
    await expect(row).toHaveCount(0);
    expect(errors).toEqual([]);
  } finally {
    if (nodeProcess && nodeProcess.exitCode === null) {
      const exited = new Promise(resolve => nodeProcess.once('exit', resolve));
      nodeProcess.kill('SIGTERM');
      await exited;
    }
    await context.close();
  }
});
