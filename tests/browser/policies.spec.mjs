// SPDX-License-Identifier: Apache-2.0
// Exercise signed packages and effective access through a real isolated policy service.
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, cli, login, origin } from './support.mjs';

test('signed policies restrict members and provide explicit recovery', async ({ page, browser }) => {
  test.skip(!process.env.FICC_TEST_OPA, 'Requires an isolated live service with the real policy evaluator configured.');
  test.setTimeout(180000);
  const root = fileURLToPath(new URL('../../', import.meta.url));
  const folder = await mkdtemp(join(tmpdir(), 'ficc-browser-policy-'));
  const key = join(folder, 'key'), publisher = `browser-${randomUUID().slice(0, 8)}`;
  const errors = [], contexts = [];
  page.on('pageerror', error => errors.push(error.message));
  try {
    execFileSync('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key], { stdio: 'ignore' });
    const packages = {};
    for (const preset of ['managed', 'contribution']) {
      const archive = join(folder, `${preset}.ficcpolicy`);
      execFileSync(process.env.FICC_PYTHON || 'python3', [join(root, 'tools/pack-policy.py'), join(root, 'policy-packs', preset),
        '--publisher', publisher, '--key', key, '--output', archive], { stdio: 'pipe' });
      packages[preset] = archive;
    }
    const user = JSON.parse(cli(['identity-create', '--label', `Policy member ${publisher}`]));
    const project = JSON.parse(cli(['project-create', '--label', `Policy project ${publisher}`]));
    cli(['project-member-set', '--project', project.id, '--subject', user.id, '--revision', '0',
      ...['workspaces:read', 'workspaces:write', 'modules:read', 'audio:playback'].flatMap(scope => ['--scope', scope])]);
    await login(page);
    await page.locator('[data-view=access]').click();
    await page.getByLabel('Policy publisher identifier').fill(publisher);
    await page.getByLabel('Policy publisher public key').fill(await readFile(`${key}.pub`, 'utf8'));
    await page.getByRole('button', { name: 'Trust policy publisher', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Trust publisher', exact: true }).click();
    await expect(page.getByRole('table', { name: 'Policy publishers', exact: true })).toContainText(publisher);
    for (const archive of Object.values(packages)) {
      await page.getByLabel('Signed policy package').setInputFiles(archive);
      await page.getByRole('button', { name: 'Install policy package', exact: true }).click();
      await expect(page.getByText('Signed policy package installed. Activation is a separate action.', { exact: true })).toBeVisible();
    }
    const installed = JSON.parse(cli(['policy-list']));
    const managed = installed.packages.find(value => value.publisher === publisher && value.manifest.id === 'ficc-managed').digest;
    const contribution = installed.packages.find(value => value.publisher === publisher && value.manifest.id === 'ficc-contribution').digest;
    async function roles(role) {
      await page.getByLabel('Policy role project').selectOption(project.id);
      await page.getByLabel('Policy role identity').selectOption(user.id);
      await expect(page.getByRole('button', { name: 'Save policy roles', exact: true })).toBeEnabled();
      const form = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Policy role assignments', exact: true }) });
      for (const checkbox of await form.getByRole('checkbox').all()) await checkbox.uncheck();
      await form.getByRole('checkbox', { name: new RegExp(`\\(${role}\\)`) }).check();
      await page.getByRole('button', { name: 'Save policy roles', exact: true }).click();
      await expect(page.getByText('Policy roles saved.', { exact: true })).toBeVisible();
    }
    async function preview(expected) {
      await page.getByLabel('Policy package', { exact: true }).selectOption(managed);
      await page.getByLabel('Policy preview identity').selectOption(user.id);
      await page.getByLabel('Policy preview project').selectOption(project.id);
      await page.getByLabel('Preview selected policy package').check();
      await page.getByRole('button', { name: 'Preview effective access', exact: true }).click();
      const cells = page.getByRole('table', { name: 'Effective policy decisions' }).locator('tbody tr').last().locator('td');
      await expect(cells.nth(1)).toHaveText('Allow');
      await expect(cells.nth(3)).toHaveText(expected);
    }
    async function activate(digest) {
      await page.getByLabel('Policy package', { exact: true }).selectOption(digest);
      await page.getByRole('button', { name: 'Activate selected policy', exact: true }).click();
      await page.getByRole('dialog').getByRole('button', { name: 'Activate policy', exact: true }).click();
      await expect(page.getByText('Policy activated at a new revision.', { exact: true })).toBeVisible();
    }
    await roles('observer'); await preview('Deny');
    await capture(page, 'policy-observer-preview');
    await roles('operator'); await preview('Allow');
    await activate(managed);
    const context = await browser.newContext(); contexts.push(context);
    const member = await context.newPage(); member.on('pageerror', error => errors.push(error.message));
    const url = new URL(cli(['open', '--print-url', '--subject', user.id, '--project', project.id]));
    await member.goto(origin);
    await member.evaluate(fragment => history.replaceState(null, '', `/${fragment}`), url.hash);
    await member.reload();
    await member.getByLabel('Workspace name', { exact: true }).fill(`Policy runbook ${publisher}`);
    await member.getByRole('button', { name: 'New workspace', exact: true }).click();
    await expect(member.getByLabel('Saved workspace').locator('option')).toHaveText(`Policy runbook ${publisher}`);
    await capture(member, 'policy-member-workspace');
    await activate(contribution);
    await page.getByRole('button', { name: 'Roll back policy', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Activate policy', exact: true }).click();
    await expect(page.getByText('Policy activated at a new revision.', { exact: true })).toBeVisible();
    expect(JSON.parse(cli(['policy-list'])).state.active).toBe(managed);
    await page.getByRole('table', { name: 'Policy publishers' }).getByRole('button', { name: 'Disable publisher', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Disable publisher', exact: true }).click();
    await expect(page.getByText('Publisher trust updated.', { exact: true })).toBeVisible();
    await expect(page.getByText('Normal access is denied while the evaluator is unavailable.', { exact: false })).toBeVisible();
    await capture(page, 'policy-owner-recovery');
    await page.getByRole('table', { name: 'Policy publishers' }).getByRole('button', { name: 'Enable publisher', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Enable publisher', exact: true }).click();
    await expect(page.getByText('Publisher trust updated.', { exact: true })).toBeVisible();
    await activate(managed);
    await preview('Allow');
    await capture(page, 'policy-active-administration');
    await member.reload();
    await expect(member.getByLabel('Saved workspace').locator('option')).toHaveText(`Policy runbook ${publisher}`);
    expect(errors).toEqual([]);
  } finally {
    for (const context of contexts) await context.close();
    await rm(folder, { recursive: true, force: true });
  }
});
