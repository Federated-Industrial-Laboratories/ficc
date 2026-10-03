// SPDX-License-Identifier: Apache-2.0
// Exercise real folder grants, project file copies and current access revocation.
import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { confirmFiles } from './file-support.mjs';
import { capture, cli, login, origin } from './support.mjs';

test('project members copy real files and lose revoked folder access', async ({ page, browser }) => {
  test.skip(process.env.FICC_TEST_LIVE_RESOURCES !== '1',
    'Requires FICC_TEST_LIVE_RESOURCES=1 and an isolated live service in FICC_URL, FICC_STATE_DIR and FICC_CLI. Demo mode refuses root registration and real file changes.');
  test.setTimeout(60000);
  await login(page);
  const session = await page.evaluate(async () => (await fetch('/api/v1/session')).json());
  expect(session.mode, 'The explicitly selected file-resource fixture must run in live mode.').toBe('live');
  const label = randomUUID().slice(0, 8), folder = await mkdtemp(join(tmpdir(), 'ficc-project-files-'));
  const source = join(folder, 'source'), destination = join(folder, 'destination');
  const faults = [], roots = [], contexts = [];
  page.on('pageerror', error => faults.push(error.message));
  try {
    await mkdir(source); await mkdir(destination);
    const content = `Project work ${label}\n`;
    await writeFile(join(source, 'runbook.txt'), content);
    for (const [name, path] of [['Source', source], ['Destination', destination]]) {
      roots.push(JSON.parse(cli(['root-add', '--path', path, '--label', `${name} ${label}`])));
    }
    const user = JSON.parse(cli(['identity-create', '--label', `Operator ${label}`]));
    const project = JSON.parse(cli(['project-create', '--label', `File project ${label}`]));
    const control = JSON.parse(cli(['project-create', '--label', `Control project ${label}`]));
    for (const item of [project, control]) {
      cli(['project-member-set', '--project', item.id, '--subject', user.id, '--revision', '0',
        ...['workspaces:read', 'files:read', 'files:write'].flatMap(scope => ['--scope', scope])]);
    }
    cli(['project-resources-set', '--project', control.id, '--revision', '0', '--root', roots[0].id]);
    expect(JSON.parse(cli(['project-resources', '--project', project.id])).root_ids).toEqual([]);
    await page.locator('[data-view=access]').click();
    await page.getByLabel('Resource project').selectOption(project.id);
    for (const name of ['Source', 'Destination']) {
      await page.getByRole('checkbox', { name: `Assign folder ${name} ${label}`, exact: true }).check();
    }
    await page.getByRole('button', { name: 'Save project resources', exact: true }).click();
    await expect(page.getByText('Project resources saved. Current requests use these assignments.', { exact: true })).toBeVisible();
    expect(JSON.parse(cli(['project-resources', '--project', project.id])).root_ids.sort()).toEqual(roots.map(root => root.id).sort());
    await capture(page, 'resource-project-administration');

    async function openMember(target) {
      const context = await browser.newContext(); contexts.push(context);
      const member = await context.newPage(); member.on('pageerror', error => faults.push(error.message));
      const url = new URL(cli(['open', '--print-url', '--subject', user.id, '--project', target.id]));
      await member.goto(origin);
      await member.evaluate(hash => history.replaceState(null, '', `/${hash}`), url.hash);
      await member.reload();
      await expect(member.getByLabel('Current project')).toHaveValue(target.id);
      await member.locator('[data-view=files]').click();
      await expect(member.locator('[data-pane=Left]').getByText('runbook.txt', { exact: true })).toBeVisible();
      return member;
    }
    const member = await openMember(project), unaffected = await openMember(control);
    const left = member.locator('[data-pane=Left]'), right = member.locator('[data-pane=Right]');
    await left.getByLabel('Location', { exact: true }).selectOption(roots[0].id);
    await right.getByLabel('Location', { exact: true }).selectOption(roots[1].id);
    await left.getByRole('checkbox').first().check();
    await left.getByRole('button', { name: 'Preview', exact: true }).click();
    await expect(member.locator('.file-content')).toHaveText(content);
    await member.getByRole('button', { name: 'Close', exact: true }).click();
    await member.getByRole('button', { name: 'Copy left to right', exact: true }).click();
    await member.getByRole('button', { name: 'Preview transfer', exact: true }).click();
    await confirmFiles(member);
    await expect.poll(() => readFile(join(destination, 'runbook.txt'), 'utf8').catch(() => '')).toBe(content);
    await expect(member.getByText('Verified SHA-256', { exact: false })).toBeVisible();
    await capture(member, 'resource-member-file-copy');

    for (const name of ['Source', 'Destination']) {
      await page.getByRole('checkbox', { name: `Assign folder ${name} ${label}`, exact: true }).uncheck();
    }
    const saved = page.waitForResponse(response => response.url().endsWith(`/projects/${project.id}/resources`) && response.request().method() === 'PUT');
    await page.getByRole('button', { name: 'Save project resources', exact: true }).click();
    expect((await saved).status()).toBe(200);
    await left.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(left.getByText('runbook.txt', { exact: true })).toHaveCount(0);
    await expect(left.getByRole('button', { name: 'Upload', exact: true })).toBeDisabled();
    await member.locator('[data-view=workspaces]').click();
    await member.locator('[data-view=files]').click();
    await expect(member.getByRole('heading', { name: 'No registered file roots', exact: true })).toBeVisible();
    await capture(member, 'resource-member-revoked');
    await unaffected.locator('[data-pane=Left]').getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(unaffected.locator('[data-pane=Left]').getByText('runbook.txt', { exact: true })).toBeVisible();
    expect(await readFile(join(source, 'runbook.txt'), 'utf8')).toBe(content);
    expect(faults).toEqual([]);
  } finally {
    for (const context of contexts) await context.close();
    for (const root of roots) cli(['root-remove', root.id]);
    await rm(folder, { recursive: true, force: true });
  }
});
