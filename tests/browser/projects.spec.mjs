// SPDX-License-Identifier: Apache-2.0
// Exercise project administration, independent user sessions and stale browser windows.
import { randomUUID } from 'node:crypto';
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, cli, login, origin } from './support.mjs';

async function api(page, path, options) {
  return page.evaluate(async ({ path, options }) => {
    const { request } = await import('/static/api.js');
    return request(path, options);
  }, { path, options });
}

async function memberLogin(page, subject, project) {
  const url = new URL(cli(['open', '--print-url', '--subject', subject, '--project', project]));
  await page.goto(origin);
  await page.evaluate(hash => history.replaceState(null, '', `/${hash}`), url.hash);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Workspace', exact: true })).toBeVisible();
  await expect(page.getByLabel('Current project')).toHaveValue(project);
}

test('owner administers identities and members use separate project workspaces', async ({ page, browser }) => {
  const label = randomUUID().slice(0, 8), userName = `Operator ${label}`, projectName = `Operations ${label}`;
  const faults = []; page.on('pageerror', error => faults.push(error.message));
  await login(page);
  await page.locator('[data-view=access]').click();
  await page.getByLabel('New identity label').fill(userName);
  await page.getByRole('button', { name: 'Create identity', exact: true }).click();
  await expect(page.getByRole('table', { name: 'User identities', exact: true })).toContainText(userName);
  await page.getByLabel('New project label').fill(projectName);
  await page.getByRole('button', { name: 'Create project', exact: true }).click();
  await expect(page.getByRole('table', { name: 'Projects', exact: true })).toContainText(projectName);
  await page.getByLabel('Membership project').selectOption({ label: projectName });
  await page.getByLabel('Membership identity').selectOption({ label: userName });
  // Await the selected project's response before changing its form values.
  await expect(page.getByRole('table', { name: 'Project memberships' })).not.toContainText(userName);
  for (const scope of ['workspaces:read', 'workspaces:write', 'modules:read', 'audio:playback']) {
    await page.getByRole('checkbox', { name: scope, exact: true }).check();
  }
  await page.getByRole('button', { name: 'Save membership', exact: true }).click();
  await expect(page.getByRole('table', { name: 'Project memberships' })).toContainText(userName);
  const project = (await api(page, '/projects')).projects.find(item => item.label === projectName);
  const user = (await api(page, '/identities')).identities.find(item => item.label === userName);
  await capture(page, 'project-administration');

  const context = await browser.newContext();
  try {
    const member = await context.newPage(); member.on('pageerror', error => faults.push(error.message));
    await memberLogin(member, user.id, project.id);
    await expect(member.locator('[data-view=overview]')).toBeDisabled();
    await expect(member.getByRole('button', { name: 'Manage modules', exact: true })).toBeHidden();
    await member.getByLabel('Workspace name', { exact: true }).fill(`Runbook ${label}`);
    await member.getByRole('button', { name: 'New workspace', exact: true }).click();
    await expect(member.getByLabel('Saved workspace').locator('option')).toHaveText(`Runbook ${label}`);
    const spaces = await api(member, '/workspaces');
    expect((await api(page, '/workspaces')).workspaces.some(item => item.id === spaces.workspaces[0].id)).toBe(false);
    await expect(page.getByLabel('Current project').locator('option', { hasText: projectName })).toHaveCount(1);
    let releaseSwitch;
    const switching = new Promise(resolve => { releaseSwitch = resolve; });
    await page.route('**/api/v1/session/project', async route => { await switching; await route.continue(); });
    try {
      await page.getByLabel('Current project').selectOption(project.id);
      await expect(page.getByLabel('Current project')).toBeDisabled();
      await expect(page.locator('[data-view=workspaces]')).toBeDisabled();
      await expect(page.locator('#main')).toHaveJSProperty('inert', true);
      releaseSwitch();
      await page.locator('[data-view=workspaces]').click();
      await expect(page.getByLabel('Current project')).toHaveValue(project.id);
    } finally { releaseSwitch(); await page.unroute('**/api/v1/session/project'); }
    await expect(page.getByLabel('Saved workspace').locator('option')).toHaveText(`Runbook ${label}`);
    await capture(member, 'project-member-workspace');
    const layouts = await api(member, '/workspace-layouts');
    const ownerLayouts = await api(page, '/workspace-layouts');
    expect(ownerLayouts.surfaces.every(item => !layouts.surfaces.some(other => other.id === item.id))).toBe(true);
  } finally { await context.close(); }
  expect(faults).toEqual([]);
});

test('a stale window cannot read or save under a newly selected project', async ({ page, context }) => {
  await login(page);
  const original = await api(page, '/session');
  const project = await api(page, '/projects', { method: 'POST', body: { label: `Switch ${randomUUID().slice(0, 8)}` } });
  const other = await context.newPage();
  try {
    await other.goto(origin);
    await expect(other.getByLabel('Current project')).toHaveValue(original.project.id);
    await other.getByLabel('Current project').selectOption(project.id);
    await expect.poll(async () => api(other, '/session').then(value => value.project.id).catch(() => null)).toBe(project.id);
    const denial = await page.evaluate(async () => {
      const { request } = await import('/static/api.js');
      try { await request('/workspaces'); return 'allowed'; }
      catch (error) { return error.code; }
    });
    expect(denial).toBe('project_changed');
    await other.getByLabel('Current project').selectOption(original.project.id);
    await expect.poll(async () => api(other, '/session').then(value => value.project.id).catch(() => null)).toBe(original.project.id);
    const sessionDenial = await page.evaluate(async () => {
      const { request } = await import('/static/api.js');
      try { await request('/workspaces'); return 'allowed'; }
      catch (error) { return error.code; }
    });
    expect(sessionDenial).toBe('session_changed');
  } finally { await other.close(); }
});
