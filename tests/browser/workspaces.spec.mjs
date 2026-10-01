// SPDX-License-Identifier: Apache-2.0
// Exercise saved module workspaces through the real local service and package installer.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { capture, login } from './support.mjs';

function archive(title, kind = 'notes') {
  const ui = kind === 'audio' ? { type: 'audio-player', id: 'audio' } :
    { type: 'editor', id: 'notes', label: 'Workspace notes' };
  const manifest = { format_version: 1, id: `org.example.m${randomUUID().replaceAll('-', '')}`,
    display_name: title, version: '1.0.0', category: 'productivity', contract_version: 1, host_api: 1,
    runtime: { kind: 'declarative', language: 'none' },
    capabilities: ['workspace:read', 'workspace:write', ...(kind === 'audio' ? ['audio:playback'] : [])],
    dependencies: [], actions: [], files: {}, ui: { type: 'column', children: [ui] } };
  return execFileSync(process.env.FICC_PYTHON || 'python3', ['-c',
    'import io,sys,zipfile; b=io.BytesIO(); z=zipfile.ZipFile(b,"w"); z.writestr("manifest.json",sys.argv[1]); z.close(); sys.stdout.buffer.write(b.getvalue())',
    JSON.stringify(manifest)], { timeout: 10000 });
}

async function create(page, name) {
  await page.getByLabel('Workspace name', { exact: true }).fill(name);
  await page.getByRole('button', { name: 'New workspace', exact: true }).click();
  await expect(page.getByLabel('Saved workspace').locator('option', { hasText: name })).toHaveCount(1);
}

async function install(page, name, workspaces, kind = 'notes') {
  await page.getByRole('button', { name: 'Manage modules', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Module manager' });
  await dialog.getByLabel('Module package', { exact: true }).setInputFiles({ name: 'example.ficc-module.zip', mimeType: 'application/zip', buffer: archive(name, kind) });
  await dialog.getByRole('button', { name: 'Inspect file', exact: true }).click();
  await expect(dialog.getByRole('table', { name: 'Inspected module package' })).toContainText('Unverified');
  await dialog.getByLabel('I accept this unverified package source.').check();
  await dialog.getByRole('button', { name: 'Install disabled', exact: true }).click();
  const row = dialog.getByRole('table', { name: 'Installed modules' }).getByRole('row').filter({ hasText: name });
  await expect(row).toContainText('Disabled');
  await row.getByRole('button', { name: 'Enable', exact: true }).click();
  for (const workspace of workspaces) for (const checkbox of await dialog.locator('.module-grants').getByLabel(workspace, { exact: true }).all()) await checkbox.check();
  await dialog.getByRole('button', { name: 'Enable with selected grants', exact: true }).click();
  await expect(row).toContainText('Enabled');
  await dialog.getByRole('button', { name: 'Close', exact: true }).click();
  await page.getByLabel('Installed module', { exact: true }).selectOption({ label: name });
  await page.getByRole('button', { name: 'Add module', exact: true }).click();
}

test('installed notes survive hiding, docking, reload and independent windows', async ({ page, context }) => {
  const faults = []; page.on('pageerror', error => faults.push(error.message));
  page.on('dialog', dialog => dialog.accept());
  await login(page); await page.locator('[data-view=workspaces]').click();
  const name = `Notes ${randomUUID().slice(0, 8)}`, title = `${name} module`;
  await create(page, name); await install(page, title, [name]);
  const panel = page.getByRole('tabpanel', { name: title, exact: true });
  const notes = panel.getByLabel('Workspace notes', { exact: true });
  await expect(notes).toBeVisible(); await notes.fill('Saved <script>plain text</script>');
  expect(await page.evaluate(() => document.documentElement.scrollHeight)).toBeLessThan(4000);
  if (process.env.FICC_CAPTURE_DIR) await page.screenshot({ path: `${process.env.FICC_CAPTURE_DIR}/workspace-notes-before-save.png` });
  await panel.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(panel.locator('.module-editor-panel [role=status]')).toHaveText('Saved');
  await notes.fill('Private unsaved draft');
  await panel.getByRole('button', { name: 'Hide', exact: true }).click();
  await expect(notes).toHaveCount(0);
  await page.locator('[data-view=overview]').click();
  await expect(page.getByRole('alert').filter({ hasText: 'Save or discard unsaved text' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Workspace', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Show hidden panels', exact: true }).click();
  await expect(notes).toHaveValue('Private unsaved draft');
  await panel.getByRole('button', { name: 'Discard changes', exact: true }).click();
  await expect(notes).toHaveValue('Saved <script>plain text</script>');
  await panel.getByRole('button', { name: 'Float', exact: true }).click();
  await page.getByRole('button', { name: 'Fullscreen', exact: true }).click();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement?.classList.contains('workspaces'))).toBe(true);
  await panel.getByRole('button', { name: 'Expand', exact: true }).click();
  await panel.getByRole('button', { name: 'Restore panel', exact: true }).click();
  await page.getByRole('button', { name: 'Exit fullscreen', exact: true }).click();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement)).toBeNull();
  await page.getByRole('button', { name: 'Expand workspace area', exact: true }).click();
  await page.setViewportSize({ width: 760, height: 620 });
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'Recover panels', exact: true }).click();
  await expect(notes).toBeVisible();
  expect(await page.evaluate(() => {
    const surface = document.querySelector('.workspace-surface').getBoundingClientRect();
    return surface.bottom <= document.querySelector('.workspaces').getBoundingClientRect().bottom + 1;
  })).toBe(true);
  await panel.getByRole('button', { name: 'Dock', exact: true }).click();
  await capture(page, 'workspace-notes-760');
  const popupPromise = context.waitForEvent('page');
  await page.getByLabel('Saved workspace').selectOption({ label: name });
  await page.getByRole('button', { name: 'Open in window', exact: true }).click();
  const popup = await popupPromise;
  popup.on('dialog', dialog => dialog.accept());
  await expect(popup.getByLabel('Workspace notes', { exact: true })).toHaveValue('Saved <script>plain text</script>');
  expect(new URL(popup.url()).searchParams.get('surface')).not.toBe(new URL(page.url()).searchParams.get('surface'));
  expect(await popup.evaluate(() => window.opener)).toBeNull();
  await popup.close();
  await page.locator('[data-view=overview]').click();
  await expect(page.getByRole('heading', { name: 'Cluster overview', exact: true })).toBeVisible();
  await page.locator('[data-view=workspaces]').click();
  await expect(notes).toHaveValue('Saved <script>plain text</script>');
  await page.reload(); await expect(notes).toHaveValue('Saved <script>plain text</script>');
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  expect(faults).toEqual([]);
});

function wave() {
  const count = 8000 * 40, bytes = Buffer.alloc(44 + count * 2);
  bytes.write('RIFF'); bytes.writeUInt32LE(bytes.length - 8, 4); bytes.write('WAVEfmt ', 8);
  bytes.writeUInt32LE(16, 16); bytes.writeUInt16LE(1, 20); bytes.writeUInt16LE(1, 22);
  bytes.writeUInt32LE(8000, 24); bytes.writeUInt32LE(16000, 28); bytes.writeUInt16LE(2, 32);
  bytes.writeUInt16LE(16, 34); bytes.write('data', 36); bytes.writeUInt32LE(count * 2, 40);
  for (let i = 0; i < count; i++) bytes.writeInt16LE(Math.round(Math.sin(i * Math.PI * 440 / 4000) * 4096), 44 + i * 2);
  return { name: 'tone.wav', mimeType: 'audio/wav', buffer: bytes };
}

test('real sound leases prevent duplicate playback and share master mute across windows', async ({ page, context }) => {
  page.on('dialog', dialog => dialog.accept());
  await login(page); await page.locator('[data-view=workspaces]').click();
  const name = `Sound ${randomUUID().slice(0, 8)}`, title = `${name} module`;
  await create(page, name); await install(page, title, [name], 'audio');
  const panel = page.getByRole('tabpanel', { name: title, exact: true });
  await panel.getByLabel('Select audio file', { exact: true }).setInputFiles(wave());
  await panel.getByLabel('Source volume', { exact: true }).fill('25');
  await expect.poll(() => page.evaluate(async name => {
    const value = await (await fetch('/api/v1/workspaces')).json();
    return value.workspaces.find(space => space.name === name).instances[0].state.audio?.volume;
  }, name)).toBe(.25);
  await panel.getByRole('button', { name: 'Play', exact: true }).click();
  await expect(panel.getByText('Playing', { exact: true })).toBeVisible();
  const popupPromise = context.waitForEvent('page');
  await page.getByLabel('Saved workspace').selectOption({ label: name });
  await page.getByRole('button', { name: 'Open in window', exact: true }).click();
  const popup = await popupPromise; popup.on('dialog', dialog => dialog.accept());
  await expect(popup.getByLabel('Source volume', { exact: true })).toHaveValue('25');
  await popup.getByLabel('Select audio file', { exact: true }).setInputFiles(wave());
  await popup.getByRole('button', { name: 'Play', exact: true }).click();
  await expect(popup.getByText('This source is playing in another window. Stop it there first.', { exact: true })).toBeVisible();
  await popup.getByRole('button', { name: 'Mute all', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Unmute all', exact: true })).toBeVisible();
  await panel.getByRole('button', { name: 'Stop', exact: true }).click();
  await popup.getByRole('button', { name: 'Play', exact: true }).click();
  await expect(popup.getByText('Playing', { exact: true })).toBeVisible();
  await popup.getByRole('button', { name: 'Unmute all', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Mute all', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Manage modules', exact: true }).click();
  const manager = page.getByRole('dialog', { name: 'Module manager' });
  await manager.getByRole('row').filter({ hasText: title }).getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(popup.getByText('Playback access was lost. Select Play to retry.', { exact: true })).toBeVisible();
  await manager.getByRole('button', { name: 'Close', exact: true }).click();
  await popup.close();
});

test('a fresh launch resumes saved tiles and floating geometry without allocating a new layout', async ({ page, context }) => {
  page.on('dialog', dialog => dialog.accept());
  await login(page); await page.locator('[data-view=workspaces]').click();
  const name = `Resume ${randomUUID().slice(0, 8)}`, other = `${name} second`, title = `${name} notes`;
  await create(page, name); await install(page, title, [name]);
  const panel = page.getByRole('tabpanel', { name: title, exact: true });
  await panel.getByLabel('Workspace notes', { exact: true }).fill('Saved text in a resumed arrangement');
  await panel.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(panel.locator('.module-editor-panel [role=status]')).toHaveText('Saved');
  await panel.getByRole('button', { name: 'Float', exact: true }).click();
  await create(page, other);
  await page.getByLabel('Saved workspace').selectOption({ label: name });
  await page.getByRole('button', { name: 'Open', exact: true }).click();
  await page.locator('[data-view=overview]').click();
  const savedUrl = page.url(), surfaceId = new URL(savedUrl).searchParams.get('surface');
  const readLayouts = () => page.evaluate(async id => {
    const all = await (await fetch('/api/v1/workspace-layouts')).json();
    const surface = await (await fetch(`/api/v1/workspace-surfaces/${id}`)).json();
    const views = await Promise.all(surface.tiles.map(async tile =>
      (await fetch(`/api/v1/workspaces/${tile.workspace_id}/views/${tile.view_id}`)).json()));
    return { count: all.surfaces.length, surface, views };
  }, surfaceId);
  const saved = await readLayouts();
  expect(saved.surface.tiles).toHaveLength(2);
  expect(saved.views.some(view => view.layout.floatingGroups?.length === 1)).toBe(true);
  await page.goto(new URL(savedUrl).origin);
  await expect(page.getByRole('heading', { name: 'Cluster overview', exact: true })).toBeVisible();
  await page.locator('[data-view=workspaces]').click();
  await expect(page.getByRole('button', { name: 'Resume saved window', exact: true })).toBeVisible();
  expect(new URL(page.url()).searchParams.has('surface')).toBe(false);
  expect((await readLayouts()).count).toBe(saved.count);
  await page.getByRole('button', { name: 'Resume saved window', exact: true }).click();
  const manager = page.getByRole('dialog', { name: 'Saved layouts', exact: true });
  const row = manager.getByRole('row').filter({ hasText: surfaceId.slice(0, 12) });
  await row.getByRole('button', { name: 'Resume window layout', exact: true }).click();
  await expect(page).toHaveURL(`${new URL(savedUrl).origin}/?surface=${surfaceId}`);
  await expect(page.getByLabel('Workspace notes', { exact: true })).toHaveValue('Saved text in a resumed arrangement');
  await expect(page.locator('.workspace-tile')).toHaveCount(2);
  await expect(page.locator('.workspace-dock .dv-resize-container')).toHaveCount(1);
  const restored = await readLayouts();
  expect(restored.count).toBe(saved.count);
  expect(restored.surface.tiles).toEqual(saved.surface.tiles);
  expect(restored.views.map(view => view.layout)).toEqual(saved.views.map(view => view.layout));
  await capture(page, 'workspace-resumed-window');
  await page.getByLabel('Saved workspace').selectOption({ label: name });
  const popupPromise = context.waitForEvent('page');
  await page.getByRole('button', { name: 'Open in window', exact: true }).click();
  const popup = await popupPromise; popup.on('dialog', dialog => dialog.accept());
  await expect(popup.getByLabel('Workspace notes', { exact: true })).toHaveValue('Saved text in a resumed arrangement');
  expect(new URL(popup.url()).searchParams.get('surface')).not.toBe(surfaceId);
  await expect.poll(async () => popup.evaluate(async () => (await (await fetch(`/api/v1/workspace-surfaces/${new URLSearchParams(location.search).get('surface')}`)).json()).tiles.length)).toBe(1);
  const popupSurface = await popup.evaluate(async () => (await fetch(`/api/v1/workspace-surfaces/${new URLSearchParams(location.search).get('surface')}`)).json());
  const ids = saved.surface.tiles.map(tile => tile.view_id);
  expect(ids).not.toContain(popupSurface.tiles[0].view_id);
  await popup.close();
});
