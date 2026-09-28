// SPDX-License-Identifier: Apache-2.0
// Exercise actual host components with bounded sample responses and no service.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { capture } from './support.mjs';

let server, origin;
const files = new Set(['components.js', 'ui-renderer.js', 'ui-components.js', 'ui-table.js', 'ui-audio-player.js',
  'audio-manager.js', 'audio-peak-processor.js', 'ui-file-editor.js', 'ui-vm-actions.js', 'ui-lifecycle-actions.js', 'provider-contracts.js', 'ui-viewers.js', 'viewer.js', 'fullscreen.js', 'api.js', 'console.css', 'workspaces.css', 'ui-components.css', 'audio.css']);
test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const name = request.url.slice(1);
    if (!name) {
      response.setHeader('Content-Type', 'text/html');
      response.end('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Component gallery</title><link rel="stylesheet" href="/console.css"><link rel="stylesheet" href="/workspaces.css"><link rel="stylesheet" href="/ui-components.css"><link rel="stylesheet" href="/audio.css"><main id="test"></main></html>'); return;
    }
    if (name === 'manifest.json') {
      response.setHeader('Content-Type', 'application/json');
      response.end(await readFile(new URL('../../modules/component-gallery/manifest.json', import.meta.url))); return;
    }
    if (!files.has(name)) { response.writeHead(404); response.end(); return; }
    response.setHeader('Content-Type', name.endsWith('.js') ? 'text/javascript' : 'text/css');
    response.end(await readFile(new URL(`../../web/static/${name}`, import.meta.url)));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise(resolve => server.close(resolve)); });

async function setup(page, count = 64) {
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin);
  await page.evaluate(async count => {
    const { renderModule } = await import('/ui-renderer.js');
    const manifest = await (await fetch('/manifest.json')).json();
    const state = window.uiTest = { calls: [], writes: [], errors: [], hold: false, reject: false };
    state.result = count => ({ version: 1, id: 'sample-request', results: [{ target: 'workspace-example', data: {
      rows: Array.from({ length: count }, (_, index) => ({ id: `sample-${String(index + 1).padStart(3, '0')}`,
        values: { name: `Sample ${index + 1}`, value: index + 1, state: 'Ready' } })),
      text: `Loaded ${count} sample rows.`, state: 'ready', value: count,
      lines: [`Loaded ${count} rows.`, '<script>plain text</script>'], details: [{ label: 'Rows', value: count }],
    } }] });
    state.module = { manifest }; state.instance = { id: 'sample-instance', state: {} };
    state.invoke = async (action, parameters) => {
      state.calls.push({ action, parameters, frozen: Object.isFrozen(parameters), selectionFrozen: !parameters.selected || Object.isFrozen(parameters.selected) });
      if (state.hold) await new Promise(resolve => { state.resume = resolve; });
      if (state.reject) throw Error('Sample request failed.');
      return action === 'load' ? state.result(parameters.count) : { results: [{ data: { text: `Selected: ${parameters.selected.join(', ') || 'none'}` } }] };
    };
    state.view = renderModule(state.instance, state.module, { saveState: async patch => { state.writes.push(patch); }, invoke: state.invoke });
    document.querySelector('#test').append(state.view.element);
    document.querySelector('[aria-label="Row count"]').value = String(count);
  }, count);
  return errors;
}

for (const count of [1, 64]) test(`stable table selection, order, filter and pages N=${count}`, async ({ page }) => {
  const errors = await setup(page, count);
  await page.getByRole('button', { name: 'Load sample rows', exact: true }).click();
  await expect(page.getByText(`Loaded ${count} sample rows.`, { exact: true })).toBeVisible();
  await page.getByLabel('Select sample-001', { exact: true }).check();
  await page.getByRole('button', { name: 'Sort by Value', exact: true }).click();
  await page.getByRole('button', { name: 'Sort by Value', exact: true }).click();
  if (count === 64) {
    await expect(page.locator('tbody tr').first()).toHaveAttribute('data-row-id', 'sample-064');
    await page.getByLabel('Select sample-064', { exact: true }).check();
    await page.getByLabel('Filter Sample resources', { exact: true }).fill('Sample 64');
    await expect(page.getByLabel('Select sample-064', { exact: true })).toBeChecked();
    await page.getByLabel('Filter Sample resources', { exact: true }).fill('No match');
    await expect(page.getByText('No rows', { exact: true })).toBeVisible();
  }
  await page.getByRole('button', { name: 'Read selection', exact: true }).click();
  const call = await page.evaluate(() => window.uiTest.calls.at(-1));
  expect(call.parameters.selected).toEqual(count === 1 ? ['sample-001'] : ['sample-001', 'sample-064']);
  expect(call.frozen && call.selectionFrozen).toBe(true);
  await page.getByLabel('Filter Sample resources', { exact: true }).fill('');
  if (count === 64) {
    await page.getByRole('button', { name: 'Next page', exact: true }).first().click();
    await expect(page.locator('tbody tr').first()).toHaveAttribute('data-row-id', 'sample-056');
  }
  if (count === 64) {
    await capture(page, 'components-table');
    await page.getByLabel('Select sample-056', { exact: true }).focus();
  }
  await page.evaluate(() => { window.uiTest.view.update('load', window.uiTest.result(1)); });
  if (count === 64) await expect(page.getByLabel('Filter Sample resources', { exact: true })).toBeFocused();
  await page.getByRole('button', { name: 'Read selection', exact: true }).click();
  expect(await page.evaluate(() => window.uiTest.calls.at(-1).parameters.selected)).toEqual(['sample-001']);
  expect(errors).toEqual([]);
});

test('tabs, native fields, tree and menu expose keyboard controls', async ({ page }) => {
  await setup(page);
  const data = page.getByRole('tab', { name: 'Data', exact: true }); await data.focus(); await data.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'Controls', exact: true })).toBeFocused();
  await page.getByLabel('View mode', { exact: true }).selectOption('wide');
  await page.getByRole('radio', { name: 'Large', exact: true }).check();
  await page.getByLabel('Use sample values', { exact: true }).uncheck();
  const root = page.getByRole('treeitem', { name: 'Samples', exact: true }); await root.focus(); await root.press('ArrowDown');
  await expect(page.getByRole('treeitem', { name: 'Sample A', exact: true })).toBeFocused();
  await page.getByRole('treeitem', { name: 'Sample A', exact: true }).press('Enter');
  await expect(page.getByRole('treeitem', { name: 'Sample A', exact: true })).toHaveAttribute('aria-selected', 'true');
  await page.getByRole('treeitem', { name: 'Sample A', exact: true }).press('ArrowLeft'); await root.press('ArrowLeft');
  await expect(root).toHaveAttribute('aria-expanded', 'false'); await root.press('ArrowRight');
  await expect(root).toHaveAttribute('aria-expanded', 'true');
  await page.getByRole('navigation', { name: 'Sample pages' }).getByRole('button', { name: 'Next page' }).click();
  await expect(page.getByRole('navigation', { name: 'Sample pages' })).toContainText('Page 2 of 4');
  await page.locator('summary', { hasText: 'Sample menu' }).click();
  await page.getByRole('button', { name: 'Refresh sample rows' }).focus(); await page.keyboard.press('Escape');
  await expect(page.locator('summary', { hasText: 'Sample menu' })).toBeFocused();
  await expect(page.getByRole('button', { name: 'Refresh sample rows' })).toBeHidden();
  await capture(page, 'components-controls');
});

test('loading, errors, stale and disabled states retain data and suppress duplicate calls', async ({ page }) => {
  await setup(page, 1);
  await page.getByRole('button', { name: 'Load sample rows', exact: true }).click();
  await page.evaluate(() => { window.uiTest.hold = true; });
  await page.getByRole('button', { name: 'Load sample rows', exact: true }).click();
  await expect(page.locator('[data-component-id="resources"]')).toHaveAttribute('aria-busy', 'true');
  await expect(page.getByLabel('Select sample-001', { exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Load sample rows', exact: true })).toBeDisabled();
  await page.evaluate(() => { window.uiTest.reject = true; window.uiTest.resume(); });
  await expect(page.locator('[data-component-id="resources"]')).toHaveAttribute('data-state', 'error');
  await expect(page.getByLabel('Select sample-001', { exact: true })).toBeEnabled();
  await page.getByRole('tab', { name: 'States', exact: true }).click();
  await expect(page.getByText('Data is stale', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Disabled field', { exact: true })).toBeDisabled();
  await capture(page, 'components-states');
});

test('untrusted result data is rejected atomically and strings remain text', async ({ page }) => {
  await setup(page, 1); await page.getByRole('button', { name: 'Load sample rows', exact: true }).click();
  const failures = await page.evaluate(() => {
    const test = window.uiTest, rejected = [];
    const changes = [data => { data.rows[0].id = '__proto__'; }, data => { data.rows.push(data.rows[0]); },
      data => { data.rows = Array.from({ length: 129 }, (_, index) => ({ id: `row-${index}`, values: {} })); },
      data => { data.text = 'x'.repeat(8193); }, data => { data.value = Infinity; },
      data => { data.rows[0].values = JSON.parse('{"constructor":"bad"}'); },
      data => { delete data.lines; }, data => { data.lines = ['x'.repeat(2049)]; },
      data => { data.extra = Array(257).fill(0); }, data => { data.extra = 'x'.repeat(65537); }];
    for (const change of changes) {
      const result = test.result(1); change(result.results[0].data);
      try { test.view.update('load', result); rejected.push(false); } catch { rejected.push(true); }
    }
    const result = test.result(1); result.results[0].data.rows[0].values.name = '<img src=x onerror=alert(1)>';
    test.view.update('load', result); return rejected;
  });
  expect(failures).toEqual(Array(10).fill(true));
  await expect(page.locator('tbody')).toContainText('<img src=x onerror=alert(1)>');
  await expect(page.locator('.module-log')).toContainText('<script>plain text</script>');
  expect(await page.locator('#test img, #test script').count()).toBe(0);
});

test('bound fields update in place and explicit action parameters take frozen field snapshots', async ({ page }) => {
  await setup(page);
  await page.evaluate(async () => {
    const { renderModule } = await import('/ui-renderer.js'); const state = window.uiTest; state.view.dispose();
    const bind = property => ({ action: 'load', path: [property] });
    state.view = renderModule(state.instance, { manifest: { actions: [{ id: 'load' }, { id: 'send' }], ui: {
      type: 'column', children: [
        { type: 'field', name: 'name', label: 'Bound name', value: 'Old', bind: { value: bind('name') } },
        { type: 'select', name: 'choice', label: 'Bound choice', options: [], value: '', bind: { options: bind('options'), value: bind('choice') } },
        { type: 'radio', name: 'radio', label: 'Bound radio', options: [], value: '', bind: { options: bind('options'), value: bind('choice') } },
        { type: 'button', label: 'Send fields', action: 'send', parameters: { text: { field: 'name' }, chosen: { field: 'choice' }, fixed: { value: 'constant' } } },
      ],
    } } }, { invoke: async (action, params) => { state.params = params; return {}; } });
    document.querySelector('#test').replaceChildren(state.view.element);
  });
  await page.getByLabel('Bound name', { exact: true }).focus();
  await page.evaluate(() => window.uiTest.view.update('load', { name: 'New', options: [{ id: 'one', label: 'One' }], choice: 'one' }));
  await expect(page.getByLabel('Bound name', { exact: true })).toBeFocused();
  await expect(page.getByLabel('Bound name', { exact: true })).toHaveValue('New');
  await page.getByRole('button', { name: 'Send fields', exact: true }).click();
  expect(await page.evaluate(() => ({ ...window.uiTest.params }))).toEqual({ text: 'New', chosen: 'one', fixed: 'constant' });
  await page.getByRole('radio', { name: 'One', exact: true }).focus();
  await page.evaluate(() => window.uiTest.view.update('load', { name: 'New', options: [{ id: 'two', label: 'Two' }], choice: 'two' }));
  await expect(page.getByRole('radio', { name: 'Two', exact: true })).toBeFocused();
});

test('notes save only their own key and preserve text typed during an in-flight save', async ({ page }) => {
  await setup(page);
  await page.evaluate(async () => {
    const { renderModule } = await import('/ui-renderer.js'); const state = window.uiTest; state.view.dispose();
    state.drafts = { notes: 'Unsaved draft' }; state.instance.state = { notes: 'Saved note', other: 'Keep' };
    state.view = renderModule(state.instance, { manifest: { ui: { type: 'column', children: [{ type: 'editor', id: 'notes', label: 'Notes', value: '' }] } } }, {
      drafts: state.drafts, saveState: async patch => { state.writes.push(patch); await new Promise(resolve => { state.saved = resolve; }); },
    });
    document.querySelector('#test').replaceChildren(state.view.element);
  });
  await expect(page.getByLabel('Notes', { exact: true })).toHaveValue('Unsaved draft');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await page.getByLabel('Notes', { exact: true }).fill('Newer draft');
  await page.evaluate(() => window.uiTest.saved());
  await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.uiTest.writes)).toEqual([{ notes: 'Unsaved draft' }]);
  expect(await page.evaluate(() => window.uiTest.drafts)).toEqual({ notes: 'Newer draft' });
  await page.getByRole('button', { name: 'Discard changes', exact: true }).click();
  await expect(page.getByLabel('Notes', { exact: true })).toHaveValue('Unsaved draft');
});

test('audio preference save and tab visibility use the existing host manager contract', async ({ page }) => {
  await setup(page);
  await page.evaluate(async () => {
    const { renderModule } = await import('/ui-renderer.js'), { getAudioManager } = await import('/audio-manager.js');
    const state = window.uiTest; state.view.dispose(); state.manager = getAudioManager({ preview: true });
    state.view = renderModule(state.instance, { manifest: { ui: { type: 'tabs', label: 'Audio tabs', items: [
      { id: 'sound', label: 'Sound', children: [{ type: 'audio-player', id: 'sound' }] },
      { id: 'other', label: 'Other', children: [{ type: 'text', text: 'Other panel' }] },
    ] } } }, { audio: state.manager, saveState: async patch => { state.writes.push(patch); } });
    document.querySelector('#test').replaceChildren(state.view.element);
  });
  await page.getByRole('button', { name: 'Mute source', exact: true }).click();
  await page.evaluate(async () => { await window.uiTest.view.flush(); });
  expect(await page.evaluate(() => window.uiTest.writes)).toEqual([{ sound: { volume: 1, muted: true } }]);
  const wave = Buffer.alloc(44 + 16000 * 8);
  wave.write('RIFF'); wave.writeUInt32LE(wave.length - 8, 4); wave.write('WAVEfmt ', 8);
  wave.writeUInt32LE(16, 16); wave.writeUInt16LE(1, 20); wave.writeUInt16LE(1, 22);
  wave.writeUInt32LE(8000, 24); wave.writeUInt32LE(16000, 28); wave.writeUInt16LE(2, 32);
  wave.writeUInt16LE(16, 34); wave.write('data', 36); wave.writeUInt32LE(wave.length - 44, 40);
  await page.getByLabel('Select audio file', { exact: true }).setInputFiles({ name: 'sample.wav', mimeType: 'audio/wav', buffer: wave });
  await page.getByRole('button', { name: 'Play', exact: true }).click();
  await expect(page.locator('.audio-status')).toHaveText('Playing');
  await page.getByRole('tab', { name: 'Other', exact: true }).click();
  await expect(page.getByText('Other panel', { exact: true })).toBeVisible();
  await page.getByRole('tab', { name: 'Sound', exact: true }).click();
  await expect(page.locator('.audio-status')).toHaveText('Paused');
  await page.evaluate(async () => { window.uiTest.view.dispose(); await window.uiTest.manager.dispose(); });
});

test('small screen, zoom and reduced motion retain visible controls', async ({ page }) => {
  await setup(page, 64); await page.setViewportSize({ width: 480, height: 800 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.getByRole('button', { name: 'Load sample rows', exact: true }).click();
  await page.evaluate(() => { document.querySelector('#test').style.zoom = '1.5'; });
  await expect(page.getByLabel('Filter Sample resources', { exact: true })).toBeVisible();
  const metrics = await page.evaluate(() => {
    const root = document.querySelector('#test'), style = getComputedStyle(root.querySelector('button'));
    return { width: document.documentElement.scrollWidth, viewport: innerWidth, transition: style.transitionDuration };
  });
  expect(metrics.width).toBeLessThanOrEqual(metrics.viewport + 1); expect(metrics.transition).toBe('0s');
  await capture(page, 'components-small');
});
