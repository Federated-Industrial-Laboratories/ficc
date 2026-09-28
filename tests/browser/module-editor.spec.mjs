// SPDX-License-Identifier: Apache-2.0
// Exercise the host text editor with bounded API fixtures.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { capture } from './support.mjs';

let server, origin;
const assets = new Set(['ui-file-editor.js', 'components.js', 'api.js', 'console.css', 'workspaces.css', 'ui-components.css']);
test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const name = request.url.slice(1);
    if (!name) {
      response.setHeader('Content-Type', 'text/html');
      response.end('<!doctype html><html lang="en"><meta charset="utf-8"><title>Text editor</title><link rel="stylesheet" href="console.css"><link rel="stylesheet" href="workspaces.css"><link rel="stylesheet" href="ui-components.css"><main id="test"></main></html>'); return;
    }
    if (!assets.has(name)) { response.writeHead(404); response.end(); return; }
    response.setHeader('Content-Type', name.endsWith('.js') ? 'text/javascript' : 'text/css');
    response.end(await readFile(new URL(`../../web/static/${name}`, import.meta.url)));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise(resolve => server.close(resolve)); });

async function setup(page, count = 1, writable = true) {
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin);
  await page.evaluate(async ({ count, writable }) => {
    const { fileEditor } = await import('/ui-file-editor.js');
    const state = window.editorTest = { drafts: {}, calls: [], writable, operations: [], mode: 'succeeded', text: 'Original text\n' };
    state.requester = async (path, options) => {
      const { body } = options; state.calls.push({ path, ...options });
      if (body.workspace_id !== 'workspace' || body.instance_id !== 'instance') throw Error('Missing editor identity');
      if (path.endsWith('/roots')) return { roots: [{ id: 'root', entry_id: 'folder', label: 'Registered text', writable: state.writable }] };
      if (path.endsWith('/list')) return { entries: Array.from({ length: count }, (_, index) => ({ name: `file-${index}.txt`, entry_id: `entry-${index}`, kind: 'file', size: 14 })), breadcrumbs: [{ name: 'Registered text', entry_id: 'folder' }], next_cursor: null };
      if (path.endsWith('/read')) return { results: [{ data: { text: state.text, writable: state.writable, sha256: 'a'.repeat(64) } }] };
      if (path.endsWith('/save')) {
        const operation = { id: options.idempotencyKey, items: [{ id: 'item', state: state.mode, retained: true, entry_id: 'new-entry', sha256: 'b'.repeat(64), message: state.mode === 'conflict' ? 'Published replacement; recover both copies.' : 'Saved' }] };
        state.operations.push(operation); state.text = body.items[0].text;
        if (state.lost) throw Error('Connection lost');
        return operation;
      }
      if (path.endsWith('/status')) { state.operations[0].items[0].state = 'succeeded'; return state.operations[0]; }
      if (path.endsWith('/operations')) return { operations: state.operations };
      if (path.endsWith('/recovery')) return { text: body.copy === 'original' ? 'External text\n' : state.text };
      if (path.endsWith('/cleanup')) { state.operations[0].items[0].retained = false; return state.operations[0]; }
      if (path.endsWith('/remove-receipt')) { state.operations = []; return { removed: true }; }
      throw Error('Unknown test action');
    };
    state.mount = () => {
      state.view = fileEditor({ workspaceId: 'workspace', instanceId: 'instance', key: 'files', drafts: state.drafts, requester: state.requester });
      document.querySelector('#test').replaceChildren(state.view.element);
    };
    state.mount();
  }, { count, writable });
  await expect(page.getByRole('button', { name: 'Open file-0.txt', exact: true })).toBeVisible();
  return errors;
}

for (const count of [1, 64]) test(`browse, edit, save, reload and recovery N=${count}`, async ({ page }) => {
  const errors = await setup(page, count);
  await expect(page.locator('tbody tr')).toHaveCount(count);
  await page.getByRole('button', { name: `Open file-${count - 1}.txt`, exact: true }).click();
  const text = page.getByRole('textbox', { name: 'Text editor', exact: true });
  await expect(text).toHaveValue('Original text\n');
  await text.fill('<script>plain text</script>\n');
  await expect(page.getByRole('button', { name: 'Save file', exact: true })).toBeDisabled();
  await page.getByLabel('I understand:', { exact: false }).check();
  await page.getByRole('button', { name: 'Save file', exact: true }).click();
  await expect(page.getByText('Saved text', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => Object.keys(window.editorTest.drafts))).toEqual([]);
  await page.getByRole('button', { name: 'Reload file', exact: true }).click();
  await expect(text).toHaveValue('<script>plain text</script>\n');
  await page.getByText('Retained edit copies', { exact: true }).click();
  await page.getByRole('button', { name: 'Refresh retained copies', exact: true }).click();
  await page.getByRole('button', { name: 'Read retained original', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Retained text', exact: true })).toHaveValue('External text\n');
  if (count === 1) await capture(page, 'module-editor-recovery');
  await page.getByRole('button', { name: 'Remove retained copies', exact: true }).click();
  await page.getByRole('button', { name: 'Remove receipt', exact: true }).click();
  await expect(page.getByText('No retained edit receipts.', { exact: true })).toBeVisible();
  const writes = await page.evaluate(() => window.editorTest.calls.filter(call => call.path.endsWith('/save')));
  expect(writes).toHaveLength(1); expect(writes[0].body.items[0].entry_id).toBe(`entry-${count - 1}`);
  expect(writes[0].idempotencyKey).toMatch(/^[a-f0-9]{32}$/); expect(errors).toEqual([]);
});

test('dirty draft survives view disposal and blocks file replacement', async ({ page }) => {
  await setup(page, 2); await page.getByRole('button', { name: 'Open file-0.txt', exact: true }).click();
  const text = page.getByRole('textbox', { name: 'Text editor', exact: true });
  await text.fill('Unsaved text');
  await page.getByRole('button', { name: 'Open file-1.txt', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText('Save or discard your text before opening another file.');
  await page.evaluate(() => { window.editorTest.view.dispose(); window.editorTest.mount(); });
  await expect(text).toHaveValue('Unsaved text');
  await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.editorTest.calls.filter(call => call.path.endsWith('/save')))).toHaveLength(0);
  await page.getByRole('button', { name: 'Discard draft', exact: true }).click();
  await expect(text).toHaveValue('Original text\n');
});

test('read-only preview cannot enable save', async ({ page }) => {
  await setup(page, 1, false); await page.getByRole('button', { name: 'Open file-0.txt', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Text editor', exact: true })).toHaveAttribute('readonly', '');
  await expect(page.getByRole('button', { name: 'Save file', exact: true })).toBeDisabled();
});

test('lost acknowledgement checks the original receipt without replay', async ({ page }) => {
  await setup(page); await page.getByRole('button', { name: 'Open file-0.txt', exact: true }).click();
  await page.getByRole('textbox', { name: 'Text editor', exact: true }).fill('Retained draft');
  await page.getByLabel('I understand:', { exact: false }).check();
  await page.evaluate(() => { window.editorTest.lost = true; });
  await page.getByRole('button', { name: 'Save file', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Check save outcome', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Check save outcome', exact: true }).click();
  await expect(page.getByText('Saved text', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.editorTest.calls.filter(call => call.path.endsWith('/save')))).toHaveLength(1);
});

test('published conflict keeps draft and requires explicit recovery before cleanup', async ({ page }) => {
  await setup(page); await page.getByRole('button', { name: 'Open file-0.txt', exact: true }).click();
  await page.getByRole('textbox', { name: 'Text editor', exact: true }).fill('Concurrent draft');
  await page.getByLabel('I understand:', { exact: false }).check();
  await page.evaluate(() => { window.editorTest.mode = 'conflict'; });
  await page.getByRole('button', { name: 'Save file', exact: true }).click();
  await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible();
  await page.getByText('Retained edit copies', { exact: true }).click();
  await page.getByRole('button', { name: 'Refresh retained copies', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Remove retained copies', exact: true })).toBeDisabled();
  await page.getByLabel('Recovery confirmed item', { exact: true }).check();
  await page.getByRole('button', { name: 'Remove retained copies', exact: true }).click();
  const cleanup = await page.evaluate(() => window.editorTest.calls.find(call => call.path.endsWith('/cleanup')));
  expect(cleanup.body.recovered).toBe(true); expect(cleanup.body.confirm).toBe(true);
});
