// SPDX-License-Identifier: Apache-2.0
// Check the supplied profile selector and VM table with bounded fixture results.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

let server, origin;
const files = new Set(['components.js', 'ui-renderer.js', 'ui-components.js', 'ui-table.js', 'ui-audio-player.js',
  'audio-manager.js', 'audio-peak-processor.js', 'ui-file-editor.js', 'ui-lifecycle-actions.js', 'provider-contracts.js', 'ui-viewers.js',
  'viewer.js', 'fullscreen.js', 'api.js', 'console.css', 'workspaces.css', 'ui-components.css', 'audio.css']);
test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const name = request.url.slice(1);
    if (!name) { response.setHeader('Content-Type', 'text/html'); response.end('<!doctype html><html lang="en"><meta charset="utf-8"><title>Hyper-V panel</title><link rel="stylesheet" href="/console.css"><link rel="stylesheet" href="/ui-components.css"><main></main></html>'); return; }
    if (name === 'manifest.json') { response.setHeader('Content-Type', 'application/json'); response.end(await readFile(new URL('../../modules/hyperv/manifest.json', import.meta.url))); return; }
    if (!files.has(name)) { response.writeHead(404); response.end(); return; }
    response.setHeader('Content-Type', name.endsWith('.js') ? 'text/javascript' : 'text/css');
    response.end(await readFile(new URL(`../../web/static/${name}`, import.meta.url)));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise(resolve => server.close(resolve)); });

for (const count of [1, 64]) test(`select registered profile and stable VM rows N=${count}`, async ({ page }) => {
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin);
  await page.evaluate(async count => {
    const { renderModule } = await import('/ui-renderer.js');
    const manifest = await (await fetch('/manifest.json')).json();
    window.calls = [];
    const view = renderModule({ id: '1'.repeat(32), state: {} }, { manifest }, {
      saveState: async () => {}, workspaceId: '2'.repeat(32),
      invoke: async (action, parameters) => {
        window.calls.push({ action, parameters });
        return { results: [{ target: '3'.repeat(32), data: action === 'profiles' ? {
          profiles: [{ id: 'a'.repeat(32), label: 'Evaluation Hyper-V' }, { id: 'b'.repeat(32), label: 'Other registered profile' }],
        } : { rows: Array.from({ length: count }, (_, index) => ({ id: `vm-${'a'.repeat(32)}-${(index + 1).toString(16).padStart(32, '0')}`,
          values: { name: `VM ${index + 1}`, system: 'Evaluation Windows', state: 'off', vcpus: 1, memory: 32768, error: '' } })), notice: '' } }] };
      },
    });
    document.querySelector('main').append(view.element);
  }, count);
  await page.getByRole('button', { name: 'Read provider profiles', exact: true }).click();
  expect(await page.evaluate(() => window.calls[0])).toEqual({ action: 'profiles', parameters: {} });
  await page.getByLabel('Provider profile', { exact: true }).selectOption('a'.repeat(32));
  await page.getByRole('button', { name: 'Read VM inventory', exact: true }).click();
  await expect(page.locator('tbody tr')).toHaveCount(Math.min(count, 32));
  expect((await page.evaluate(() => window.calls.at(-1))).parameters.profile_id).toBe('a'.repeat(32));
  await page.getByLabel(`Select vm-${'a'.repeat(32)}-${'1'.padStart(32, '0')}`, { exact: true }).check();
  await page.getByRole('button', { name: 'Preview start', exact: true }).click();
  const preview = await page.evaluate(() => window.calls.at(-1));
  expect(preview.parameters.vm_ids).toEqual([`vm-${'a'.repeat(32)}-${'1'.padStart(32, '0')}`]);
  expect(preview.parameters.profile_id).toBe('a'.repeat(32));
  expect(errors).toEqual([]);
});
