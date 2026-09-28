// SPDX-License-Identifier: Apache-2.0
// Render the supplied container document with bounded sample results.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { capture } from './support.mjs';

let server, origin;
test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const name = request.url.slice(1);
    if (!name) {
      response.setHeader('Content-Type', 'text/html');
      response.end('<!doctype html><html lang="en"><meta charset="utf-8"><title>Container component check</title><link rel="stylesheet" href="/console.css"><link rel="stylesheet" href="/workspaces.css"><link rel="stylesheet" href="/ui-components.css"><main id="test"></main></html>'); return;
    }
    if (name === 'manifest.json') {
      response.setHeader('Content-Type', 'application/json');
      response.end(await readFile(new URL('../../modules/containers/manifest.json', import.meta.url))); return;
    }
    if (!/^[a-z0-9-]+\.(js|css)$/u.test(name)) { response.writeHead(404); response.end(); return; }
    try {
      const file = process.env.FICC_CONTAINER_UI_ROOT ? resolve(process.env.FICC_CONTAINER_UI_ROOT, name) : new URL(`../../web/static/${name}`, import.meta.url);
      response.setHeader('Content-Type', name.endsWith('.js') ? 'text/javascript' : 'text/css');
      response.end(await readFile(file));
    } catch { response.writeHead(404); response.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise(resolve => server.close(resolve)); });

for (const count of [1, 64]) test(`container controls preserve stable selected IDs N=${count}`, async ({ page }) => {
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin);
  await page.evaluate(async count => {
    const { renderModule } = await import('/ui-renderer.js');
    const manifest = await (await fetch('/manifest.json')).json();
    const state = window.containerCheck = { calls: [] };
    state.rows = Array.from({ length: count }, (_, index) => ({ id: `ctr-${'a'.repeat(32)}-container-${index.toString(16).padStart(64, '0')}`,
      values: { name: `Sample ${index + 1}`, kind: 'container', system: 'sample-node', provider: 'docker', namespace: '', state: 'running', replicas: null, error: '' } }));
    state.view = renderModule({ id: 'sample-instance', state: {} }, { manifest }, {
      saveState: async () => {}, invoke: async (action, parameters) => {
        state.calls.push({ action, parameters, frozen: Object.isFrozen(parameters) && (!parameters.resource_ids || Object.isFrozen(parameters.resource_ids)) });
        return { results: [{ target: 'sample-node', data: action === 'load' ? { rows: state.rows, notice: `Read ${count} sample workloads.` } : action === 'logs' ? { lines: ['Sample output', '<script>plain text</script>'] } : {} }] };
      },
    });
    document.querySelector('#test').append(state.view.element);
  }, count);
  await page.getByLabel('Provider', { exact: true }).selectOption('docker');
  await page.getByRole('button', { name: 'Read workloads', exact: true }).click();
  await expect(page.getByText(`Read ${count} sample workloads.`, { exact: true })).toBeVisible();
  const first = `ctr-${'a'.repeat(32)}-container-${'0'.repeat(64)}`;
  await page.getByLabel(`Select ${first}`, { exact: true }).check();
  await page.getByRole('button', { name: 'Sort by Name', exact: true }).click();
  await page.getByRole('button', { name: 'Sort by Name', exact: true }).click();
  if (count === 64) {
    await page.getByLabel('Filter workloads', { exact: true }).fill('Sample 64');
    const last = `ctr-${'a'.repeat(32)}-container-${'3f'.padStart(64, '0')}`;
    await page.getByLabel(`Select ${last}`, { exact: true }).check();
  }
  await page.getByRole('button', { name: 'Preview stop', exact: true }).click();
  const call = await page.evaluate(() => window.containerCheck.calls.at(-1));
  expect(call.action).toBe('preview-stop'); expect(call.parameters.resource_ids.length).toBe(count === 1 ? 1 : 2);
  expect(call.parameters.resource_ids[0]).toBe(first); expect(call.frozen).toBe(true);
  await page.getByLabel('Pod container name (optional)', { exact: true }).fill('app');
  await page.getByRole('button', { name: 'Read logs', exact: true }).click();
  await expect(page.getByText('<script>plain text</script>', { exact: false })).toBeVisible();
  expect(await page.evaluate(() => window.containerCheck.calls.at(-1).parameters.container)).toBe('app');
  await page.getByLabel('Filter workloads', { exact: true }).fill('');
  if (count === 64) await capture(page, 'container-components');
  expect(errors).toEqual([]);
});
