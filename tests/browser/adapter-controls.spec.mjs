// SPDX-License-Identifier: Apache-2.0
// Check exact provider grants, current readiness and private Windows account edits.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { capture } from './support.mjs';

let server, origin;
test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const name = request.url.slice(1);
    if (!name) {
      response.setHeader('Content-Type', 'text/html');
      response.end('<!doctype html><html lang="en"><meta charset="utf-8"><title>Provider controls</title><link rel="stylesheet" href="/console.css"><link rel="stylesheet" href="/workspaces.css"><main></main></html>'); return;
    }
    if (!/^[a-z0-9-]+\.(js|css)$/u.test(name)) { response.writeHead(404); response.end(); return; }
    try {
      response.setHeader('Content-Type', name.endsWith('.js') ? 'text/javascript' : 'text/css');
      response.end(await readFile(new URL(`../../web/static/${name}`, import.meta.url)));
    } catch { response.writeHead(404); response.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise(resolve => server.close(resolve)); });

for (const count of [1, 64]) test(`provider grant disclosure and changed endpoint readiness N=${count}`, async ({ page }) => {
  const digest = 'b'.repeat(64), writes = [];
  const endpoints = Array.from({ length: count }, (_, index) => ({ id: (index + 1).toString(16).padStart(32, '0'), name: `Endpoint ${index}` }));
  const profiles = endpoints.map((endpoint, index) => ({ id: (index + 100).toString(16).padStart(32, '0'),
    endpoint_id: endpoint.id, digest, display_name: `Adapter ${index}`, consistency: 'checked-before-dispatch',
    enabled: true, admin_granted: true, ready: false, revision: index + 3,
    diagnostic: { code: 'adapter_endpoint_changed', message: 'Register a new profile for the changed endpoint.' } }));
  await page.route('**/api/v1/**', route => {
    const request = route.request(), path = new URL(request.url()).pathname.slice(7);
    if (request.method() !== 'GET') {
      writes.push({ path, body: request.postDataJSON() });
      return route.fulfill({ json: {} });
    }
    const value = path === '/modules' ? { modules: [{ digest, manifest: { role: 'provider-adapter', version: '1.0.0',
      id: 'org.example.adapter', display_name: 'Example adapter', adapter: { execution: 'controller' } } }] } :
      path === '/nodes' ? { nodes: [] } : path === '/windows-endpoints' ? { endpoints } :
        path === '/adapter-profiles' ? { profiles } : { bindings: [] };
    return route.fulfill({ json: value });
  });
  await page.goto(origin);
  await page.evaluate(async () => { (await import('/adapter-profiles.js')).adapterProfiles(); });
  const dialog = page.getByRole('dialog'), rows = dialog.getByRole('table').getByRole('row');
  await expect(rows).toHaveCount(count + 1);
  await expect(rows.last()).toContainText('Unavailable');
  await expect(rows.last()).toContainText('Register a new profile');
  await rows.last().getByRole('button', { name: 'Review account grant', exact: true }).click();
  await expect(dialog).toContainText(digest);
  await expect(dialog).toContainText('complete registered provider account');
  await expect(dialog).toContainText('Another administrator can change');
  const grant = dialog.getByRole('button', { name: 'Grant account access and probe', exact: true });
  await grant.click(); expect(writes).toEqual([]);
  await dialog.getByRole('checkbox').check();
  if (count === 1) await capture(page, 'adapter-account-grant');
  await grant.click();
  await expect(dialog).toContainText('Provider access granted');
  expect(writes).toEqual([{ path: `/adapter-profiles/${profiles.at(-1).id}/grant`,
    body: { expected_revision: profiles.at(-1).revision, confirm: true } }]);
});

for (const count of [1, 64]) test(`Windows account edits keep saved credentials private N=${count}`, async ({ page }) => {
  const writes = [], endpoints = Array.from({ length: count }, (_, index) => ({
    id: (index + 1).toString(16).padStart(32, '0'), name: `Windows ${index}`, host: `windows-${index}.example`,
    port: 5986, configuration: 'ProviderEndpoint', commands: [{ name: 'Get-FICCEndpointIdentity', parameters: [] }],
    certificate_sha256: 'c'.repeat(64), revision: index + 4, enabled: true,
    vmconnect: { port: 2179, certificate_sha256: 'd'.repeat(64) },
  }));
  await page.route('**/api/v1/windows-endpoints**', route => {
    if (route.request().method() === 'GET') return route.fulfill({ json: { endpoints } });
    writes.push(route.request().postDataJSON());
    if (writes.length === 1) return route.fulfill({ status: 409, json: { error: { code: 'endpoint_changed', message: 'The endpoint changed. Retry after inspection.' } } });
    return route.fulfill({ json: endpoints.at(-1) });
  });
  await page.goto(origin);
  await page.evaluate(async () => { (await import('/windows-endpoints.js')).windowsEndpoints(); });
  const dialog = page.getByRole('dialog'), rows = dialog.getByRole('table').getByRole('row');
  await expect(rows).toHaveCount(count + 1);
  await rows.last().getByRole('button', { name: 'Edit', exact: true }).click();
  const username = dialog.getByRole('textbox', { name: 'Management account: User name', exact: true });
  const password = dialog.getByLabel('Management account: Password', { exact: true });
  await expect(username).toHaveValue(''); await expect(password).toHaveValue('');
  await username.fill('synthetic-operator'); await password.fill('synthetic-input-only');
  const save = dialog.getByRole('button', { name: 'Save endpoint', exact: true });
  await save.click();
  await expect(dialog).toContainText('The endpoint changed');
  await expect(username).toHaveValue(''); await expect(password).toHaveValue('');
  expect(writes[0].credentials.password).toBe('synthetic-input-only');
  expect(writes[0].expected_revision).toBe(endpoints.at(-1).revision);
  await expect(dialog).not.toContainText('synthetic-input-only');
  if (count === 1) await capture(page, 'windows-private-account-edit');
  await save.click();
  await expect(dialog).toContainText('Windows endpoint saved');
  expect(writes[1].credentials).toBeUndefined(); expect(writes[1].ca_pem).toBeUndefined();
  expect(writes[1].vmconnect.credentials).toBeUndefined();
  expect(writes[1].vmconnect.certificate_sha256).toBe('d'.repeat(64));
});
