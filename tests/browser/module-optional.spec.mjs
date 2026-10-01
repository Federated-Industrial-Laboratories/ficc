// SPDX-License-Identifier: Apache-2.0
// Exercise required and optional grants in the actual module manager and selector.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

let server, origin;
const files = new Set(['components.js', 'module-manager.js', 'module-targets.js', 'adapter-profiles.js',
  'provider-contracts.js', 'windows-endpoints.js', 'api.js', 'console.css']);
test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const name = request.url.slice(1);
    if (!name) {
      response.setHeader('Content-Type', 'text/html');
      response.end('<!doctype html><html lang="en"><title>Optional module grants</title><main></main></html>'); return;
    }
    if (!files.has(name)) { response.writeHead(404); response.end(); return; }
    response.setHeader('Content-Type', name.endsWith('.js') ? 'text/javascript' : 'text/css');
    response.end(await readFile(new URL(`../../web/static/${name}`, import.meta.url)));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise(resolve => server.close(resolve)); });

async function setup(page, count) {
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto(origin);
  await page.evaluate(count => {
    const ids = Array.from({ length: count }, (_, index) => `system-${index}`);
    const state = window.optional = { calls: [], ids, module: { digest: 'a'.repeat(64), enabled: true,
      manifest: { id: 'org.example.vm', display_name: 'VM inventory', version: '1.0.0', category: 'virtual-machines',
        host_api: 1, contract_version: 1, runtime: { kind: 'python', language: 'python', platform: 'linux', architecture: 'any', protocol: 2 },
        capabilities: ['vm:read', 'vm:power', 'vm:console'], optional_capabilities: ['vm:power', 'vm:console'] },
      grants: [{ capability: 'vm:read', target_ids: ids }] },
      catalogue: { capabilities: { 'vm:read': { kind: 'system', label: 'Read inventory' },
        'vm:power': { kind: 'system', label: 'Change VM power' }, 'vm:console': { kind: 'system', label: 'Open console' } },
      targets: { system: ids.map(id => ({ id, name: id })) } } };
    state.modules = [state.module];
    state.sandbox = { available: false, reason: 'User namespaces are unavailable.' };
    window.fetch = async (path, options) => {
      state.calls.push({ path, body: options?.body && JSON.parse(options.body) });
      const data = path.endsWith('/module-targets') ? state.catalogue : path.endsWith('/supplied-modules') ?
        { modules: [] } : path.endsWith('/sandbox') ? state.sandbox : { modules: state.modules };
      return { ok: true, status: 200, json: async () => data };
    };
  }, count);
  return errors;
}

for (const count of [1, 64]) test(`read-only target selection and explicit optional grants N=${count}`, async ({ page }) => {
  const errors = await setup(page, count);
  await page.evaluate(async () => {
    const { selectTargets, requiredCapabilities } = await import('/module-targets.js');
    window.optional.required = requiredCapabilities(window.optional.module.manifest);
    window.optional.selection = selectTargets(window.optional.module, window.optional.ids);
  });
  expect(await page.evaluate(() => window.optional.required)).toEqual(['vm:read']);
  await expect(page.getByRole('dialog', { name: 'Module targets' }).getByRole('checkbox')).toHaveCount(count);
  await page.getByRole('button', { name: 'Use selected targets', exact: true }).click();
  expect(await page.evaluate(() => window.optional.selection)).toHaveLength(count);
  await page.evaluate(async () => {
    const { moduleManager } = await import('/module-manager.js');
    window.optional.manager = moduleManager([], () => {});
  });
  await page.getByRole('button', { name: 'Edit grants', exact: true }).click();
  await expect(page.locator('legend').filter({ hasText: 'vm:power' })).toContainText('(optional)');
  await expect(page.locator('legend').filter({ hasText: 'vm:console' })).toContainText('(optional)');
  const power = page.locator('fieldset').filter({ has: page.locator('legend').filter({ hasText: 'vm:power' }) });
  expect(await power.getByRole('checkbox').evaluateAll(items => items.some(item => item.checked))).toBe(false);
  await page.getByRole('button', { name: 'Enable with selected grants', exact: true }).click();
  const body = await page.evaluate(() => window.optional.calls.find(call => call.path.endsWith('/activation')).body);
  expect(body).toEqual({ enabled: true, grants: [{ capability: 'vm:read', target_ids: Array.from({ length: count }, (_, index) => `system-${index}`) }] });
  expect(errors).toEqual([]);
});

test('legacy requirements and optional-only targets remain explicit', async ({ page }) => {
  const errors = await setup(page, 1);
  const result = await page.evaluate(async () => {
    const { requiredCapabilities, targetOptions } = await import('/module-targets.js');
    const legacy = structuredClone(window.optional.module);
    delete legacy.manifest.optional_capabilities;
    const missing = targetOptions(legacy, window.optional.catalogue).targets;
    const module = structuredClone(window.optional.module);
    module.manifest.optional_capabilities = [...module.manifest.capabilities];
    const selected = targetOptions(module, window.optional.catalogue);
    module.grants = [];
    return { legacy: requiredCapabilities(legacy.manifest), missing, selected,
      ungranted: targetOptions(module, window.optional.catalogue) };
  });
  expect(result.legacy).toEqual(['vm:read', 'vm:power', 'vm:console']);
  expect(result.missing).toEqual([]);
  expect(result.selected.required).toBe(false);
  expect(result.selected.targets).toHaveLength(1);
  expect(result.ungranted.targets).toEqual([]);
  expect(errors).toEqual([]);
});

test('equal names and versions retain exact package identity through grants and removal', async ({ page }) => {
  const errors = await setup(page, 1);
  await page.evaluate(async () => {
    const second = structuredClone(window.optional.module);
    second.digest = 'b'.repeat(64); second.enabled = false;
    window.optional.modules.push(second);
    const { moduleManager } = await import('/module-manager.js');
    moduleManager([], () => {});
  });
  const manager = page.getByRole('dialog', { name: 'Module manager', exact: true });
  const table = manager.getByRole('table', { name: 'Installed modules', exact: true });
  await expect(table.getByRole('row')).toHaveCount(3);
  await expect(table).toContainText('org.example.vm');
  const second = table.getByRole('row').filter({ hasText: 'bbbbbbbbbbbb' });
  await second.getByRole('button', { name: 'Details', exact: true }).click();
  const identity = manager.getByRole('table', { name: 'Installed package identity', exact: true });
  for (const text of ['org.example.vm', 'b'.repeat(64), '1.0.0', 'Unverified', 'Workspace module']) await expect(identity).toContainText(text);
  await expect(identity.getByRole('row').filter({ has: page.getByRole('rowheader', { name: 'Process protocol', exact: true }) })).toContainText('2');
  await second.getByRole('button', { name: 'Enable', exact: true }).click();
  await expect(manager.getByRole('table', { name: 'Package grant identity', exact: true })).toContainText('b'.repeat(64));
  await expect(manager.getByRole('table', { name: 'Package replaced by activation', exact: true })).toContainText('a'.repeat(64));
  await expect(manager).toContainText('Existing panels keep their old digest and saved data.');
  await manager.getByRole('button', { name: 'Enable with selected grants', exact: true }).click();
  expect(await page.evaluate(() => window.optional.calls.filter(call => call.path.endsWith('/activation')).map(call => call.path)))
    .toEqual([`/api/v1/modules/${'b'.repeat(64)}/activation`]);
  await second.getByRole('button', { name: 'Remove', exact: true }).click();
  const confirmation = page.getByRole('dialog', { name: 'Remove module?', exact: true });
  for (const text of ['org.example.vm', 'b'.repeat(64), '1.0.0', 'Unverified', 'Workspace module']) await expect(confirmation).toContainText(text);
  await confirmation.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(await page.evaluate(() => window.optional.calls.filter(call => call.path.endsWith('b'.repeat(64))))).toEqual([]);
  expect(errors).toEqual([]);
});

test('sandbox diagnostics show refusal and retry without installing or enabling a package', async ({ page }) => {
  const errors = await setup(page, 1);
  await page.evaluate(async () => { const { moduleManager } = await import('/module-manager.js'); moduleManager([], () => {}); });
  const manager = page.getByRole('dialog', { name: 'Module manager', exact: true });
  await manager.getByRole('button', { name: 'Check module sandbox', exact: true }).click();
  await expect(manager.getByRole('alert')).toHaveText('Module sandbox unavailable: User namespaces are unavailable.');
  await expect(manager).toContainText('ficc module-sandbox');
  await expect(manager.getByRole('link', { name: 'scoped policy instructions' })).toHaveAttribute('rel', 'noopener noreferrer');
  await page.evaluate(() => { window.optional.sandbox = { available: true, reason: '' }; });
  await manager.getByRole('button', { name: 'Check module sandbox', exact: true }).click();
  await expect(manager.getByText('Module sandbox available.', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.optional.calls.filter(call => call.body !== undefined))).toEqual([]);
  expect(errors).toEqual([]);
});
