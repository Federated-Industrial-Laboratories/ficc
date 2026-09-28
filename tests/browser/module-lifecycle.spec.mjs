// SPDX-License-Identifier: Apache-2.0
// Verify host confirmations, stable retry keys and retained operation history.
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
      response.end('<!doctype html><html lang="en"><meta charset="utf-8"><title>Action controls</title><link rel="stylesheet" href="/console.css"><link rel="stylesheet" href="/workspaces.css"><main></main></html>'); return;
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

for (const kind of ['vms', 'containers', 'admin']) for (const count of [1, 64]) test(`${kind} host action and recovery N=${count}`, async ({ page }) => {
  const vm = kind === 'vms', admin = kind === 'admin', label = vm ? 'VM' : admin ? 'administration' : 'container', id = 'a'.repeat(32), op = 'b'.repeat(32);
  const faults = [], keys = [], calls = [];
  page.on('pageerror', error => faults.push(error.message));
  let removed = false, resolved = false, commits = 0;
  const targets = Array.from({ length: count }, (_, index) => ({ node_id: `sample-${index}`, name: `Sample ${index}`,
    [vm ? 'vm_id' : 'resource_id']: `resource-${index}`, provider: admin ? 'systemd' : 'docker', kind: 'service', namespace: '', replicas: null, state: 'running' }));
  await page.route('**/api/v1/module-*/*', async route => {
    const request = route.request(), path = new URL(request.url()).pathname.split('/').at(-1), body = request.postDataJSON();
    calls.push({ path, body });
    if (path === 'preview') return route.fulfill({ json: { preview_id: id, action: vm ? 'shutdown' : 'stop', expires_at: Date.now() / 1000 + 120,
      [vm ? 'vms' : admin ? 'resources' : 'workloads']: targets, effect: admin ? 'Unit dependencies and configured stop timeouts apply; systemd can terminate processes.' : 'The provider allows 10 seconds to exit, then forces them to stop. Other clients can change the state during this request.' } });
    if (path === 'commit') {
      keys.push(request.headers()['idempotency-key']);
      if (++commits === 1) return route.fulfill({ status: 504, json: { error: { message: 'The response timed out.' } } });
    }
    const operation = { id: op, action: vm ? 'shutdown' : 'stop', created_at: 1, updated_at: 2, cleanup: null,
      targets: targets.map(item => ({ ...item, state: resolved ? 'resolved' : 'unknown', observed_state: 'shutoff', observed: { state: 'exited', replicas: null, ready: null } })) };
    if (path === 'resolve') { resolved = true; operation.targets.forEach(item => { item.state = 'resolved'; }); }
    if (path === 'forget') { removed = true; return route.fulfill({ json: { removed: true } }); }
    if (path === 'history') return route.fulfill({ json: { operations: removed ? [] : [{ ...operation, outcomes: { unknown: count } }] } });
    return route.fulfill({ json: operation });
  });
  await page.goto(origin);
  await page.evaluate(async ({ kind, id, vm, admin }) => {
    const { lifecycleActions } = await import('/ui-lifecycle-actions.js');
    const control = lifecycleActions({ workspace_id: 'c'.repeat(32), instance_id: 'd'.repeat(32) }, kind);
    document.querySelector('main').append(control.historyControl(), ...control.controls({ results: [{ data: { preview_id: id, [vm ? 'vms' : admin ? 'resources' : 'workloads']: [] } }] }));
  }, { kind, id, vm, admin });
  await page.getByRole('button', { name: `Review ${label} action in FICC`, exact: true }).click();
  const dialog = page.getByRole('dialog');
  if (!vm) await expect(dialog).toContainText(admin ? 'Unit dependencies' : '10 seconds');
  expect(await dialog.getByRole('row').count()).toBe(count + 1);
  const confirm = dialog.getByRole('button', { name: vm ? 'Shut down these VMs' : admin ? 'Stop these services' : 'Stop these containers', exact: true });
  await confirm.click();
  await expect(dialog).toContainText('Retry uses the same operation key');
  await confirm.click();
  expect(keys).toHaveLength(2); expect(keys[0]).toBe(keys[1]);
  await expect(dialog).toContainText(`Operation ${op}`);
  await dialog.getByRole('button', { name: 'Close', exact: true }).click();
  await page.getByRole('button', { name: `${vm ? 'VM' : admin ? 'Administration' : 'Container'} action history`, exact: true }).click();
  await dialog.getByRole('button', { name: 'Inspect operation', exact: true }).click();
  await expect(dialog).toContainText('unknown');
  await dialog.getByRole('button', { name: 'Close pending outcomes', exact: true }).click();
  expect(calls.some(item => item.path === 'resolve')).toBe(false);
  await dialog.getByRole('checkbox').check();
  await dialog.getByRole('button', { name: 'Close pending outcomes', exact: true }).click();
  expect(calls.find(item => item.path === 'resolve').body[vm ? 'vm_ids' : 'resource_ids']).toHaveLength(count);
  await expect(dialog).toContainText('resolved');
  await expect(dialog.getByRole('heading')).toBeInViewport();
  await expect(dialog.getByRole('button', { name: 'Close', exact: true })).toBeInViewport();
  if (count === 64 && !vm) await capture(page, `${kind}-host-operation`);
  await dialog.getByRole('checkbox').check();
  await dialog.getByRole('button', { name: 'Remove operation receipt', exact: true }).click();
  await expect(dialog).toContainText('Operation receipt removed');
  expect(removed).toBe(true); expect(faults).toEqual([]);
});

for (const action of ['reboot', 'poweroff']) test(`administration ${action} keeps queued power outcomes explicit`, async ({ page }) => {
  const preview = 'a'.repeat(32), operation = 'b'.repeat(32);
  let commits = 0;
  await page.route('**/api/v1/module-admin/*', route => {
    const path = new URL(route.request().url()).pathname.split('/').at(-1);
    if (path === 'preview') return route.fulfill({ json: { preview_id: preview, action, expires_at: Date.now() / 1000 + 120,
      effect: 'Queue a normal power action. Active work can stop. Current inhibitors and account policy apply.',
      resources: [{ resource_id: 'system-resource', kind: 'system', name: 'system', node_id: 'Selected machine', provider: 'systemd', state: 'running' }] } });
    if (path === 'commit') commits++;
    return route.fulfill({ json: { id: operation, action,
      targets: [{ node_id: 'Selected machine', resource_id: 'system-resource', state: 'accepted' }] } });
  });
  await page.goto(origin);
  await page.evaluate(async preview => {
    const { lifecycleActions } = await import('/ui-lifecycle-actions.js');
    const control = lifecycleActions({ workspace_id: 'c'.repeat(32), instance_id: 'd'.repeat(32) }, 'admin');
    document.querySelector('main').append(...control.controls({ results: [{ data: { preview_id: preview, resources: [] } }] }));
  }, preview);
  await page.getByRole('button', { name: 'Review administration action in FICC', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('Selected machine');
  await expect(dialog).toContainText('Active work can stop');
  expect(commits).toBe(0);
  await dialog.getByRole('button', { name: action === 'reboot' ? 'Restart these systems' : 'Shut down these systems', exact: true }).click();
  await expect(dialog).toContainText('A lost SSH connection does not prove shutdown');
  await dialog.getByRole('button', { name: 'Refresh operation', exact: true }).click();
  await expect(dialog).toContainText('accepted');
  await expect(dialog.getByRole('button', { name: 'Remove operation receipt', exact: true })).toHaveCount(0);
  expect(commits).toBe(1);
});

test('new requests clear old preview controls and earlier replies cannot replace them', async ({ page }) => {
  const reviewed = [];
  await page.route('**/api/v1/module-vms/preview', route => {
    reviewed.push(route.request().postDataJSON().preview_id);
    return route.fulfill({ json: { action: 'start', expires_at: Date.now() / 1000 + 120, vms: [] } });
  });
  await page.goto(origin);
  await page.evaluate(async () => {
    const { renderModule } = await import('/ui-renderer.js');
    const replies = window.replies = {};
    const manifest = { capabilities: ['vm:read'], actions: [{ id: 'first' }, { id: 'second' }],
      ui: { type: 'column', children: [
        { type: 'button', action: 'first', label: 'First preview' }, { type: 'button', action: 'second', label: 'Second preview' },
      ] } };
    const view = renderModule({ id: 'a'.repeat(32), state: {} }, { manifest }, {
      workspaceId: 'b'.repeat(32), saveState: async () => {}, invoke: action => new Promise(resolve => { replies[action] = resolve; }),
    });
    document.querySelector('main').append(view.element);
  });
  const reply = (action, char) => page.evaluate(({ action, char }) => window.replies[action]({ results: [{ data: { preview_id: char.repeat(32), vms: [] } }] }), { action, char });
  await page.getByRole('button', { name: 'First preview', exact: true }).click();
  await reply('first', 'c');
  const review = page.getByRole('button', { name: 'Review VM action in FICC', exact: true });
  await expect(review).toBeVisible();
  await expect(page.locator('.module-result')).toHaveCount(0);
  await page.getByRole('button', { name: 'Second preview', exact: true }).click();
  await expect(review).toHaveCount(0);
  await page.getByRole('button', { name: 'First preview', exact: true }).click();
  await reply('first', 'd');
  await expect(review).toBeVisible();
  await reply('second', 'e');
  await review.click();
  await expect(page.getByRole('dialog')).toContainText('Action: start.');
  expect(reviewed).toEqual(['d'.repeat(32)]);
});

for (const count of [1, 64]) test(`adapter consistency and separate local cleanup acknowledgement N=${count}`, async ({ page }) => {
  const id = 'a'.repeat(32), op = 'b'.repeat(32), profile = 'e'.repeat(32), removals = [];
  const targets = Array.from({ length: count }, (_, index) => ({ node_id: `endpoint-${index}`, name: `VM ${index}`,
    vm_id: `resource-${index}`, profile_id: profile, consistency: 'checked-before-dispatch', state: 'off' }));
  await page.route('**/api/v1/module-vms/*', route => {
    const path = new URL(route.request().url()).pathname.split('/').at(-1), body = route.request().postDataJSON();
    if (path === 'preview') return route.fulfill({ json: { preview_id: id, action: 'start',
      expires_at: Date.now() / 1000 + 120, vms: targets } });
    if (path === 'forget') {
      removals.push(body);
      if (!body.acknowledge_orphans) return route.fulfill({ status: 409, json: { error: {
        code: 'adapter_orphan_ack_required', message: 'The registered system identity changed.' } } });
      return route.fulfill({ json: { removed: true, orphaned_profiles: [profile] } });
    }
    return route.fulfill({ json: { id: op, action: 'start',
      targets: targets.map(target => ({ ...target, state: 'observed', observed_state: 'running' })) } });
  });
  await page.goto(origin);
  await page.evaluate(async id => {
    const { lifecycleActions } = await import('/ui-lifecycle-actions.js');
    const control = lifecycleActions({ workspace_id: 'c'.repeat(32), instance_id: 'd'.repeat(32) }, 'vms');
    document.querySelector('main').append(...control.controls({ results: [{ data: { preview_id: id, vms: [] } }] }));
  }, id);
  await page.getByRole('button', { name: 'Review VM action in FICC', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('Another administrator can change');
  await expect(dialog).toContainText(profile);
  await dialog.getByRole('button', { name: 'Start these VMs', exact: true }).click();
  await dialog.getByRole('checkbox').check();
  await dialog.getByRole('button', { name: 'Remove operation receipt', exact: true }).click();
  await expect(dialog).toContainText('Remote receipt cleanup cannot be verified');
  expect(removals).toHaveLength(1);
  expect(removals[0].acknowledge_orphans).toBeUndefined();
  const local = dialog.getByRole('button', { name: 'Remove local receipt only', exact: true });
  await local.click();
  expect(removals).toHaveLength(1);
  await dialog.getByRole('checkbox', { name: 'Remove the local receipt only.', exact: false }).check();
  if (count === 1) await capture(page, 'adapter-local-receipt-confirmation');
  await local.click();
  await expect(dialog).toContainText('Operation receipt removed');
  expect(removals).toHaveLength(2);
  expect(removals[1].acknowledge_orphans).toBe(true);
});
