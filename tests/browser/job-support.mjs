// SPDX-License-Identifier: Apache-2.0
// Supply typed synthetic job responses for browser contract checks.
import { expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { node, origin } from './support.mjs';

export const jobScopes = ['nodes:read', 'nodes:write', 'resources:read', 'jobs:read', 'jobs:execute', 'jobs:cancel', 'jobs:logs'];
export function jobNode(index = 1, changes = {}) {
  return node(index, { capabilities: { resources: true, jobs: true, logout_persistent: false }, ...changes });
}
export function operation(nodes = [jobNode()], changes = {}) {
  return {
    id: '1'.repeat(32), action: 'job.submit', actor: 'fixture-actor', created_at: Date.now() / 1000,
    updated_at: Date.now() / 1000, request: { action: 'job.submit', node_ids: nodes.map(node => node.id),
      job: { label: 'Example job', argv: ['/bin/echo', 'hello'], cwd: '', env: {},
        limits: { cpu_percent: 100, memory_high_bytes: 201326592, memory_max_bytes: 268435456,
          memory_swap_max_bytes: 0, tasks_max: 32, runtime_seconds: 300 },
        allow_session_lifetime: true, gpu_reservations: {} } },
    targets: nodes.map(node => ({ node_id: node.id, name: node.name, job_id: `job-${node.id}`, state: 'running', error: null,
      result: null, requested_limits: { cpu_percent: 100, memory_max_bytes: 268435456 },
      effective_limits: { cpu_percent: 50, memory_max_bytes: 268435456 }, reservations: [], session_lifetime: true })), ...changes,
  };
}
export async function setupJobs(page, options = {}) {
  const nodes = options.nodes ?? [jobNode()];
  const state = { operations: options.operations ?? [], available: true, denied: false, previews: [], submissions: [],
    cancellations: [], logCalls: [], ...options };
  await page.route('**/api/v1/session', route => route.fulfill({ json: {
    csrf: 'synthetic-csrf', mode: options.mode ?? 'live', version: 'fixture',
    principal: { id: 'fixture-actor', label: 'Synthetic operator', scopes: options.scopes ?? jobScopes, node_ids: null },
  } }));
  await page.route('**/api/v1/nodes', route => route.fulfill({ json: { nodes } }));
  await page.route('**/api/v1/operation-previews', route => {
    const body = route.request().postDataJSON(); state.previews.push(body);
    return route.fulfill({ json: { preview_id: '2'.repeat(32), expires_at: Date.now() / 1000 + (options.expiry ?? 120), request: body,
      targets: nodes.filter(node => body.node_ids.includes(node.id)).map(node => ({ node_id: node.id, name: node.name,
        ready: options.ready ?? true, errors: options.ready === false ? ['Required control unavailable.'] : [], warnings: [] })), warnings: [] } });
  });
  await page.route('**/api/v1/operations', route => {
    if (route.request().method() === 'POST') {
      state.submissions.push({ body: route.request().postDataJSON(), key: route.request().headers()['idempotency-key'] });
      if (options.dropFirstSubmit && state.submissions.length === 1) return route.abort('connectionfailed');
      const value = operation(nodes.filter(node => state.previews.at(-1).node_ids.includes(node.id)), { request: state.previews.at(-1) });
      state.operations = [value];
      return route.fulfill({ status: 202, json: value });
    }
    if (state.denied) return route.fulfill({ status: 403, json: { error: { code: 'denied', message: 'Job permission revoked.' } } });
    if (!state.available) return route.abort('connectionfailed');
    return route.fulfill({ json: { operations: state.operations } });
  });
  await page.route('**/api/v1/operations/*/cancel', route => {
    const body = route.request().postDataJSON(); state.cancellations.push(body);
    state.operations[0].targets = state.operations[0].targets.map(target => body.node_ids.includes(target.node_id) ?
      { ...target, state: 'cancel_requested' } : target);
    return route.fulfill({ status: 202, json: state.operations[0] });
  });
  await page.route('**/api/v1/operations/*/logs/**', route => {
    const url = new URL(route.request().url()); state.logCalls.push(url);
    if (state.logDenied) return route.fulfill({ status: 403, json: { error: { code: 'denied', message: 'Output grant required.' } } });
    if (state.logUnavailable) return route.fulfill({ status: 503, json: { error: { code: 'unreachable', message: 'Remote output is temporarily unavailable.' } } });
    const stream = url.searchParams.get('stream'), offset = Number(url.searchParams.get('offset'));
    const all = Buffer.from(stream === 'stderr' ? options.stderr ?? 'Error stream sample\n' : options.stdout ?? 'Hello from FICC\n');
    const chunk = all.subarray(offset, offset + Number(url.searchParams.get('limit')));
    return route.fulfill({ json: { data_base64: chunk.toString('base64'), next_offset: offset + chunk.length,
      total_bytes: all.length, dropped_bytes: options.dropped ?? 0, complete: true } });
  });
  await page.goto(origin);
  await expect(page.getByRole('heading', { name: 'Cluster overview', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Jobs', exact: false }).click();
  await expect(page.getByRole('heading', { name: 'Managed jobs', exact: true })).toBeVisible();
  return state;
}
export async function previewJob(page, label = 'Browser job') {
  await page.getByRole('button', { name: 'New job', exact: true }).click();
  await page.getByRole('button', { name: 'Select all machines', exact: true }).click();
  await page.getByLabel('Job label / purpose', { exact: true }).fill(label);
  await page.getByLabel('Allow a job that depends', { exact: false }).check();
  await page.getByRole('button', { name: 'Preview job', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Confirm frozen targets', exact: true })).toBeVisible();
}
