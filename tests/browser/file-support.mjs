// SPDX-License-Identifier: Apache-2.0
// Supply opaque file identities and durable transfer outcomes for browser checks.
import { expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { node, origin } from './support.mjs';

export const fileScopes = ['nodes:read', 'resources:read', 'files:read', 'files:write', 'files:mode', 'files:delete'];
export function fileEntry(index = 1, extra = {}) {
  return { entry_id: `opaque-file-${index}`, name: `sample-${index}.txt`, kind: 'file', size: 12,
    modified_ns: Date.now() * 1000000, uid: 1000, gid: 1000, mode: 420, revision: `revision-${index}`, ...extra };
}
export function transferRecord(kind = 'copy', extra = {}) {
  return { id: '3'.repeat(32), kind, state: 'interrupted', items: [{ id: '4'.repeat(32), name: 'sample-1.txt', size: 12,
    offset: 4, state: 'interrupted', sha256: null, error: null, resumable: true }], created_at: Date.now() / 1000, updated_at: Date.now() / 1000, ...extra };
}
export async function setupFiles(page, options = {}) {
  const roots = options.roots ?? [{ id: 'root-local', node_id: null, label: 'Local work', entry_id: 'local-dir', revision: 'r1', actions: ['read', 'write', 'mode', 'delete'], available: true, error: null },
    { id: 'root-remote', node_id: 'sample-1', label: 'Remote work', entry_id: 'remote-dir', revision: 'r2', actions: ['read', 'write', 'mode', 'delete'], available: true, error: null }];
  const state = { entries: options.entries ?? [fileEntry()], previews: [], submissions: [], transfers: options.transfers ?? [],
    operations: options.operations ?? [], mutations: [], reconciliations: [], lists: [], chunks: [], finishes: [], resumes: [], cancellations: [], denied: false, previewDenied: false };
  await page.route('**/api/v1/session', route => route.fulfill({ json: { csrf: 'test-csrf', mode: options.mode ?? 'live', version: 'fixture',
    principal: { id: 'test', label: 'Test operator', scopes: options.scopes ?? fileScopes, node_ids: null, root_ids: null } } }));
  await page.route('**/api/v1/nodes', route => route.fulfill({ json: { nodes: [node()] } }));
  await page.route('**/api/v1/file-roots', route => route.fulfill({ json: { roots } }));
  await page.route('**/api/v1/files/list', route => {
    const body = route.request().postDataJSON(); state.lists.push(body);
    if (state.denied) return route.fulfill({ status: 403, json: { error: { code: 'denied', message: 'File permission revoked.' } } });
    return route.fulfill({ json: { root_id: body.root_id, entry_id: body.entry_id, breadcrumbs: [{ entry_id: body.entry_id, name: 'Root' }],
      entries: body.cursor ? [fileEntry(100)] : state.entries, next_cursor: options.paginated && !body.cursor ? 'opaque-next' : null } });
  });
  await page.route('**/api/v1/files/preview', route => route.fulfill({ json: { entry_id: state.entries[0].entry_id, revision: 'r1',
    data_base64: Buffer.from(options.content ?? '<script>never execute</script>').toString('base64'), bytes: 30, truncated: false, encoding: options.encoding ?? 'utf-8' } }));
  for (const kind of ['file-operation', 'transfer']) await page.route(`**/api/v1/${kind}-previews`, route => {
    const body = route.request().postDataJSON(); state.previews.push(body);
    if (state.previewDenied) return route.fulfill({ status: 409, json: { error: { code: 'conflict', message: 'Destination exists or entry changed.' } } });
    return route.fulfill({ json: { preview_id: 'preview-one', expires_at: Date.now() / 1000 + (options.expiry ?? 120), request_digest: 'digest',
      action: body.action, kind: body.kind, root_id: body.root_id, entries: state.entries, effects: ['Apply exact entries'], count: body.entries?.length,
      items: (body.sources ?? []).map((source, index) => ({ ...source, name: source.name ?? state.entries[index]?.name, size: source.size ?? 12 })),
      total_bytes: 12, conflicts: body.overwrite ? [{ name: 'sample-1.txt', exists: true }] : [], relay: options.relay ?? false } });
  });
  await page.route('**/api/v1/file-operations', route => {
    if (route.request().method() === 'POST') {
      state.mutations.push(route.request().postDataJSON());
      const result = { id: 'op1', state: 'succeeded', action: state.previews.at(-1).action, items: [{ id: 'one', entry_id: state.entries[0].entry_id, state: 'succeeded', result: {}, error: null }] };
      state.operations.push(result); return route.fulfill({ json: result });
    }
    return route.fulfill({ json: { operations: state.operations } });
  });
  await page.route('**/api/v1/file-operations/*/reconcile', route => {
    state.reconciliations.push({ url: route.request().url(), body: route.request().postDataJSON() });
    return route.fulfill({ json: state.operations[0] });
  });
  await page.route('**/api/v1/transfers', route => {
    if (route.request().method() === 'POST') {
      state.submissions.push({ body: route.request().postDataJSON(), key: route.request().headers()['idempotency-key'] });
      if (options.dropFirstSubmit && state.submissions.length === 1) return route.abort('connectionfailed');
      const prior = state.previews.at(-1);
      const record = transferRecord(prior.kind, { state: 'running', items: prior.sources.map((source, index) => ({ id: String(index + 1).padStart(32, '0'),
        name: source.name ?? state.entries[index]?.name, size: source.size ?? 12, offset: 0, state: 'running', sha256: null, error: null, resumable: prior.kind === 'upload' })) });
      state.transfers = [record]; return route.fulfill({ status: 202, json: record });
    }
    return route.fulfill({ json: { transfers: state.transfers } });
  });
  await page.route('**/api/v1/transfers/*/items/*/chunks?*', async route => {
    const offset = Number(new URL(route.request().url()).searchParams.get('offset'));
    const bytes = route.request().postDataBuffer(); state.chunks.push({ offset, bytes, hash: route.request().headers()['x-chunk-sha256'] });
    if (options.badPrefix && offset === 0) return route.fulfill({ status: 409, json: { error: { code: 'chunk_conflict', message: 'Accepted prefix does not match.' } } });
    return route.fulfill({ json: { offset: offset + bytes.length, sha256: state.chunks.at(-1).hash, state: 'running' } });
  });
  await page.route('**/api/v1/transfers/*/items/*/finish', route => {
    state.finishes.push(route.request().url()); state.transfers[0].state = 'succeeded';
    state.transfers[0].items = state.transfers[0].items.map(item => ({ ...item, state: 'succeeded', offset: item.size, resumable: false, sha256: 'a'.repeat(64) }));
    return route.fulfill({ json: state.transfers[0] });
  });
  await page.route('**/api/v1/transfers/*/resume', route => { state.resumes.push(route.request().postDataJSON()); return route.fulfill({ json: state.transfers[0] }); });
  await page.route('**/api/v1/transfers/*/cancel', route => {
    const body = route.request().postDataJSON(); state.cancellations.push(body);
    const record = state.transfers[0];
    for (const item of record.items.filter(item => body.item_ids.includes(item.id))) {
      if (item.state === 'succeeded') {
        item.cleanup_pending = false;
        if (record.kind === 'download' && body.discard_partial) item.state = 'cancelled';
      } else if (item.state !== 'unknown') {
        item.state = body.discard_partial ? 'cancelled' : 'interrupted';
        item.resumable = !body.discard_partial;
      }
    }
    record.state = record.items.every(item => item.state === 'cancelled') ? 'cancelled' : record.items[0].state;
    return route.fulfill({ json: record });
  });
  await page.goto(origin); await page.locator('[data-view=files]').click();
  await expect(page.getByRole('heading', { name: 'Files', exact: true })).toBeVisible();
  return state;
}
export async function confirmFiles(page) {
  await expect(page.getByRole('heading', { name: 'Confirm frozen file request' })).toBeVisible();
  await page.getByLabel('Apply this exact request', { exact: false }).check();
  await page.getByRole('button', { name: 'Confirm exact request' }).click();
}
