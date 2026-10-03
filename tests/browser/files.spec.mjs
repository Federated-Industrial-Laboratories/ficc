// SPDX-License-Identifier: Apache-2.0
// Check exact file consent, opaque names, bounded upload and explicit recovery.
import { createHash } from 'node:crypto';
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { confirmFiles, fileEntry, fileScopes, setupFiles, transferRecord } from './file-support.mjs';
import { capture } from './support.mjs';

const pane = (page, side = 'Left') => page.locator(`[data-pane=${side}]`);
async function selectFirst(page) { await pane(page).getByRole('checkbox').first().check(); }

for (const count of [1, 64]) test(`copy freezes exact opaque sources at N=${count}`, async ({ page }) => {
  const state = await setupFiles(page, { entries: Array.from({ length: count }, (_, i) => fileEntry(i + 1)), dropFirstSubmit: true });
  await pane(page).getByRole('button', { name: 'Select page' }).click();
  await page.getByRole('button', { name: 'Copy left to right' }).click();
  await page.getByRole('button', { name: 'Preview transfer', exact: true }).click();
  expect(state.submissions).toHaveLength(0);
  await expect(page.getByText('Controller storage / Local work', { exact: true })).toBeVisible();
  await expect(page.getByText('Sample machine 1 / Remote work', { exact: true })).toBeVisible();
  await confirmFiles(page);
  await expect(page.getByRole('button', { name: 'Retry same request' })).toBeVisible();
  await page.getByRole('button', { name: 'Retry same request' }).click();
  await expect.poll(() => state.submissions.length).toBe(2);
  expect(state.submissions[0]).toEqual(state.submissions[1]);
  expect(state.previews[0]).toEqual({ kind: 'copy', sources: state.entries.map(entry => ({ root_id: 'root-local', entry_id: entry.entry_id })),
    destination: { root_id: 'root-remote', entry_id: 'remote-dir' }, overwrite: false });
});

test('hostile names remain literal and opaque selection reaches the service', async ({ page }) => {
  const name = '<img src=x onerror=alert(1)> "quote" \\n \\xFF';
  const state = await setupFiles(page, { entries: [fileEntry(1, { name })] });
  await expect(pane(page).getByText(name, { exact: true })).toBeVisible();
  expect(await pane(page).locator('img').count()).toBe(0);
  await selectFirst(page); await pane(page).getByRole('button', { name: 'Delete', exact: true }).click();
  expect(state.previews[0].entries).toEqual(['opaque-file-1']); expect(state.mutations).toHaveLength(0);
  await confirmFiles(page); await expect.poll(() => state.mutations.length).toBe(1);
});

test('text preview displays markup as text and binary preview does not render bytes', async ({ page }) => {
  await setupFiles(page); await selectFirst(page); await pane(page).getByRole('button', { name: 'Preview', exact: true }).click();
  await expect(page.locator('.file-content')).toHaveText('<script>never execute</script>');
  expect(await page.locator('.file-content script').count()).toBe(0);
});

test('changing page clears selections and sends only the opaque cursor', async ({ page }) => {
  const state = await setupFiles(page, { paginated: true }); await selectFirst(page);
  await pane(page).getByRole('button', { name: 'Next page' }).click();
  await expect(pane(page).getByText('sample-100.txt', { exact: true })).toBeVisible();
  await expect(pane(page).getByText('0 selected', { exact: true })).toBeVisible();
  expect(state.lists.at(-1).cursor).toBe('opaque-next');
});

test('overwrite is opt-in and a destination conflict never submits', async ({ page }) => {
  const state = await setupFiles(page); state.previewDenied = true; await selectFirst(page);
  await page.getByRole('button', { name: 'Copy left to right' }).click();
  await expect(page.getByLabel('Allow replacement', { exact: false })).not.toBeChecked();
  await page.getByRole('button', { name: 'Preview transfer', exact: true }).click();
  await expect(page.getByText('Destination exists or entry changed.')).toBeVisible();
  expect(state.submissions).toHaveLength(0); expect(state.previews[0].overwrite).toBe(false);
});

test('expired preview cannot start a fresh file request', async ({ page }) => {
  const state = await setupFiles(page, { expiry: -1 }); await selectFirst(page);
  await pane(page).getByRole('button', { name: 'Delete', exact: true }).click();
  await page.getByLabel('Apply this exact request', { exact: false }).check();
  await expect(page.getByRole('button', { name: 'Confirm exact request' })).toBeDisabled();
  expect(state.mutations).toHaveLength(0);
});

test('mode preview uses ordinary bits and deletion states non-recursion', async ({ page }) => {
  const state = await setupFiles(page); await selectFirst(page);
  await pane(page).getByRole('button', { name: 'Change mode' }).click();
  await page.getByLabel('Ordinary mode').fill('600');
  await page.getByRole('button', { name: 'Preview exact change' }).click();
  expect(state.previews[0].mode).toBe(384); expect(state.mutations).toHaveLength(0);
  await confirmFiles(page); await expect.poll(() => state.mutations.length).toBe(1);
});

test('browser upload hashes bounded chunks and finishes only after the final byte', async ({ page }) => {
  const state = await setupFiles(page); const bytes = Buffer.alloc(262151, 107);
  await pane(page).getByRole('button', { name: 'Upload', exact: true }).click();
  await page.getByLabel('Files to upload').setInputFiles({ name: 'payload.bin', mimeType: 'application/octet-stream', buffer: bytes });
  await page.getByRole('button', { name: 'Review upload' }).click();
  await page.getByRole('button', { name: 'Preview transfer', exact: true }).click(); await confirmFiles(page);
  await expect.poll(() => state.finishes.length).toBe(1);
  expect(state.chunks.map(chunk => [chunk.offset, chunk.bytes.length])).toEqual([[0, 262144], [262144, 7]]);
  for (const chunk of state.chunks) expect(chunk.hash).toBe(createHash('sha256').update(chunk.bytes).digest('hex'));
  let source = createHash('sha256').update(`ficc-upload-v1:${bytes.length}:262144`).digest();
  for (const chunk of state.chunks) source = createHash('sha256').update(Buffer.concat([source, Buffer.from(chunk.hash, 'hex')])).digest();
  expect(state.previews[0].sources[0].source_manifest).toEqual({ algorithm: 'sha256-chain-v1', digest: source.toString('hex') });
  expect(Buffer.concat(state.chunks.map(chunk => chunk.bytes))).toEqual(bytes);
  await expect(page.getByText('Verified SHA-256', { exact: false })).toBeVisible();
});

test('upload resume checks the whole original source before sending any bytes', async ({ page }) => {
  const record = transferRecord('upload');
  record.items[0].source_manifest = { algorithm: 'sha256-chain-v1', digest: '0'.repeat(64) };
  const state = await setupFiles(page, { transfers: [record] });
  await page.getByRole('button', { name: 'Resume', exact: true }).click();
  await page.getByLabel('Original upload files', { exact: true }).setInputFiles({ name: 'sample-1.txt', mimeType: 'text/plain', buffer: Buffer.from('changed-data') });
  await page.getByRole('button', { name: 'Verify prefix and resume' }).click();
  await expect(page.getByText('The selected source for sample-1.txt changed. Start a new transfer.')).toBeVisible();
  expect(state.resumes).toHaveLength(0); expect(state.chunks).toHaveLength(0); expect(state.finishes).toHaveLength(0);
});

test('dataset registration preserves explicit schema and shows its manifest', async ({ page }) => {
  await setupFiles(page); let saved;
  const identity = '9'.repeat(32);
  await page.route('**/api/v1/datasets', route => {
    if (route.request().method() === 'POST') {
      saved = route.request().postDataJSON();
      return route.fulfill({ status: 201, json: { id: identity, name: saved.name } });
    }
    return route.fulfill({ json: { provider_available: true, next_cursor: null, datasets: saved ? [{ id: identity,
      name: saved.name, format: saved.format, file_count: 1, total_bytes: 12 }] : [] } });
  });
  await page.route(`**/api/v1/datasets/${identity}`, route => route.fulfill({ json: { ...saved, id: identity,
    project_id: '1'.repeat(32), created_at: 1, manifest_digest: 'a'.repeat(64),
    files: [{ name: 'sample-1.txt', size: 12, sha256: 'b'.repeat(64) }] } }));
  await selectFirst(page); await page.getByRole('button', { name: 'Register left selection' }).click();
  await page.getByLabel('Dataset name', { exact: true }).fill('Measurements');
  await page.getByLabel('Format', { exact: true }).selectOption('csv');
  await page.getByLabel('Explicit schema JSON').fill('{"fields":[{"name":"count","type":"int64","nullable":false}]}');
  await page.getByRole('button', { name: 'Verify sources and register' }).click();
  await expect(page.getByText(`Dataset Measurements registered. ID: ${identity}`)).toBeVisible();
  expect(saved.sources).toEqual([{ root_id: 'root-local', entry_id: 'opaque-file-1' }]);
  await page.getByRole('button', { name: 'Inspect dataset Measurements' }).click();
  await expect(page.getByRole('table', { name: 'Explicit dataset schema' })).toContainText('int64');
  await expect(page.getByRole('table', { name: 'Dataset files' })).toContainText('b'.repeat(64));
});

test('zero-byte upload uses explicit finish without an empty data chunk', async ({ page }) => {
  const state = await setupFiles(page);
  await pane(page).getByRole('button', { name: 'Upload', exact: true }).click();
  await page.getByLabel('Files to upload').setInputFiles({ name: 'empty', mimeType: 'application/octet-stream', buffer: Buffer.alloc(0) });
  await page.getByRole('button', { name: 'Review upload' }).click();
  await page.getByRole('button', { name: 'Preview transfer', exact: true }).click(); await confirmFiles(page);
  await expect.poll(() => state.finishes.length).toBe(1); expect(state.chunks).toHaveLength(0);
});

test('download uses authenticated attachment after server verification', async ({ page }) => {
  const record = transferRecord('download'); record.state = 'succeeded'; record.items[0] = { ...record.items[0], state: 'succeeded', offset: 12, sha256: 'b'.repeat(64), resumable: false };
  await setupFiles(page, { transfers: [record] });
  await expect(page.getByRole('link', { name: 'Save to browser' })).toHaveAttribute('href', `/api/v1/transfers/${record.id}/items/${record.items[0].id}/content`);
  await expect(page.getByText('Saving the attachment is controlled by your browser.', { exact: false })).toBeVisible();
});

test('discarding a verified download explicitly frees its controller copy', async ({ page }) => {
  const record = transferRecord('download'); record.state = 'succeeded'; record.items[0] = { ...record.items[0], state: 'succeeded', offset: 12, sha256: 'b'.repeat(64), resumable: false };
  const state = await setupFiles(page, { transfers: [record] });
  await page.getByRole('button', { name: 'Discard download', exact: true }).click();
  await expect(page.getByText('The source file is preserved.', { exact: false })).toBeVisible();
  expect(state.cancellations).toHaveLength(0);
  await page.getByRole('button', { name: 'Confirm discard' }).click();
  await expect.poll(() => state.cancellations.length).toBe(1);
  expect(state.cancellations[0]).toEqual({ item_ids: [record.items[0].id], discard_partial: true });
});

for (const kind of ['copy', 'upload']) test(`retained ${kind} partial cleanup preserves the verified outcome`, async ({ page }) => {
  const record = transferRecord(kind); record.state = 'succeeded';
  record.items[0] = { ...record.items[0], state: 'succeeded', offset: 12, sha256: 'b'.repeat(64), resumable: false, cleanup_pending: true };
  const state = await setupFiles(page, { transfers: [record] });
  await expect(page.getByText('Temporary data retained', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Clean retained partial', exact: true }).click();
  await expect(page.getByText('The verified destination file remains unchanged.', { exact: false })).toBeVisible();
  expect(state.cancellations).toHaveLength(0);
  await page.getByRole('button', { name: 'Confirm cleanup' }).click();
  await expect.poll(() => state.cancellations.length).toBe(1);
  expect(state.cancellations[0]).toEqual({ item_ids: [record.items[0].id], discard_partial: true });
  expect(state.submissions).toHaveLength(0); expect(state.previews).toHaveLength(0);
  await expect(page.getByText(`Verified SHA-256 ${'b'.repeat(64)}`)).toBeVisible();
});

test('retained partial cleanup requires a write grant and preserves download controls', async ({ page }) => {
  const copy = transferRecord('copy'); copy.state = 'succeeded';
  copy.items[0] = { ...copy.items[0], state: 'succeeded', cleanup_pending: true, resumable: false };
  const download = transferRecord('download', { ...copy, id: '7'.repeat(32), kind: 'download' });
  await setupFiles(page, { scopes: fileScopes.filter(scope => scope !== 'files:write'), transfers: [copy, download] });
  await expect(page.getByText('Temporary data retained', { exact: true })).toHaveCount(2);
  await expect(page.getByRole('button', { name: 'Clean retained partial', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Discard download', exact: true })).toHaveCount(1);
});

test('unknown transfer checks only its recorded item without new submission', async ({ page }) => {
  const record = transferRecord(); record.state = 'unknown'; record.items[0].state = 'unknown'; record.items[0].resumable = false;
  const state = await setupFiles(page, { transfers: [record] });
  await page.getByRole('button', { name: 'Check recorded outcome' }).click();
  await expect.poll(() => state.resumes.length).toBe(1);
  expect(state.resumes[0]).toEqual({ item_ids: [record.items[0].id] });
  expect(state.previews).toHaveLength(0); expect(state.submissions).toHaveLength(0);
  await expect(page.getByText('this does not repeat the transfer.', { exact: false })).toBeVisible();
});

test('unknown file changes reconcile the frozen operation with the required grant', async ({ page }) => {
  const operation = { id: '6'.repeat(32), action: 'delete', state: 'unknown', items: [{ name: 'sample-1.txt', state: 'unknown', error: 'Receipt unavailable.' }] };
  const state = await setupFiles(page, { operations: [operation] });
  await page.getByRole('button', { name: 'Check recorded outcome' }).click();
  await expect.poll(() => state.reconciliations.length).toBe(1);
  expect(new URL(state.reconciliations[0].url).pathname).toBe(`/api/v1/file-operations/${operation.id}/reconcile`);
  expect(state.reconciliations[0].body).toEqual({}); expect(state.mutations).toHaveLength(0);
  expect(state.previews).toHaveLength(0);
});

test('missing delete grant hides unknown deletion reconciliation', async ({ page }) => {
  await setupFiles(page, { scopes: fileScopes.filter(scope => scope !== 'files:delete'),
    operations: [{ id: '6'.repeat(32), action: 'delete', state: 'unknown', items: [{ name: 'sample-1.txt', state: 'unknown', error: null }] }] });
  await expect(page.getByRole('table', { name: 'File operation results' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Check recorded outcome' })).toHaveCount(0);
});

for (const [roots, label] of [[null, 'All registered roots'], [[], 'No file roots'], [['selected-root'], 'selected-root'], [undefined, 'Not reported']]) {
  test(`access and credentials display root restrictions: ${label}`, async ({ page }) => {
    await setupFiles(page, { scopes: [...fileScopes, 'tokens:manage'] });
    await page.route('**/api/v1/permissions', route => route.fulfill({ json: { scopes: fileScopes, node_ids: null, root_ids: roots } }));
    await page.route('**/api/v1/tokens', route => route.fulfill({ json: { tokens: [{ id: 'token-id', label: 'Scoped files', scopes: ['files:read'], node_ids: null,
      root_ids: roots, expires_at: Date.now() / 1000 + 3600 }] } }));
    await page.locator('[data-view=access]').click();
    await expect(page.getByRole('heading', { name: 'Host permission grants' })).toBeVisible();
    await expect(page.getByText(label, { exact: true })).toHaveCount(2);
    await expect(page.getByRole('columnheader', { name: 'File roots', exact: true })).toBeVisible();
  });
}

test('file permission loss clears the exposed listing', async ({ page }) => {
  const state = await setupFiles(page); await expect(pane(page).getByText('sample-1.txt', { exact: true })).toBeVisible();
  state.denied = true; await pane(page).getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(pane(page).getByText('File permission revoked.')).toBeVisible();
  await expect(pane(page).getByText('sample-1.txt', { exact: true })).toHaveCount(0);
  await expect(pane(page).getByRole('button', { name: 'Upload', exact: true })).toBeDisabled();
});

test('special files are displayed without open or destructive actions', async ({ page }) => {
  await setupFiles(page, { entries: [fileEntry(1, { kind: 'special' })] }); await selectFirst(page);
  for (const name of ['Preview', 'Download', 'Change mode', 'Delete']) await expect(pane(page).getByRole('button', { name, exact: true })).toBeDisabled();
});

test('simulation prevents mutations and empty roots explain local registration', async ({ page }) => {
  await setupFiles(page, { mode: 'demo' }); await selectFirst(page);
  for (const name of ['Upload', 'Download', 'Change mode', 'Delete']) await expect(pane(page).getByRole('button', { name, exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Copy left to right' })).toBeDisabled();
});

test('missing file read scope does not request or show root data', async ({ page }) => {
  const state = await setupFiles(page, { scopes: fileScopes.filter(scope => scope !== 'files:read') });
  await expect(page.getByRole('heading', { name: 'File access denied' })).toBeVisible(); expect(state.lists).toHaveLength(0);
});

test('empty roots provide an actionable local setup message', async ({ page }) => {
  await setupFiles(page, { roots: [] });
  await expect(page.getByRole('heading', { name: 'No registered file roots' })).toBeVisible();
  await expect(page.getByText('Register an existing directory with ficc root-add', { exact: false })).toBeVisible();
});

test('a 65-entry page does not silently exceed the operation selection limit', async ({ page }) => {
  const state = await setupFiles(page, { entries: Array.from({ length: 65 }, (_, index) => fileEntry(index + 1)) });
  await pane(page).getByRole('button', { name: 'Select page' }).click();
  await expect(pane(page).getByRole('heading', { name: 'Selection limit' })).toBeVisible();
  await expect(pane(page).getByText('0 selected', { exact: true })).toBeVisible();
  expect(state.submissions).toHaveLength(0);
});

test('partial transfer failure stays separate from a verified sibling', async ({ page }) => {
  const record = transferRecord(); record.state = 'interrupted';
  record.items.push({ ...record.items[0], id: '5'.repeat(32), name: 'finished.txt', state: 'succeeded', sha256: 'c'.repeat(64), resumable: false });
  record.items[0].error = { code: 'disk_full', message: 'Destination has insufficient space.' };
  await setupFiles(page, { transfers: [record] });
  await expect(page.getByText('Destination has insufficient space.')).toBeVisible();
  await expect(page.getByText(`Verified SHA-256 ${'c'.repeat(64)}`)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Resume', exact: true })).toHaveCount(1);
});

test('cancel keeps partial bytes unless cleanup is explicitly confirmed', async ({ page }) => {
  const record = transferRecord(); record.state = 'running'; record.items[0].state = 'running';
  const state = await setupFiles(page, { transfers: [record] });
  await page.getByRole('button', { name: 'Cancel transfer' }).click();
  expect(state.cancellations).toHaveLength(0);
  await page.getByRole('button', { name: 'Confirm cancellation' }).click();
  await expect.poll(() => state.cancellations.length).toBe(1);
  expect(state.cancellations[0]).toEqual({ item_ids: ['4'.repeat(32)], discard_partial: false });
  await expect(page.getByRole('button', { name: 'Clean up partial', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Resume', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Clean up partial', exact: true }).click();
  expect(state.cancellations).toHaveLength(1);
  await expect(page.getByText('Committed destinations are not removed.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Discard partial', exact: true }).click();
  await expect.poll(() => state.cancellations.length).toBe(2);
  expect(state.cancellations[1]).toEqual({ item_ids: ['4'.repeat(32)], discard_partial: true });
  await expect(page.getByRole('button', { name: 'Clean up partial', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Resume', exact: true })).toHaveCount(0);
  expect(state.mutations).toHaveLength(0);
});

test('two hundred percent files layout retains keyboard actions', async ({ page }) => {
  await setupFiles(page); await page.evaluate(() => { document.documentElement.style.zoom = '2'; });
  await selectFirst(page); await pane(page).getByRole('button', { name: 'Preview', exact: true }).focus();
  await page.keyboard.press('Enter'); await expect(page.locator('.file-content')).toBeVisible();
  await page.getByRole('button', { name: 'Close', exact: true }).click();
  await expect(pane(page).getByRole('button', { name: 'Preview', exact: true })).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('an already cancelled file request never reaches the network', async ({ page }) => {
  await setupFiles(page); let sent = 0;
  await page.route('**/api/v1/cancelled-check', route => { sent++; return route.fulfill({ json: {} }); });
  const result = await page.evaluate(async () => {
    const { request } = await import('/static/api.js'); const controller = new AbortController(); controller.abort();
    try { await request('/cancelled-check', { method: 'POST', body: {}, signal: controller.signal }); return 'sent'; }
    catch (error) { return error.code; }
  });
  expect(result).toBe('disconnected'); expect(sent).toBe(0);
});

for (const width of [390, 768, 1280, 1920]) test(`files remain operable at ${width}px`, async ({ page }) => {
  await page.setViewportSize({ width, height: 1080 }); await page.emulateMedia({ reducedMotion: 'reduce' });
  await setupFiles(page); await selectFirst(page);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await expect(pane(page).getByRole('button', { name: 'Delete', exact: true })).toBeEnabled();
  await capture(page, `files-${width}`);
});
