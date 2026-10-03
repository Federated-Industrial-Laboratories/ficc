// SPDX-License-Identifier: Apache-2.0
// Explicit multipart progress and recovery bound to one immutable dataset.
import { request } from './api.js';
import { button, confirmation, details, el, errorPanel, notice, table } from './components.js';
import { fileDialog } from './file-dialog.js';
import { field, text } from './source-forms.js';

export function beginObjectUpload(connection, received) {
  const view = fileDialog('Upload dataset object'), status = el('div');
  const dataset = text('object-dataset', '', { required: true, pattern: '[a-f0-9]{32}' });
  const index = text('object-file', '0', { type: 'number', min: 0, max: 127, required: true });
  const key = text('object-key', connection.configuration.prefix, { required: true, maxlength: 1024 });
  const submit = el('button', { type: 'submit', class: 'primary' }, 'Begin verified upload');
  const requestKey = crypto.randomUUID();
  view.content.append(notice('The upload binds a complete verified dataset file. Changed sources cannot resume. The destination key must be new.'),
    el('form', { onsubmit: async event => {
      event.preventDefault(); if (view.busy()) return;
      try {
        view.working(true); submit.disabled = true;
        const result = await request(`/sources/${connection.id}/uploads`, { method: 'POST', idempotencyKey: requestKey, timeout: null,
          body: { dataset_id: dataset.value, file_index: Number(index.value), key: key.value } });
        view.dialog.close(); received(result); objectUpload(result.id, received);
      } catch (error) { status.replaceChildren(errorPanel(error)); }
      finally { view.working(false); submit.disabled = false; }
    } }, ...field('Dataset ID', dataset), ...field('File index (zero based)', index), ...field('Object key', key), status, submit));
}

export async function objectUpload(identity, received) {
  const view = fileDialog('Dataset object upload'), summary = el('div'), status = el('div'), retained = el('div');
  let upload, busy = false, pause = false;
  const part = text('object-part', '1', { type: 'number', min: 1, max: 10000 });
  async function load() {
    upload = await request(`/source-uploads/${identity}`);
    if (!view.active()) return;
    summary.replaceChildren(details([['Object key', upload.key], ['State', upload.state], ['Dataset', upload.dataset_id],
      ['Manifest SHA-256', upload.manifest_digest], ['File SHA-256', upload.sha256], ['File bytes', String(upload.size)],
      ['Part bytes', String(upload.part_bytes ?? 'Pending')], ['Parts', String(upload.parts ?? 'Pending')]]));
  }
  async function wait(identity) {
    while (view.active()) {
      const result = await request(`/source-runs/${identity}`);
      if (['completed', 'failed', 'cancelled', 'unknown'].includes(result.state)) {
        if (result.state !== 'completed') throw new Error(result.error?.message ?? 'The operation is unknown. Check retained parts or reconcile publication.');
        return result.receipt;
      }
      await new Promise(resolve => setTimeout(resolve, 800));
    }
    throw new Error('The upload remains recorded. Open it again to check its outcome.');
  }
  async function operation(body) {
    const result = await request(`/source-uploads/${identity}/operations`, { method: 'POST', body, idempotencyKey: crypto.randomUUID() });
    const receipt = await wait(result.id);
    await load(); received(); return receipt;
  }
  async function act(body) {
    if (busy) return; busy = true;
    try { const receipt = await operation(body); status.replaceChildren(notice(`Recorded outcome: ${receipt.outcome}`)); }
    catch (error) { status.replaceChildren(errorPanel(error)); }
    finally { busy = false; }
  }
  async function parts() {
    let cursor = 0;
    const present = new Set();
    do {
      const receipt = await operation({ operation: 'status', cursor });
      receipt.parts.filter(item => item.verified).forEach(item => present.add(item.part_number));
      retained.replaceChildren(table(['Part', 'Bytes', 'Verification'], receipt.parts.map(item => el('tr', {}, el('td', {}, item.part_number),
        el('td', {}, String(item.size)), el('td', { class: 'wrap' }, item.verified ? item.checksum_sha256 : 'No matching acknowledged receipt. Upload this part again.'))), 'Retained upload parts'));
      cursor = receipt.next_cursor;
    } while (cursor && view.active());
    return present;
  }
  const remaining = button('Upload remaining parts', async () => {
    if (busy) return; busy = true; pause = false;
    try {
      const present = await parts();
      for (let number = 1; number <= upload.parts && view.active() && !pause; number++) {
        if (present.has(number)) continue;
        status.replaceChildren(notice(`Uploading part ${number} of ${upload.parts}. Closing this view pauses after the admitted part.`));
        await operation({ operation: 'part', part_number: number });
      }
      status.replaceChildren(notice(pause ? 'Paused. Retained parts remain available.' : 'Parts uploaded. Complete the upload to verify the full source and publish the object.'));
    } catch (error) { status.replaceChildren(errorPanel(error)); }
    finally { busy = false; }
  });
  view.content.append(summary, status, notice('Recovery checks do not repeat completion. Multipart ETags are not content hashes; FICC checks explicit SHA256 receipts.'),
    el('div', { class: 'actions' }, button('Refresh upload', () => load().catch(error => status.replaceChildren(errorPanel(error)))),
      button('Check retained parts', async () => { if (busy) return; busy = true; try { await parts(); } catch (error) { status.replaceChildren(errorPanel(error)); } finally { busy = false; } }),
      remaining, button('Pause after current part', () => { pause = true; }),
      button('Verify and complete', () => act({ operation: 'complete' })), button('Reconcile publication', () => act({ operation: 'reconcile' })),
      button('Abort upload', () => confirmation('Abort retained object upload?', 'Uploaded parts are removed by the object provider.', 'Abort', () => act({ operation: 'abort' })), { class: 'danger' })),
    ...field('Specific part number', part), button('Upload this part', () => act({ operation: 'part', part_number: Number(part.value) })), retained);
  try { await load(); if (upload.state === 'creating' && upload.last_run_id) { await wait(upload.last_run_id); await load(); } }
  catch (error) { status.replaceChildren(errorPanel(error)); }
}
