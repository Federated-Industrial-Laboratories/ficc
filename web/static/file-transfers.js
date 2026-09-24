// SPDX-License-Identifier: Apache-2.0
// Present verified transfer outcomes and explicit recovery without automatic replay.
import { allowed, request } from './api.js';
import { button, bytes, confirmation, el, errorPanel, notice, panel, state, table } from './components.js';
import { uploadSender } from './file-uploads.js';

export function fileTransfers(demo, changed) {
  let active = true, loading = false, timer, records = [];
  const status = el('div'), content = el('div');
  const element = el('section', { class: 'file-transfers' }, status, content);
  const uploads = uploadSender(load, error => status.replaceChildren(errorPanel(error), notice('Upload stopped. Resume requires the original files and prefix verification.', 'warning')));
  function received(record, files) {
    if (!active) return;
    records = [record, ...records.filter(item => item.id !== record.id)]; draw();
    if (files) uploads.send(record, files);
    load();
  }
  function draw() {
    const focus = element.contains(document.activeElement) ? document.activeElement.dataset.focus : null;
    if (!records.length) { content.replaceChildren(state('No transfers', 'Copy, upload or download files to see verified progress and recovery actions.')); return; }
    const rows = records.flatMap(transfer => transfer.items.map(item => {
      const controls = [], done = ['succeeded', 'cancelled', 'failed'].includes(item.state);
      const write = allowed(transfer.kind === 'download' ? 'files:read' : 'files:write');
      if (!demo && write && item.resumable && !uploads.busy(transfer.id)) controls.push(button('Resume', async () => {
        if (transfer.kind === 'upload') uploads.resume({ ...transfer, items: [item] });
        else {
          try { await request(`/transfers/${transfer.id}/resume`, { method: 'POST', body: { item_ids: [item.id] } }); load(); }
          catch (error) { if (active) status.replaceChildren(errorPanel(error)); }
        }
      }, { 'data-focus': `resume-${item.id}` }));
      if (!demo && write && item.state === 'unknown') controls.push(button('Check recorded outcome', async () => {
        try {
          await request(`/transfers/${transfer.id}/resume`, { method: 'POST', body: { item_ids: [item.id] } });
          status.replaceChildren(notice('Recorded outcome checked. An unresolved result remains unknown; this does not repeat the transfer.')); load();
        } catch (error) { if (active) status.replaceChildren(errorPanel(error), notice('The outcome is still unresolved. Do not create a replacement transfer until it is known.', 'warning')); }
      }, { 'data-focus': `reconcile-${item.id}` }));
      const cleanup = ['interrupted', 'failed'].includes(item.state);
      if (!demo && write && item.state !== 'unknown' && (!done || cleanup)) controls.push(button(cleanup ? 'Clean up partial' : 'Cancel transfer', () => confirmation('Cancel file transfer',
        `Cancel ${item.name} and ${cleanup ? 'discard its retained partial bytes' : 'retain any partial bytes for explicit recovery'}? Committed destinations are not removed.`,
        cleanup ? 'Discard partial' : 'Confirm cancellation', async () => {
          uploads.cancel(transfer.id);
          await request(`/transfers/${transfer.id}/cancel`, { method: 'POST', body: { item_ids: [item.id], discard_partial: cleanup } });
          await load();
        }), { class: 'danger', 'data-focus': `cancel-${item.id}` }));
      if (!demo && write && transfer.kind !== 'download' && item.state === 'succeeded' && item.cleanup_pending) controls.push(button('Clean retained partial', () => confirmation('Clean retained transfer data',
        `Remove retained temporary data for ${item.name}? The verified destination file remains unchanged.`, 'Confirm cleanup', async () => {
          await request(`/transfers/${transfer.id}/cancel`, { method: 'POST', body: { item_ids: [item.id], discard_partial: true } });
          await load();
        }), { class: 'danger', 'data-focus': `cleanup-${item.id}` }));
      if (!demo && transfer.kind === 'download' && item.state === 'succeeded' && allowed('files:read')) controls.push(el('a', {
        href: `/api/v1/transfers/${encodeURIComponent(transfer.id)}/items/${encodeURIComponent(item.id)}/content`,
        class: 'button-link', download: '', 'data-focus': `save-${item.id}` }, 'Save to browser'));
      if (!demo && transfer.kind === 'download' && item.state === 'succeeded' && allowed('files:read')) controls.push(button('Discard download', () => confirmation('Discard prepared download',
        `Remove the verified controller copy of ${item.name}? The source file is preserved. Prepare a new download if you need it again.`, 'Confirm discard', async () => {
          await request(`/transfers/${transfer.id}/cancel`, { method: 'POST', body: { item_ids: [item.id], discard_partial: true } });
          await load();
        }), { class: 'danger', 'data-focus': `discard-${item.id}` }));
      return el('tr', {}, el('td', {}, item.name), el('td', {}, transfer.kind), el('td', {}, item.state),
        el('td', {}, `${bytes(item.offset)} / ${bytes(item.size)}`),
        el('td', { class: 'wrap transfer-hash' }, item.sha256 && item.state === 'succeeded' ? `Verified SHA-256 ${item.sha256}` : item.error?.message ?? item.error ?? 'Verification pending',
          item.cleanup_pending ? el('small', { class: 'cell-note' }, 'Temporary data retained') : null),
        el('td', {}, el('div', { class: 'actions' }, controls)));
    }));
    content.replaceChildren(panel('Transfers and recovery', [notice('Finished downloads verify the server copy. Saving the attachment is controlled by your browser.'),
      table(['File', 'Direction', 'State', 'Accepted bytes', 'Verification / error', 'Actions'], rows, 'File transfers')]));
    if (focus) [...element.querySelectorAll('[data-focus]')].find(item => item.dataset.focus === focus)?.focus({ preventScroll: true });
  }
  async function load() {
    if (!active || loading || !allowed('files:read')) return;
    loading = true; clearTimeout(timer);
    try {
      const result = await request('/transfers');
      if (!active) return;
      const prior = new Map(records.map(item => [item.id, item.state]));
      records = result.transfers; draw();
      if (records.some(item => item.state === 'succeeded' && prior.get(item.id) !== 'succeeded')) changed();
    } catch (error) {
      if (!active) return;
      status.replaceChildren(errorPanel(error, load));
      if ([401, 403].includes(error.status)) { uploads.dispose(); records = []; content.replaceChildren(); }
    } finally { loading = false; if (active) timer = setTimeout(load, 3000); }
  }
  load();
  return { element, received, dispose() { active = false; clearTimeout(timer); uploads.dispose(); } };
}
