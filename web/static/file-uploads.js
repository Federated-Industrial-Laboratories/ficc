// SPDX-License-Identifier: Apache-2.0
// Upload one chunk at a time and verify every accepted prefix again on resume.
import { request } from './api.js';
import { el, notice } from './components.js';
import { fileDialog } from './file-dialog.js';

export function uploadSender(updated, failed) {
  let active = true;
  const controllers = new Map();
  async function send(transfer, files, resume = false) {
    if (!active || controllers.has(transfer.id)) return;
    const controller = new AbortController(); controllers.set(transfer.id, controller);
    try {
      const items = transfer.items.filter(item => !['succeeded', 'cancelled', 'failed', 'unknown'].includes(item.state));
      const matched = items.map(item => {
        const file = files.find(file => file.name === item.name && file.size === item.size);
        if (!file) throw new Error(`Select the original file for ${item.name}. Filename and size identify a candidate; its full accepted prefix is verified before continuing.`);
        return { item, file };
      });
      if (resume) await request(`/transfers/${transfer.id}/resume`, { method: 'POST', body: { item_ids: items.map(item => item.id) }, signal: controller.signal });
      for (const { item, file } of matched) {
        for (let offset = 0; offset < file.size; offset += 262144) {
          if (!active || controller.signal.aborted) return;
          const bytes = new Uint8Array(await file.slice(offset, offset + 262144).arrayBuffer());
          const digest = await crypto.subtle.digest('SHA-256', bytes);
          const chunkHash = [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
          await request(`/transfers/${transfer.id}/items/${item.id}/chunks?offset=${offset}`, { method: 'PUT', bytes, chunkHash, signal: controller.signal });
          if (!active || controller.signal.aborted) return;
          updated();
        }
        if (!active || controller.signal.aborted) return;
        await request(`/transfers/${transfer.id}/items/${item.id}/finish`, { method: 'POST', body: {}, signal: controller.signal });
        updated();
      }
    } catch (error) { if (active && !controller.signal.aborted) failed(error); }
    finally { controllers.delete(transfer.id); if (active) updated(); }
  }
  return { send, busy: id => controllers.has(id),
    cancel(id) { controllers.get(id)?.abort(); },
    resume(transfer) {
      const view = fileDialog('Reselect original upload files');
      const input = el('input', { id: 'resume-upload-files', type: 'file', multiple: true, required: true });
      view.content.append(notice('Select the original files. Every accepted prefix chunk is sent again and checked against the staged bytes before new data continues.'),
        el('form', { onsubmit: event => { event.preventDefault(); const files = [...input.files]; view.dialog.close(); send(transfer, files, true); } },
          el('label', { for: input.id }, 'Original upload files'), input,
          el('div', { class: 'actions' }, el('button', { type: 'submit', class: 'primary' }, 'Verify prefix and resume'))));
    },
    dispose() { active = false; for (const controller of controllers.values()) controller.abort(); controllers.clear(); },
  };
}
