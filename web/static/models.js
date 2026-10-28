// SPDX-License-Identifier: Apache-2.0
// Register immutable model manifests and resume bounded file uploads.
import { allowed, getSession, request } from './api.js';
import { button, bytes, el, heading, notice, panel, table } from './components.js';
import { modelHub } from './model-hub.js';

export function models() {
  const session = getSession(), abort = new AbortController();
  let active = true, timer;
  const status = el('div'), rows = el('div');
  const valid = () => active && getSession() === session;
  const dialogs = new Set();
  const send = (path, options = {}) => {
    if (!valid()) return Promise.reject(new Error('The selected project has changed. Reopen this view.'));
    return request(path, { ...options, signal: abort.signal });
  };
  async function action(run) {
    try { await run(); if (valid()) await load(); }
    catch (error) { if (valid()) status.replaceChildren(notice(error.message, 'error')); }
  }
  function register() {
    const manifest = el('input', { type: 'file', accept: '.json,application/json', 'aria-label': 'Immutable model manifest' });
    const message = el('div');
    const dialog = el('dialog', {}, el('h2', {}, 'Register model revision'),
      el('p', {}, 'Choose a manifest with the model revision, licence, file sizes and SHA256 digests. Then acquire its HTTPS files or upload matching local weights.'), manifest, message,
      button('Register', async () => {
        try {
          const file = manifest.files[0];
          if (!file || file.size > 65536) throw new Error('Choose a model manifest below 64 KiB.');
          await send('/models', { method: 'POST', body: JSON.parse(await file.text()) });
          dialog.close(); await load();
        } catch (error) { message.replaceChildren(notice(error.message, 'error')); }
      }), button('Cancel', () => dialog.close()));
    dialogs.add(dialog); dialog.addEventListener('close', () => { dialogs.delete(dialog); dialog.remove(); }); document.body.append(dialog); dialog.showModal();
  }
  async function upload(model) {
    const files = el('input', { type: 'file', multiple: true, 'aria-label': 'Model weight and configuration files' });
    const progress = el('p', { role: 'status' });
    let busy = false;
    const dialog = el('dialog', {}, el('h2', {}, 'Upload model files'),
      el('p', {}, 'Choose the files named by this revision. Interrupted uploads resume at their durable offset; all bytes are verified before use.'), files, progress,
      button('Upload', async () => {
        if (busy) return; busy = true;
        try {
          let current = await send(`/models/${model.id}`);
          for (const [index, expected] of current.files.entries()) {
            if (expected.complete) continue;
            if (expected.offset === expected.bytes) {
              progress.textContent = `Verifying ${expected.name}`;
              await send(`/models/${model.id}/files/${index}/bytes?offset=${expected.offset}`, { method: 'POST', bytes: new ArrayBuffer(0), timeout: 600000 });
              continue;
            }
            const file = [...files.files].find(value => value.name === expected.name);
            if (!file || file.size !== expected.bytes) throw new Error(`Choose ${expected.name} (${bytes(expected.bytes)}).`);
            let offset = expected.offset;
            while (offset < file.size) {
              if (!valid()) return;
              const data = await file.slice(offset, offset + 16 * 1024 * 1024).arrayBuffer();
              const receipt = await send(`/models/${model.id}/files/${index}/bytes?offset=${offset}`, { method: 'POST', bytes: data, timeout: 600000 });
              offset = receipt.offset; progress.textContent = `${file.name}: ${bytes(offset)} / ${bytes(file.size)}`;
            }
          }
          dialog.close(); await load();
        } catch (error) { progress.textContent = error.message; } finally { busy = false; }
      }), button('Close', () => dialog.close()));
    dialogs.add(dialog); dialog.addEventListener('close', () => { dialogs.delete(dialog); dialog.remove(); }); document.body.append(dialog); dialog.showModal();
  }
  async function load() {
    clearTimeout(timer);
    try {
      const result = await send('/models'); if (!valid()) return;
      rows.replaceChildren(panel('Project model revisions', [table(['Model', 'Revision / format', 'Verified files', 'Actions'], result.models.map(model =>
        el('tr', {}, el('td', {}, model.manifest.name, el('small', { class: 'cell-note' }, model.id)),
          el('td', {}, `${model.manifest.revision} / ${model.manifest.format}`, el('small', { class: 'cell-note' }, model.manifest.licence)),
          el('td', {}, `${model.files.filter(file => file.complete).length}/${model.files.length} / ${bytes(model.total_bytes)}`, el('small', { class: 'cell-note' }, model.download || (model.ready ? 'Ready' : 'Awaiting weights'))),
          el('td', {}, button('Acquire HTTPS', () => action(() => send(`/models/${model.id}/acquire`, { method: 'POST' })), { disabled: !allowed('models:manage') || model.ready }),
            button('Pause acquisition', () => action(() => send(`/models/${model.id}/pause`, { method: 'POST' })), { disabled: !allowed('models:manage') || model.download !== 'downloading' }),
            button('Upload files', () => upload(model), { disabled: !allowed('models:manage') || model.ready }),
            button('Remove revision', () => action(() => send(`/models/${model.id}?evict=true`, { method: 'DELETE' })), { disabled: !allowed('models:manage') })))), 'Model catalogue')]));
    } catch (error) { if (valid()) status.replaceChildren(notice(error.message, 'error')); }
    if (valid()) timer = setTimeout(load, 3000);
  }
  const importHub = () => { const dialog = modelHub(send, load); dialogs.add(dialog); dialog.addEventListener('close', () => dialogs.delete(dialog)); };
  const element = el('div', {}, heading('INFERENCE / WEIGHTS', 'Models', 'Immutable project revisions, verified storage and resumable acquisition.', [button('Import from Hugging Face', importHub, { disabled: !allowed('models:manage') }), button('Register model', register, { disabled: !allowed('models:manage') }), button('Refresh', load)]), status, rows);
  void load();
  return { element, dispose() { active = false; clearTimeout(timer); abort.abort(); for (const dialog of dialogs) dialog.close(); } };
}
