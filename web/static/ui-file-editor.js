// SPDX-License-Identifier: Apache-2.0
// Edit registered text files through the host file authority.
import { request } from './api.js';
import { button, el, notice, table } from './components.js';

export function fileEditor({ workspaceId, instanceId, drafts, key, label = 'Text editor', requester = request }) {
  const context = { workspace_id: workspaceId, instance_id: instanceId };
  let active = true, roots = [], root, directory, cursor = null, current = drafts[key] ? { ...drafts[key] } : null, busy = false;
  const output = el('div', { role: 'status' }), files = el('div'), crumbs = el('nav', { 'aria-label': 'Editor folders' });
  const folder = el('select', { 'aria-label': 'Registered folder' });
  const input = el('textarea', { class: 'module-editor', 'aria-label': label, maxlength: 262144, spellcheck: 'false', disabled: true });
  const name = el('strong', {}, 'Select a text file'), state = el('output', { 'aria-live': 'polite' });
  const accepted = el('input', { type: 'checkbox' });
  const disclosure = el('label', { class: 'module-field' }, accepted,
    'I understand: Save exchanges the file and retains both versions. An external edit can cause a published replacement followed by a conflict. Recover both copies before removing them.');
  const save = button('Save file', () => { void saveFile(); }), check = button('Check save outcome', () => { void checkSave(); });
  const discard = button('Discard draft', () => {
    if (busy) return;
    delete drafts[key]; if (current) { input.value = current.savedText ?? current.text; current.pending = null; } update();
  });
  const reload = button('Reload file', () => { if (current) void open(current.entry_id, current.name); });
  const more = button('Next files', () => { if (cursor) void browse(directory, cursor); });
  const history = el('div'), recoveryText = el('textarea', { class: 'module-editor', 'aria-label': 'Retained text', readonly: true, hidden: true });
  const element = el('section', { class: 'module-column', 'aria-label': label },
    el('label', { class: 'module-field' }, 'Registered folder', folder),
    el('div', { class: 'actions' }, button('Refresh folders', () => { void loadRoots(); }), button('Refresh files', () => { if (directory) void browse(directory); })),
    crumbs, files, more, name, input, disclosure,
    el('div', { class: 'actions' }, save, check, reload, discard, button('Copy text', async () => {
      try { await navigator.clipboard.writeText(input.value); message('Text copied.'); }
      catch { input.focus(); input.select(); message('Use the copy shortcut to copy the selected text.'); }
    }), state), output,
    el('details', {}, el('summary', {}, 'Retained edit copies'), button('Refresh retained copies', () => { void retained(); }), history, recoveryText));
  const dirty = () => Object.hasOwn(drafts, key);
  function message(text, error = false) { if (active) output.replaceChildren(notice(text, error ? 'error' : 'info')); }
  async function api(path, body = {}, options = {}) {
    return requester(`/module-editor/${path}`, { method: 'POST', body: { ...context, ...body }, ...options });
  }
  function update() {
    if (!active) return;
    const valid = new TextEncoder().encode(input.value).length <= 262144 && !input.value.includes('\0');
    input.disabled = !current; input.readOnly = current ? !current.writable : true;
    save.disabled = busy || !current?.writable || !dirty() || !accepted.checked || !valid || Boolean(current?.pending);
    check.disabled = busy || !current?.pending; reload.disabled = busy || !current || dirty(); discard.disabled = busy || !dirty();
    state.textContent = !current ? 'No file selected' : !valid ? 'Text exceeds 256 KiB or contains NUL bytes' :
      current.pending ? 'Save outcome needs a check. Your draft is retained.' : dirty() ? 'Unsaved changes' : current.writable ? 'Saved text' : 'Read-only preview';
  }
  function keepDraft() {
    if (current) drafts[key] = { ...current, text: input.value };
    update();
  }
  input.addEventListener('input', keepDraft); accepted.addEventListener('change', update);
  folder.addEventListener('change', () => {
    if (dirty()) { folder.value = root?.id || ''; message('Save or discard your text before changing folders.', true); return; }
    root = roots.find(item => item.id === folder.value); current = null; input.value = ''; update();
    if (root) void browse(root.entry_id);
  });
  async function loadRoots() {
    try {
      const result = await api('roots'); if (!active) return;
      roots = result.roots; folder.replaceChildren(...roots.map(item => el('option', { value: item.id }, item.label)));
      root = roots.find(item => item.id === (current?.root_id || root?.id)) || roots[0];
      if (!root) { if (current) current.writable = false; update(); files.replaceChildren(notice('No readable folder is granted to this panel.')); return; }
      folder.value = root.id;
      if (current) { current.writable = current.editable !== false && root.id === current.root_id && root.writable; name.textContent = current.name; input.value = current.text; update(); }
      await browse(root.entry_id);
    } catch (error) { if (current) current.writable = false; update(); message(error.message, true); }
  }
  async function browse(entry, next = null) {
    try {
      const selected = root.id, result = await api('list', { root_id: selected, entry_id: entry, cursor: next });
      if (!active || root.id !== selected) return;
      directory = entry; cursor = result.next_cursor;
      crumbs.replaceChildren(...result.breadcrumbs.map(item => button(item.name, () => { void browse(item.entry_id); })));
      files.replaceChildren(table(['Name', 'Type', 'Bytes', 'Action'], result.entries.map(item => el('tr', {},
        el('td', {}, item.name), el('td', {}, item.kind), el('td', {}, String(item.size)), el('td', {},
          ['file', 'directory'].includes(item.kind) && button(item.kind === 'directory' ? 'Browse' : 'Open', () => {
            if (item.kind === 'directory') void browse(item.entry_id); else void open(item.entry_id, item.name);
          }, { 'aria-label': `${item.kind === 'directory' ? 'Browse' : 'Open'} ${item.name}` })))), 'Registered files'));
      more.disabled = !cursor;
    } catch (error) { message(error.message, true); }
  }
  async function open(entryId, title) {
    if (dirty()) { message('Save or discard your text before opening another file.', true); return; }
    busy = true; update();
    try {
      const selected = root.id, result = await api('read', { items: [{ root_id: selected, entry_id: entryId }] });
      if (!active || root.id !== selected) return;
      const item = result.results[0]; if (item.error) throw Error(item.error.message);
      current = { root_id: selected, entry_id: entryId, name: title, ...item.data, savedText: item.data.text, pending: null };
      name.textContent = title; input.value = current.text; message(current.writable ? 'Text loaded.' : 'Read-only preview. A write grant and supported file metadata are required to save.');
    } catch (error) { message(error.message, true); }
    finally { busy = false; update(); }
  }
  function outcome(result, submitted) {
    const item = result.items[0];
    if (item.state === 'succeeded') {
      current = { ...current, entry_id: item.entry_id, sha256: item.sha256, savedText: submitted, text: input.value, pending: null };
      if (input.value === submitted) delete drafts[key]; else keepDraft();
      message('Saved. Both versions are retained. Use Retained edit copies to inspect and remove them.');
    } else {
      if (item.state === 'failed' || item.state === 'conflict') current.pending = null;
      keepDraft(); message(item.message || item.error?.message || 'Save outcome is unknown. Keep your draft and check the receipt.', true);
    }
  }
  async function saveFile() {
    if (save.disabled || !current) return;
    const text = input.value, identity = crypto.randomUUID().replaceAll('-', '');
    current.pending = { id: identity, text }; keepDraft(); busy = true; update();
    try {
      const result = await api('save', { accept_retained_exchange: true,
        items: [{ root_id: current.root_id, entry_id: current.entry_id, sha256: current.sha256, text }] }, { idempotencyKey: identity });
      if (active) outcome(result, text);
    } catch (error) { if (active) { keepDraft(); message(`${error.message} Your draft and save identity are retained. Check the outcome before another save.`, true); } }
    finally { busy = false; update(); }
  }
  async function checkSave() {
    if (!current?.pending || busy) return;
    const pending = current.pending; busy = true; update();
    try { const result = await api('status', { operation_id: pending.id }); if (active) outcome(result, pending.text); }
    catch (error) { message(error.message, true); }
    finally { busy = false; update(); }
  }
  async function retained() {
    try {
      const result = await api('operations'); if (!active) return;
      history.replaceChildren(...result.operations.map(operation => {
        const items = operation.items.map(item => {
          const recovered = el('input', { type: 'checkbox', 'aria-label': `Recovery confirmed ${item.id}` });
          const remove = button('Remove retained copies', async () => {
            try {
              await api('cleanup', { operation_id: operation.id, item_ids: [item.id], confirm: true, recovered: recovered.checked });
              await retained();
            } catch (error) { message(error.message, true); }
          }, { disabled: !item.retained || ['unknown', 'pending'].includes(item.state) || item.state === 'conflict' });
          recovered.addEventListener('change', () => { if (item.state === 'conflict') remove.disabled = !recovered.checked; });
          return el('div', { class: 'module-group' }, el('strong', {}, `${item.state}: ${item.id}`),
            el('p', {}, item.message || item.error?.message || ''),
            el('div', { class: 'actions' }, ...['original', 'draft'].map(copy => button(`Read retained ${copy}`, async () => {
              try {
                const data = await api('recovery', { operation_id: operation.id, item_id: item.id, copy });
                if (!active) return; recoveryText.hidden = false; recoveryText.value = data.text; recoveryText.focus();
              } catch (error) { message(error.message, true); }
            }, { disabled: !item.retained })), remove),
            item.state === 'conflict' && el('label', {}, recovered, 'I have recovered both copies and confirm their removal.'));
        });
        return el('section', { class: 'module-group' }, el('h4', {}, `Save ${operation.id}`), ...items,
          button('Check outcome', async () => {
            try { await api('status', { operation_id: operation.id }); await retained(); }
            catch (error) { message(error.message, true); }
          }),
          button('Remove receipt', async () => {
            try { await api('remove-receipt', { operation_id: operation.id }); await retained(); }
            catch (error) { message(error.message, true); }
          }, { disabled: operation.items.some(item => item.retained || ['pending', 'unknown'].includes(item.state)) }));
      }));
      if (!result.operations.length) history.append(notice('No retained edit receipts.'));
    } catch (error) { message(error.message, true); }
  }
  if (current) { input.value = current.text; name.textContent = current.name; }
  update(); void loadRoots();
  return { element, dispose() { active = false; }, async flush() {}, setVisible() {} };
}
