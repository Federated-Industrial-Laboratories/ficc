// SPDX-License-Identifier: Apache-2.0
// Render approved component data without evaluating module code or markup.
import { button, el, notice } from './components.js';
import { audioPlayer } from './ui-audio-player.js';
import { basicComponent, bindable, boundedData, pathValue, tabs, validateData } from './ui-components.js';
import { dataTable } from './ui-table.js';
import { fileEditor } from './ui-file-editor.js';
import { lifecycleActions } from './ui-lifecycle-actions.js';
import { viewers } from './ui-viewers.js';

export function renderModule(instance, module, { saveState, audio, invoke, drafts = {}, workspaceId }) {
  const disposers = [], flushers = [], visible = [], fields = new Map(), selections = new Map(), records = [];
  const output = el('div', { role: 'status' }), pending = new Set(), actions = new Set((module.manifest.actions || []).map(item => item.id));
  let count = 0, disposed = false, shown = true, outputRevision = 0;
  const lifecycle = [['vm:read', 'vms'], ['container:read', 'containers'], ['admin:read', 'admin']]
    .filter(([capability]) => module.manifest.capabilities?.includes(capability))
    .map(([, kind]) => lifecycleActions({ workspace_id: workspaceId, instance_id: instance.id }, kind));
  lifecycle.forEach(control => disposers.push(() => control.dispose()));
  const displays = viewers();
  disposers.push(() => displays.dispose());
  const element = el('div', { class: 'module-view' });
  const visibility = () => { for (const item of visible) item.change(shown && !item.element.closest('[hidden]')); };
  function paint(record, state = record.current.state || 'ready', message = record.current.message || '') {
    record.wrapper.dataset.state = state;
    record.wrapper.disabled = Boolean(record.current.disabled) || state === 'loading';
    record.controller.element.inert = record.wrapper.disabled;
    record.wrapper.setAttribute('aria-busy', String(state === 'loading'));
    record.wrapper.setAttribute('aria-disabled', String(record.wrapper.disabled));
    record.status.setAttribute('role', state === 'error' ? 'alert' : 'status');
    record.status.textContent = message || { loading: 'Loading', empty: 'No data', stale: 'Data is stale', error: 'Data is not available' }[state] || '';
    record.status.hidden = !record.status.textContent;
  }
  function related(action) { return records.filter(record => Object.values(record.node.bind || {}).some(binding => binding.action === action)); }
  function update(action, result) {
    if (disposed) return false;
    if (!actions.has(action)) throw Error('This action is not declared.');
    const data = boundedData(result), changes = related(action).map(record => {
      const next = { ...record.current };
      for (const [property, binding] of Object.entries(record.node.bind || {})) {
        if (binding.action === action) next[property] = pathValue(data, binding.path);
      }
      validateData(next); return [record, next];
    });
    for (const [record, next] of changes) { record.controller.update?.(next); record.current = next; paint(record); }
    return true;
  }
  function parameters(node) {
    if (node.parameters === undefined) return boundedData(Object.fromEntries([...fields].map(([name, read]) => [name, read()])));
    return boundedData(Object.fromEntries(Object.entries(node.parameters).map(([name, source]) => {
      if (Object.hasOwn(source, 'value')) return [name, source.value];
      const read = Object.hasOwn(source, 'field') ? fields.get(source.field) : selections.get(source.selection);
      if (!read) throw Error('The action parameter source is missing.');
      return [name, read()];
    })));
  }
  async function run(node, control) {
    if (disposed || pending.has(node.action)) return;
    const revision = ++outputRevision;
    pending.add(node.action); control.disabled = true;
    output.replaceChildren(notice('Running action.'));
    const affected = related(node.action); affected.forEach(record => paint(record, 'loading'));
    try {
      const result = await invoke(node.action, parameters(node));
      if (disposed) return;
      update(node.action, result);
      if (revision !== outputRevision) return;
      const controls = [...lifecycle.flatMap(control => control.controls(result)), ...displays.controls(result)];
      output.replaceChildren(controls.length ? notice('Use the FICC controls below to continue.') : affected.length ? notice('Action complete.') :
        el('pre', { class: 'module-result' }, JSON.stringify(boundedData(result), null, 2).slice(0, 65536)));
      output.append(...controls);
    } catch (error) {
      if (!disposed) {
        affected.forEach(record => paint(record, 'error', String(error.message).slice(0, 160)));
        if (revision === outputRevision) output.replaceChildren(notice(error.message, 'error'));
      }
    } finally { pending.delete(node.action); if (!disposed) control.disabled = Boolean(node.disabled); }
  }
  function render(node, depth = 0) {
    if (++count > 128 || depth > 8 || !node || typeof node !== 'object') throw Error('Invalid component document.');
    const label = String(node.label || node.name || node.id || 'Value').slice(0, 160);
    const key = String(node.id || node.name || node.type);
    for (const [property, binding] of Object.entries(node.bind || {})) {
      if (![...(bindable[node.type] || []), 'state', 'message', 'disabled'].includes(property) || !actions.has(binding.action)) throw Error('Invalid component binding.');
      // Validate the path before an action is dispatched.
      if (!Array.isArray(binding.path) || !binding.path.length || binding.path.length > 8 || binding.path.some(part =>
        !(typeof part === 'string' && part.length > 0 && part.length <= 96 && !['__proto__', 'prototype', 'constructor'].includes(part) || Number.isInteger(part) && part >= 0 && part < 256))) throw Error('Invalid component path.');
    }
    validateData(node);
    const controller = create(node, depth, label, key), status = el('p', { class: 'module-component-state', hidden: true });
    const wrapper = el('fieldset', { class: 'module-component', 'data-component-id': node.id || '' }, controller.element, status);
    const record = { node, current: node, controller, wrapper, status }; records.push(record); paint(record);
    if (controller.read) fields.set(node.name, controller.read);
    if (controller.selection) selections.set(node.id, controller.selection);
    return wrapper;
  }
  function create(node, depth, label, key) {
    const basic = basicComponent(node, label); if (basic) return basic;
    switch (node.type) {
      case 'column': case 'row': case 'group': case 'toolbar': case 'menu': {
        if (node.children !== undefined && (!Array.isArray(node.children) || node.children.length > 32)) throw Error('Invalid component group.');
        const children = (node.children || []).map(child => render(child, depth + 1));
        if (node.type === 'menu') {
          const summary = el('summary', {}, label), menu = el('details', { class: 'module-menu' }, summary, ...children);
          menu.addEventListener('keydown', event => {
            if (event.key === 'Escape') { menu.open = false; summary.focus(); event.preventDefault(); }
          });
          return { element: menu };
        }
        return { element: el('section', { class: `module-${node.type}`, 'aria-label': label }, node.label && el('h3', {}, label), children) };
      }
      case 'tabs': return tabs(node, label, child => render(child, depth + 1), visibility);
      case 'table': return dataTable(node, label);
      case 'clock': {
        const clock = el('time', { class: 'module-clock', 'aria-label': label });
        const format = new Intl.DateTimeFormat(undefined, { dateStyle: 'full', timeStyle: 'long', timeZone: node.timezone || 'UTC' });
        const tick = () => { clock.dateTime = new Date().toISOString(); clock.textContent = format.format(new Date()); };
        tick(); const timer = setInterval(tick, 1000); disposers.push(() => clearInterval(timer)); return { element: clock };
      }
      case 'file-editor': {
        const editor = fileEditor({ workspaceId, instanceId: instance.id, drafts, key, label });
        disposers.push(() => editor.dispose()); return { element: editor.element };
      }
      case 'editor': {
        const input = el('textarea', { 'aria-label': label, class: 'module-editor', maxlength: '65536', spellcheck: 'false' });
        const saved = () => String(instance.state[key] ?? node.value ?? '');
        input.value = String(drafts[key] ?? saved());
        const status = el('span', { role: 'status' }, key in drafts ? 'Unsaved changes' : 'Saved'), save = button('Save', async () => {
          save.disabled = true;
          try {
            const text = input.value;
            await saveState({ [key]: text });
            instance.state[key] = text;
            if (input.value === text) { delete drafts[key]; status.textContent = 'Saved'; }
          } catch (error) { status.textContent = error.message; }
          finally { save.disabled = false; }
        });
        input.addEventListener('input', () => { drafts[key] = input.value; status.textContent = 'Unsaved changes'; });
        return { element: el('div', { class: 'module-editor-panel' }, el('label', {}, label, input),
          el('div', { class: 'actions' }, save, button('Discard changes', () => {
            input.value = saved(); delete drafts[key]; status.textContent = 'Saved';
          }), button('Copy text', async () => {
            try { await navigator.clipboard.writeText(input.value); status.textContent = 'Text copied'; }
            catch { input.focus(); input.select(); status.textContent = 'Use the copy shortcut to copy the selected text.'; }
          }), status)) };
      }
      case 'audio-player': {
        const initial = instance.state[key] || {};
        let timer, pending, last = { volume: initial.volume ?? 1, muted: initial.muted ?? false };
        async function persist() {
          clearTimeout(timer); if (!pending) return;
          const next = pending; pending = null;
          try { await saveState({ [key]: next }); instance.state[key] = next; }
          catch (error) { pending = next; if (!disposed) output.replaceChildren(notice(error.message, 'error')); throw error; }
        }
        const player = audioPlayer({ instanceId: instance.id, manager: audio,
          ...last, onState: state => {
            if (disposed || state.volume === last.volume && state.muted === last.muted) return;
            pending = last = { volume: state.volume, muted: state.muted };
            clearTimeout(timer); timer = setTimeout(() => { void persist().catch(() => {}); }, 150);
          } });
        flushers.push(persist);
        disposers.push(() => { clearTimeout(timer); void persist().catch(() => {}); player.dispose(); });
        visible.push({ element: player.element, change: value => player.setVisible(value) }); return { element: player.element };
      }
      case 'button': return { element: button(label, event => { void run(node, event.currentTarget); }, { disabled: node.disabled }) };
      default: throw Error('This component is not supported.');
    }
  }
  try { element.append(...lifecycle.map(control => control.historyControl()), render(boundedData(module.manifest.ui)), output, displays.element); visibility(); }
  catch (error) { for (const dispose of disposers) dispose(); element.replaceChildren(notice(error.message, 'error')); }
  return { element, update, async flush() { await Promise.all(flushers.map(flush => flush())); },
    setVisible(value) { shown = Boolean(value); visibility(); displays.setVisible(shown); },
    dispose() { if (disposed) return; disposed = true; for (const dispose of disposers) dispose(); } };
}
