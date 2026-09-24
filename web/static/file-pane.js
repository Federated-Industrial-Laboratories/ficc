// SPDX-License-Identifier: Apache-2.0
// Browse one registered location using opaque identities and bounded page selection.
import { allowed, request } from './api.js';
import { button, bytes, el, errorPanel, panel, state, table } from './components.js';

export function filePane(side, roots, nodes, action, demo) {
  let active = true, ready = false, generation = 0, currentRoot, directory, entries = [], selected = new Set(), next = null, cursor = null;
  const endpoint = el('select', { id: `file-${side}-endpoint` }), rootInput = el('select', { id: `file-${side}-root` });
  const status = el('div'), listing = el('div'), breadcrumb = el('nav', { class: 'file-breadcrumbs', 'aria-label': `${side} directory` });
  const count = el('span', { class: 'muted' }, '0 selected');
  const refresh = button('Refresh', () => load(directory, cursor));
  const more = button('Next page', () => load(directory, next), { disabled: true });
  const first = button('First page', () => load(directory), { disabled: true });
  const selectPage = button('Select page', () => {
    if (entries.length > 64) { status.replaceChildren(state('Selection limit', 'Select at most 64 entries. This page has more than 64 entries.')); return; }
    selected = new Set(entries.map(entry => entry.entry_id)); draw();
  }, { disabled: true });
  const buttons = {};
  for (const [key, label] of Object.entries({ preview: 'Preview', download: 'Download', mkdir: 'New folder', rename: 'Rename', mode: 'Change mode', delete: 'Delete', upload: 'Upload' })) {
    buttons[key] = button(label, () => action(key, api), { 'data-file-action': key, disabled: true });
  }
  const element = panel(`${side} location`, [el('div', { class: 'file-location' },
    el('div', {}, el('label', { for: endpoint.id }, 'Endpoint'), endpoint),
    el('div', {}, el('label', { for: rootInput.id }, 'Registered root'), rootInput)), breadcrumb,
    el('div', { class: 'actions file-actions' }, refresh, selectPage, button('Clear selection', () => { selected.clear(); draw(); }), count),
    status, listing, el('div', { class: 'actions file-actions' }, first, more),
    el('div', { class: 'actions file-actions' }, Object.values(buttons))], { class: 'panel file-pane', 'data-pane': side });
  const endpoints = [...new Set(roots.map(root => root.node_id ?? 'controller'))];
  for (const id of endpoints) endpoint.append(el('option', { value: id }, id === 'controller' ? 'Controller storage' : nodes.find(node => node.id === id)?.name ?? 'Remote machine'));
  if (side === 'Right') endpoint.value = endpoints.find(id => id !== 'controller') ?? endpoints[0] ?? '';
  else if (endpoints.includes('controller')) endpoint.value = 'controller';
  function chooseRoot() {
    generation++; ready = false; entries = []; next = null;
    currentRoot = roots.find(root => root.id === rootInput.value); selected.clear(); cursor = null; directory = currentRoot?.entry_id;
    if (currentRoot?.available && currentRoot.actions.includes('read') && allowed('files:read')) load(directory);
    else { entries = []; listing.replaceChildren(state('Root unavailable', currentRoot?.error?.message ?? currentRoot?.error ?? 'This location does not permit reading.')); update(); }
  }
  function chooseEndpoint() {
    rootInput.replaceChildren(...roots.filter(root => (root.node_id ?? 'controller') === endpoint.value).map(root => el('option', { value: root.id }, root.label)));
    chooseRoot();
  }
  endpoint.addEventListener('change', chooseEndpoint); rootInput.addEventListener('change', chooseRoot);
  function update() {
    count.textContent = `${selected.size} selected`;
    const values = entries.filter(entry => selected.has(entry.entry_id));
    const usable = ready && currentRoot?.available && directory;
    const grant = name => usable && currentRoot.actions.includes(name) && allowed(`files:${name}`);
    buttons.preview.disabled = !grant('read') || values.length !== 1 || values[0].kind !== 'file';
    buttons.download.disabled = demo || !grant('read') || !values.length || values.some(entry => entry.kind !== 'file');
    buttons.mkdir.disabled = demo || !grant('write'); buttons.upload.disabled = demo || !grant('write');
    buttons.rename.disabled = demo || !grant('write') || values.length !== 1;
    buttons.mode.disabled = demo || !grant('mode') || !values.length || values.some(entry => !['file', 'directory'].includes(entry.kind));
    buttons.delete.disabled = demo || !grant('delete') || !values.length || values.some(entry => !['file', 'directory', 'symlink'].includes(entry.kind));
    more.disabled = !next; first.disabled = !cursor; refresh.disabled = !usable;
    selectPage.disabled = !usable || !entries.length;
  }
  function draw() {
    listing.replaceChildren(entries.length ? table(['Select', 'Name', 'Type', 'Size', 'Modified', 'Owner / group', 'Mode'], entries.map(entry => {
      const check = el('input', { type: 'checkbox', 'aria-label': `Select ${entry.name}` }); check.checked = selected.has(entry.entry_id);
      check.addEventListener('change', () => {
        if (check.checked && selected.size >= 64) { check.checked = false; status.replaceChildren(state('Selection limit', 'Select at most 64 entries.')); return; }
        if (check.checked) selected.add(entry.entry_id); else selected.delete(entry.entry_id); update();
      });
      return el('tr', {}, el('td', {}, check), el('td', { class: 'file-name' }, entry.kind === 'directory' ?
        button(entry.name, () => load(entry.entry_id), { class: 'node-select' }) : el('span', {}, entry.name)),
      el('td', {}, entry.kind), el('td', { class: 'numeric' }, bytes(entry.size)),
      el('td', {}, new Date(entry.modified_ns / 1e6).toLocaleString()), el('td', {}, `${entry.uid} / ${entry.gid}`),
      el('td', {}, Number(entry.mode).toString(8).padStart(3, '0')));
    }), `${side} files`) : state('Empty directory', 'This directory has no entries.'));
    update();
  }
  async function load(entryId, pageCursor = null) {
    if (!active || !currentRoot?.available) return;
    const identity = ++generation, root = currentRoot;
    ready = false; listing.replaceChildren();
    for (const control of [...Object.values(buttons), refresh, first, more, selectPage]) control.disabled = true;
    status.replaceChildren(state('Loading directory', 'Reading a bounded page of registered objects.'));
    try {
      const result = await request('/files/list', { method: 'POST', body: { root_id: root.id, entry_id: entryId, cursor: pageCursor, limit: 100 } });
      if (!active || identity !== generation) return;
      const same = directory === result.entry_id && cursor === pageCursor;
      selected = new Set(same ? [...selected].filter(id => result.entries.some(entry => entry.entry_id === id)) : []);
      directory = result.entry_id; cursor = pageCursor; entries = result.entries; next = result.next_cursor; ready = true;
      breadcrumb.replaceChildren(...result.breadcrumbs.map(item => button(item.name, () => load(item.entry_id), { class: 'quiet' })));
      status.replaceChildren(); draw();
    } catch (error) {
      if (!active || identity !== generation) return;
      entries = []; selected.clear(); next = null; listing.replaceChildren(); breadcrumb.replaceChildren();
      status.replaceChildren(errorPanel(error, () => load(root.entry_id))); update();
      for (const control of Object.values(buttons)) control.disabled = true;
    }
  }
  const api = { element, value: () => ({ root: currentRoot ? { ...currentRoot, display_label:
    `${currentRoot.node_id ? nodes.find(node => node.id === currentRoot.node_id)?.name ?? `Remote ${currentRoot.node_id.slice(0, 8)}` : 'Controller storage'} / ${currentRoot.label}` } : null,
    entry_id: directory, ready, entries: ready ? entries.filter(entry => selected.has(entry.entry_id)) : [] }),
    refresh: () => load(directory, cursor), dispose() { active = false; generation++; } };
  chooseEndpoint(); return api;
}
