// SPDX-License-Identifier: Apache-2.0
// Browse one registered location using opaque identities and bounded page selection.
import { allowed, request } from './api.js';
import { button, el, errorPanel, panel, state } from './components.js';
import { fileTable } from './file-table.js';

export function filePane(side, roots, nodes, action, demo) {
  let active = true, ready = false, generation = 0, currentRoot, directory, entries = [], selected = new Set(), next = null, cursor = null;
  const endpoint = el('select', { id: `file-${side}-endpoint` }), rootInput = el('select', { id: `file-${side}-root` });
  const status = el('div'), listing = el('div'), breadcrumb = el('nav', { class: 'file-breadcrumbs', 'aria-label': `${side} directory` });
  const count = el('span', { class: 'selection-count' }, '0 selected');
  const pageCount = el('span', { class: 'muted' });
  const search = el('input', { id: `file-${side}-filter`, type: 'search', placeholder: 'Find on this page', autocomplete: 'off' });
  const up = button('Up', () => { if (parentId) load(parentId); }, { disabled: true });
  let parentId = null;
  const grid = fileTable(side, nextSelection => {
    if (!ready || nextSelection.size > 64) {
      status.replaceChildren(state('Selection limit', 'Select at most 64 entries.')); return false;
    }
    selected = nextSelection; update(); return true;
  }, entry => {
    if (!ready) return;
    if (entry.kind === 'directory') load(entry.entry_id);
    else if (entry.kind === 'file') { selected = new Set([entry.entry_id]); update(); action('preview', api); }
  }, () => { selected.clear(); update(); });
  search.addEventListener('input', () => { grid.filter(search.value); pageCount.textContent = `${grid.visible().length} of ${entries.length} items on this page`; });
  const refresh = button('Refresh', () => load(directory, cursor));
  const more = button('Next page', () => load(directory, next), { disabled: true });
  const first = button('First page', () => load(directory), { disabled: true });
  const selectPage = button('Select page', () => {
    if (grid.visible().length > 64) { status.replaceChildren(state('Selection limit', 'Select at most 64 entries. This page has more than 64 entries.')); return; }
    selected = new Set(grid.visible().map(entry => entry.entry_id)); draw();
  }, { disabled: true });
  const buttons = {};
  for (const [key, label] of Object.entries({ preview: 'Preview', download: 'Download', mkdir: 'New folder', rename: 'Rename', mode: 'Change mode', delete: 'Delete', upload: 'Upload' })) {
    buttons[key] = button(label, () => action(key, api), { 'data-file-action': key, disabled: true });
  }
  const element = panel(`${side} location`, [el('div', { class: 'file-location' },
    el('div', {}, el('label', { for: endpoint.id }, 'Machine'), endpoint),
    el('div', {}, el('label', { for: rootInput.id }, 'Location'), rootInput)),
    el('div', { class: 'file-address' }, up, breadcrumb),
    el('div', { class: 'actions file-actions explorer-toolbar' }, refresh, Object.values(buttons)),
    el('div', { class: 'explorer-selection' }, selectPage, button('Clear selection', () => { selected.clear(); draw(); }),
      el('label', { class: 'sr-only', for: search.id }, `${side} find on this page`), search),
    status, listing, el('div', { class: 'explorer-status' }, count, pageCount,
      el('div', { class: 'actions' }, first, more))], { class: 'panel file-pane', 'data-pane': side });
  const endpoints = [...new Set(roots.map(root => root.node_id ?? 'controller'))];
  for (const id of endpoints) endpoint.append(el('option', { value: id }, id === 'controller' ? 'Controller storage' : nodes.find(node => node.id === id)?.name ?? 'Remote machine'));
  if (side === 'Right') endpoint.value = endpoints.find(id => id !== 'controller') ?? endpoints[0] ?? '';
  else if (endpoints.includes('controller')) endpoint.value = 'controller';
  function chooseRoot() {
    generation++; ready = false; entries = []; next = null; parentId = null; up.disabled = true; search.value = ''; grid.filter(''); breadcrumb.replaceChildren();
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
    selectPage.disabled = !usable || !entries.length; up.disabled = !usable || !parentId; search.disabled = !usable;
  }
  function draw() {
    grid.update(entries, selected); listing.replaceChildren(grid.element);
    pageCount.textContent = `${grid.visible().length} of ${entries.length} items on this page`;
    update();
  }
  async function load(entryId, pageCursor = null) {
    if (!active || !currentRoot?.available) return;
    const identity = ++generation, root = currentRoot;
    ready = false; listing.replaceChildren(); up.disabled = true; search.disabled = true;
    for (const control of [...Object.values(buttons), refresh, first, more, selectPage]) control.disabled = true;
    status.replaceChildren(state('Loading directory', 'Reading a bounded page of registered objects.'));
    try {
      const result = await request('/files/list', { method: 'POST', body: { root_id: root.id, entry_id: entryId, cursor: pageCursor, limit: 100 } });
      if (!active || identity !== generation) return;
      const same = directory === result.entry_id && cursor === pageCursor;
      selected = new Set(same ? [...selected].filter(id => result.entries.some(entry => entry.entry_id === id)) : []);
      if (!same) { search.value = ''; grid.filter(''); }
      parentId = result.breadcrumbs.at(-2)?.entry_id ?? null;
      directory = result.entry_id; cursor = pageCursor; entries = result.entries; next = result.next_cursor; ready = true;
      breadcrumb.replaceChildren(...result.breadcrumbs.map(item => button(item.name, () => load(item.entry_id), { class: 'quiet' })));
      status.replaceChildren(); draw();
    } catch (error) {
      if (!active || identity !== generation) return;
      entries = []; selected.clear(); next = null; parentId = null; listing.replaceChildren(); breadcrumb.replaceChildren();
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
