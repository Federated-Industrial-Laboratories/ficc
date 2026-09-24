// SPDX-License-Identifier: Apache-2.0
// Own machine tabs, stable terminal attachments and explicit keyboard selection.
import { button, el, notice } from './components.js';
import { terminalLayout } from './terminal-layout.js';
import { terminalStream } from './terminal-stream.js';

export function terminalWorkspace({ create, changed, canCreate }) {
  let active = true, selectedNode = null, expanded = false;
  const groups = new Map(), tiles = new Map();
  const tabs = el('div', { class: 'terminal-tabs', role: 'tablist', 'aria-label': 'Terminal machines' });
  const panels = el('div', { class: 'terminal-machines' }), message = el('div', { class: 'terminal-message' });
  const empty = notice('Select a recorded session or create a terminal to start this workspace.');
  const splitRight = button('Split right', () => split('right'));
  const splitDown = button('Split down', () => split('down'));
  const expand = button('Expand workspace', () => setExpanded(!expanded), { 'aria-pressed': 'false' });
  const fullscreen = button('Enter fullscreen', toggleFullscreen, { 'aria-pressed': 'false' });
  const element = el('section', { class: 'terminal-workspace', 'aria-label': 'Terminal workspace' },
    el('div', { class: 'terminal-workspace-toolbar' }, el('strong', {}, 'Machine terminals'),
      el('div', { class: 'actions' }, canCreate ? [button('Open terminal', () => create(attach, selectedNode)), splitRight, splitDown] : null, expand, fullscreen)), tabs, message, empty, panels);
  function sync() {
    if (!active) return;
    const current = groups.get(selectedNode);
    splitRight.disabled = splitDown.disabled = !canCreate || !current?.focused || current.layout.leaves().length >= 4 || tiles.size >= 16;
    for (const group of groups.values()) {
      const showing = group.id === selectedNode;
      group.panel.hidden = !showing; group.panel.inert = !showing;
      group.tab.setAttribute('aria-selected', String(showing)); group.tab.tabIndex = showing ? 0 : -1;
      for (const tile of group.layout.leaves()) {
        const visible = showing && (!group.layout.zoomed || group.layout.zoomed === tile);
        tile.element.hidden = !visible; tile.element.inert = !visible;
        tile.element.classList.toggle('terminal-selected', group.focused === tile);
        tile.zoom.textContent = group.layout.zoomed === tile ? 'Restore tiles' : 'Zoom tile';
        tile.zoom.setAttribute('aria-pressed', String(group.layout.zoomed === tile));
        tile.stream.presentation(visible, visible && group.focused === tile);
      }
      group.placeholder.hidden = group.layout.leaves().length > 0;
      group.viewport.hidden = !group.placeholder.hidden;
    }
    empty.hidden = groups.size > 0;
  }
  function select(group, tile, keyboard = false) {
    if (!active || !tiles.has(tile.record.id)) return;
    if (group.layout.zoomed && group.layout.zoomed !== tile) group.layout.zoom(group.layout.zoomed);
    selectedNode = group.id; group.focused = tile; sync();
    tile.stream.presentation(true, true, keyboard);
  }
  function selectMachine(group, keyboard = false) {
    selectedNode = group.id; sync(); group.layout.render();
    if (keyboard) group.tab.focus();
  }
  function machine(record) {
    let group = groups.get(record.node_id);
    if (group) return group;
    const id = `terminal-machine-${groups.size + 1}`;
    const tab = button(record.node_name, () => selectMachine(group), { role: 'tab', id: `${id}-tab`, 'aria-controls': id });
    const canvas = el('div', { class: 'terminal-canvas' });
    const viewport = el('div', { class: 'terminal-viewport' }, canvas);
    const placeholder = notice('No attached terminals on this machine. Attach a recorded session or use New terminal.');
    const panel = el('div', { class: 'terminal-machine', role: 'tabpanel', id, 'aria-labelledby': tab.id }, placeholder, viewport);
    group = { id: record.node_id, tab, panel, placeholder, viewport, focused: null };
    panels.append(panel); tabs.append(tab); group.layout = terminalLayout(canvas, sync); groups.set(group.id, group);
    tab.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      const list = [...groups.values()], index = list.indexOf(group);
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? list.length - 1 : (index + (event.key === 'ArrowLeft' ? -1 : 1) + list.length) % list.length;
      event.preventDefault(); selectMachine(list[next], true);
    });
    if (!selectedNode) selectedNode = group.id;
    sync(); return group;
  }
  function split(axis) {
    const group = groups.get(selectedNode);
    if (!canCreate || !group?.focused || group.layout.leaves().length >= 4 || tiles.size >= 16) return;
    const focusedId = group.focused.record.id;
    create(record => attach(record, axis, focusedId), group.id);
  }
  function remove(id) {
    const tile = tiles.get(id); if (!tile) return;
    const group = groups.get(tile.record.node_id), hadFocus = tile.element.contains(document.activeElement);
    tile.stream.dispose(); tiles.delete(id); const neighbour = group.layout.remove(tile);
    if (group.focused === tile) group.focused = neighbour ?? group.layout.leaves()[0] ?? null;
    sync();
    if (hadFocus) { if (group.focused) group.focused.stream.presentation(true, true, true); else group.tab.focus(); }
    changed();
  }
  function attach(record, axis = 'right', focusedId = null) {
    if (!active) return;
    const previous = tiles.get(record.id);
    if (previous && !previous.stream.ended) { select(groups.get(record.node_id), previous, true); return; }
    if (previous) remove(record.id);
    const group = machine(record);
    if (tiles.size >= 16 || group.layout.leaves().length >= 4) {
      message.replaceChildren(notice('Workspace limit reached: four panes per machine and sixteen in total. Close a pane before attaching another session.', 'warning')); return;
    }
    const tile = { record };
    tile.zoom = button('Zoom tile', () => { group.layout.zoom(tile); select(group, tile); }, { 'aria-pressed': 'false' });
    tile.stream = terminalStream(record, () => { if (active && tiles.get(record.id) === tile) changed(); }, keyboard => select(group, tile, keyboard));
    tile.element = el('section', { class: 'terminal-tile', 'data-terminal-id': record.id, 'aria-label': `${record.label} on ${record.node_name}` },
      el('div', { class: 'terminal-tile-title' }, el('strong', {}, record.label), el('div', { class: 'actions' }, tile.zoom,
        button('Close pane', () => remove(record.id), { title: 'Detach this connection and remove its pane. Tmux can continue.' }))), tile.stream.element);
    tiles.set(record.id, tile); group.layout.add(tile, tiles.get(focusedId) ?? group.focused, axis);
    message.replaceChildren(); select(group, tile, true); group.layout.render(); tile.stream.open(); changed();
  }
  function setExpanded(value) {
    expanded = value; element.classList.toggle('terminal-expanded', value);
    expand.textContent = value ? 'Restore workspace' : 'Expand workspace'; expand.setAttribute('aria-pressed', String(value));
    for (const group of groups.values()) group.layout.render();
  }
  async function toggleFullscreen() {
    try {
      if (document.fullscreenElement === element) { await document.exitFullscreen(); return; }
      setExpanded(true); await element.requestFullscreen();
    }
    catch { if (active) message.replaceChildren(notice('Browser fullscreen is unavailable. The expanded workspace is still available.', 'warning')); }
  }
  function fullscreenChanged() {
    const full = document.fullscreenElement === element;
    fullscreen.textContent = full ? 'Exit fullscreen' : 'Enter fullscreen'; fullscreen.setAttribute('aria-pressed', String(full));
    for (const group of groups.values()) group.layout.render();
  }
  document.addEventListener('fullscreenchange', fullscreenChanged);
  element.addEventListener('keydown', event => {
    if (event.key !== 'Tab' || (!expanded && document.fullscreenElement !== element)) return;
    const controls = [...element.querySelectorAll('button:not(:disabled), [tabindex="0"], textarea')]
      .filter(item => item.getClientRects().length && !item.closest('[inert]'));
    const first = controls[0], last = controls.at(-1);
    if ((event.shiftKey && document.activeElement === first) || (!event.shiftKey && document.activeElement === last)) {
      event.preventDefault(); (event.shiftKey ? last : first)?.focus();
    }
  });
  function clear() {
    setExpanded(false);
    if (document.fullscreenElement === element) document.exitFullscreen().catch(() => {});
    for (const tile of tiles.values()) tile.stream.dispose();
    for (const group of groups.values()) group.layout.dispose();
    tiles.clear(); groups.clear(); selectedNode = null; tabs.replaceChildren(); panels.replaceChildren(); sync();
  }
  sync();
  return { element, attach, remove, clear,
    attached(id) { const tile = tiles.get(id); return Boolean(tile && !tile.stream.ended); },
    records(records) { for (const record of records) machine(record); sync(); },
    dispose() {
      if (!active) return;
      clear(); active = false; document.removeEventListener('fullscreenchange', fullscreenChanged);
    },
  };
}
