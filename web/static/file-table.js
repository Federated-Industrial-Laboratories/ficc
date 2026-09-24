// SPDX-License-Identifier: Apache-2.0
// Present one bounded file page with literal names, sorting and column control.
import { button, bytes, el } from './components.js';

const columns = [
  ['select', 'Select', 42, 36], ['name', 'Name', 245, 140], ['kind', 'Type', 85, 65],
  ['size', 'Size', 95, 75], ['modified_ns', 'Modified', 164, 140],
  ['owner', 'Owner / group', 112, 90], ['mode', 'Mode', 66, 55],
];
const names = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
const dates = new Intl.DateTimeFormat('en-GB', {
  day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
});

export function fileTable(side, changed, open, filtered) {
  let entries = [], selected = new Set(), sort = 'name', direction = 1, focused = null, query = '';
  const widths = columns.map(column => column[2]);
  const body = el('tbody'), head = el('tr'), colgroup = el('colgroup');
  const table = el('table', { class: 'explorer-table' }, el('caption', { class: 'sr-only' }, `${side} files`),
    colgroup, el('thead', {}, head), body);
  const element = el('div', { class: 'table-scroll explorer-list', tabindex: '0', role: 'region', 'aria-label': `${side} file list` }, table);
  const headers = new Map();
  function size() {
    table.style.width = `${widths.reduce((a, b) => a + b, 0)}px`;
    [...colgroup.children].forEach((col, i) => { col.style.width = `${widths[i]}px`; });
  }
  for (const [index, [key, title, , minimum]] of columns.entries()) {
    colgroup.append(el('col'));
    const th = el('th', { scope: 'col', 'data-column': key });
    if (key === 'select') th.append(el('span', { class: 'sr-only' }, title));
    else th.append(button(title, () => {
      direction = sort === key ? -direction : 1; sort = key; draw();
    }, { class: 'column-sort', 'data-sort': key }));
    const resize = el('span', { class: 'column-resize', role: 'separator', tabindex: '0',
      'aria-label': `${side} ${title} column width`, 'aria-orientation': 'vertical',
      'aria-valuemin': minimum, 'aria-valuemax': 600, 'aria-valuenow': widths[index] });
    let drag = null;
    function adjust(value) {
      widths[index] = Math.max(minimum, Math.min(600, Math.round(value)));
      resize.setAttribute('aria-valuenow', widths[index]); size();
    }
    resize.addEventListener('keydown', event => {
      const delta = { ArrowLeft: -16, ArrowRight: 16 }[event.key];
      if (delta != null || ['Home', 'End'].includes(event.key)) {
        event.preventDefault(); adjust(event.key === 'Home' ? minimum : event.key === 'End' ? 600 : widths[index] + delta);
      }
    });
    resize.addEventListener('pointerdown', event => {
      if (event.button !== 0) return;
      event.preventDefault(); drag = { x: event.clientX, width: widths[index], id: event.pointerId };
      resize.setPointerCapture(event.pointerId);
    });
    resize.addEventListener('pointermove', event => { if (drag?.id === event.pointerId) adjust(drag.width + event.clientX - drag.x); });
    for (const name of ['pointerup', 'pointercancel', 'lostpointercapture']) resize.addEventListener(name, () => { drag = null; });
    th.append(resize); headers.set(key, th); head.append(th);
  }
  function visible() {
    return entries.filter(entry => entry.name.toLocaleLowerCase().includes(query)).sort((a, b) => {
      const value = entry => sort === 'owner' ? `${entry.uid} / ${entry.gid}` : entry[sort];
      const av = value(a), bv = value(b);
      const order = typeof av === 'number' && typeof bv === 'number' ? av - bv : names.compare(String(av), String(bv));
      const folders = sort === 'name' ? Number(b.kind === 'directory') - Number(a.kind === 'directory') : 0;
      return folders || direction * order || names.compare(a.name, b.name) || a.entry_id.localeCompare(b.entry_id);
    });
  }
  function paint() {
    for (const row of body.querySelectorAll('[data-entry]')) {
      const checked = selected.has(row.dataset.entry);
      row.classList.toggle('selected', checked); row.setAttribute('aria-selected', String(checked));
      row.querySelector('input').checked = checked;
      row.tabIndex = row.dataset.entry === focused ? 0 : -1;
    }
  }
  function select(entry, event = {}) {
    const next = new Set(event.ctrlKey || event.metaKey ? selected : []), rows = visible();
    if (event.shiftKey && focused && rows.some(row => row.entry_id === focused)) {
      const start = rows.findIndex(row => row.entry_id === focused), end = rows.indexOf(entry);
      for (const row of rows.slice(Math.min(start, end), Math.max(start, end) + 1)) next.add(row.entry_id);
    } else if ((event.ctrlKey || event.metaKey) && next.has(entry.entry_id)) next.delete(entry.entry_id);
    else next.add(entry.entry_id);
    if (changed(next) === false) return;
    selected = next; focused = entry.entry_id; paint();
  }
  function draw() {
    const visibleEntries = visible();
    if (!visibleEntries.some(entry => entry.entry_id === focused)) focused = visibleEntries[0]?.entry_id ?? null;
    for (const [key, th] of headers) {
      if (key === sort) th.setAttribute('aria-sort', direction === 1 ? 'ascending' : 'descending');
      else th.removeAttribute('aria-sort');
    }
    body.replaceChildren(...visibleEntries.map(entry => {
      const checkbox = el('input', { type: 'checkbox', 'aria-label': `Select ${entry.name}` });
      checkbox.addEventListener('change', () => {
        const next = new Set(selected);
        if (checkbox.checked) next.add(entry.entry_id); else next.delete(entry.entry_id);
        if (changed(next) !== false) selected = next;
        focused = entry.entry_id; paint();
      });
      const name = entry.kind === 'directory' ? button(entry.name, () => open(entry), { class: 'file-open' }) : el('span', {}, entry.name);
      const row = el('tr', { 'data-entry': entry.entry_id, title: entry.name },
        el('td', {}, checkbox), el('td', { class: 'file-name' }, name),
        el('td', {}, entry.kind), el('td', { class: 'numeric' }, entry.kind === 'directory' ? '-' : bytes(entry.size)),
        el('td', { class: 'file-date' }, dates.format(new Date(entry.modified_ns / 1e6))),
        el('td', { class: 'file-owner' }, `${entry.uid} / ${entry.gid}`),
        el('td', { class: 'file-mode' }, Number(entry.mode).toString(8).padStart(3, '0')));
      row.addEventListener('click', event => {
        if (event.target.closest('input,button')) return;
        select(entry, event); row.focus({ preventScroll: true });
      });
      row.addEventListener('dblclick', event => { if (!event.target.closest('input,button')) { select(entry); open(entry); } });
      row.addEventListener('keydown', event => {
        if (event.target !== row) return;
        const index = visibleEntries.indexOf(entry);
        const target = { ArrowDown: Math.min(index + 1, visibleEntries.length - 1), ArrowUp: Math.max(index - 1, 0), Home: 0, End: visibleEntries.length - 1 }[event.key];
        if (target != null) {
          event.preventDefault(); focused = visibleEntries[target].entry_id; paint(); body.children[target].focus();
        } else if (event.key === ' ') { event.preventDefault(); select(entry, { ctrlKey: true }); }
        else if (event.key === 'Enter') { event.preventDefault(); select(entry); open(entry); }
      });
      return row;
    }));
    if (!visibleEntries.length) body.append(el('tr', {}, el('td', { colspan: columns.length, class: 'explorer-empty' },
      entries.length ? 'No matches on this page.' : 'This directory has no entries.')));
    paint(); size();
  }
  return { element, visible, update(values, selection) { entries = values; selected = selection; draw(); },
    filter(value) { query = value.toLocaleLowerCase(); selected = new Set(); filtered(); draw(); } };
}
