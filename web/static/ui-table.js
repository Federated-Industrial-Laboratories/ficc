// SPDX-License-Identifier: Apache-2.0
// Keep row identity independent of the visible order and page.
import { button, el } from './components.js';

const reserved = new Set(['__proto__', 'prototype', 'constructor']);
export function validateTableRows(node) {
  if (!Array.isArray(node.columns) || !node.columns.length || node.columns.length > 32 ||
      !Array.isArray(node.rows) || node.rows.length > 128) throw Error('Invalid table data.');
  const columns = new Set(), ids = new Set();
  for (const column of node.columns) {
    if (!column || typeof column.id !== 'string' || reserved.has(column.id) || columns.has(column.id) ||
        typeof column.label !== 'string' || column.label.length > 160) throw Error('Invalid table column.');
    columns.add(column.id);
  }
  for (const row of node.rows) {
    if (!row || typeof row.id !== 'string' || !row.id || row.id.length > 128 || reserved.has(row.id) ||
        /[\\/:\u0000]/u.test(row.id) || ids.has(row.id) || !row.values || Array.isArray(row.values) ||
        typeof row.values !== 'object') throw Error('Invalid table row.');
    ids.add(row.id);
    for (const [key, value] of Object.entries(row.values)) {
      if (!columns.has(key) || !(value === null || typeof value === 'boolean' ||
          typeof value === 'number' && Number.isFinite(value) || typeof value === 'string' && value.length <= 4096)) {
        throw Error('Invalid table cell.');
      }
    }
  }
}

export function dataTable(node, label) {
  let rows = node.rows || [], page = 0, sort = '', direction = 1;
  const selected = new Set(), size = node.page_size || 16, mode = node.selection || 'none';
  const radioName = `module-table-${crypto.randomUUID()}`, headers = [], tbody = el('tbody');
  const summary = el('output', { 'aria-live': 'polite' }), selection = el('output', { 'aria-live': 'polite' });
  const filter = el('input', { type: 'search', 'aria-label': `Filter ${label}`, maxlength: 160 });
  const previous = button('Previous page', () => { page--; draw(); });
  const next = button('Next page', () => { page++; draw(); });
  const clear = button('Clear selection', () => { selected.clear(); draw(); });
  const header = el('tr', {}, mode !== 'none' && el('th', { scope: 'col' }, 'Select'));
  for (const column of node.columns) {
    const cell = el('th', { scope: 'col', 'aria-sort': 'none' }, button(column.label, () => {
      direction = sort === column.id ? -direction : 1; sort = column.id; draw();
    }, { 'aria-label': `Sort by ${column.label}` }));
    headers.push([column.id, cell]); header.append(cell);
  }
  const table = el('table', {}, el('caption', { class: 'sr-only' }, label), el('thead', {}, header), tbody);
  const element = el('section', { class: 'module-table', 'aria-label': label },
    el('div', { class: 'module-table-tools' }, el('label', {}, 'Filter', filter), mode !== 'none' && clear, selection),
    el('div', { class: 'table-scroll', tabindex: 0, role: 'region', 'aria-label': label }, table),
    el('div', { class: 'module-pager', 'aria-label': `${label} pages` }, previous, summary, next));
  filter.addEventListener('input', () => { page = 0; draw(); });
  function draw() {
    const focus = tbody.contains(document.activeElement) ? document.activeElement.dataset.row : null;
    const query = filter.value.toLocaleLowerCase();
    const shown = rows.filter(row => node.columns.some(column => String(row.values[column.id] ?? '').toLocaleLowerCase().includes(query)));
    if (sort) shown.sort((a, b) => {
      const first = a.values[sort], second = b.values[sort];
      const order = typeof first === 'number' && typeof second === 'number' ? first - second :
        String(first ?? '').localeCompare(String(second ?? ''), undefined, { numeric: true });
      return direction * order || a.id.localeCompare(b.id);
    });
    const pages = Math.max(1, Math.ceil(shown.length / size)); page = Math.max(0, Math.min(page, pages - 1));
    tbody.replaceChildren(...shown.slice(page * size, (page + 1) * size).map(row => {
      const tr = el('tr', { 'data-row-id': row.id, 'aria-selected': mode === 'none' ? null : String(selected.has(row.id)) });
      if (mode !== 'none') {
        const input = el('input', { type: mode === 'single' ? 'radio' : 'checkbox', name: radioName,
          'aria-label': `Select ${row.id}`, 'data-row': row.id });
        input.checked = selected.has(row.id);
        input.addEventListener('change', () => {
          if (mode === 'single') selected.clear();
          if (input.checked) selected.add(row.id); else selected.delete(row.id);
          draw();
        });
        tr.append(el('td', {}, input));
      }
      tr.append(...node.columns.map(column => el('td', {}, String(row.values[column.id] ?? ''))));
      return tr;
    }));
    if (!shown.length) tbody.append(el('tr', {}, el('td', { colspan: node.columns.length + (mode === 'none' ? 0 : 1) }, 'No rows')));
    for (const [id, cell] of headers) cell.setAttribute('aria-sort', sort === id ? direction === 1 ? 'ascending' : 'descending' : 'none');
    previous.disabled = page === 0; next.disabled = page === pages - 1;
    summary.textContent = `Page ${page + 1} of ${pages}. ${shown.length} rows.`;
    selection.textContent = mode === 'none' ? '' : `${selected.size} selected`; clear.disabled = !selected.size;
    if (focus) ([...tbody.querySelectorAll('input')].find(input => input.dataset.row === focus) || filter).focus();
  }
  function update(value) {
    validateTableRows(value); rows = value.rows;
    const available = new Set(rows.map(row => row.id));
    for (const id of selected) if (!available.has(id)) selected.delete(id);
    draw();
  }
  update({ ...node, rows });
  return { element, update, selection: () => Object.freeze([...selected].sort()) };
}
