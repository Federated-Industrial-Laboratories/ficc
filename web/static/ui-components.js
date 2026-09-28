// SPDX-License-Identifier: Apache-2.0
// Build host controls and validate each value before it reaches a component.
import { button, el } from './components.js';
import { validateTableRows } from './ui-table.js';

const unsafe = new Set(['__proto__', 'prototype', 'constructor']);
const fail = () => { throw Error('Invalid component data.'); };
const text = (value, max = 8192) => { if (typeof value !== 'string' || value.length > max || value.includes('\0')) fail(); };
const list = (value, max) => { if (!Array.isArray(value) || value.length > max) fail(); return value; };
const ref = value => { text(value, 128); if (!value || unsafe.has(value) || /[\\/:]/u.test(value)) fail(); };
const scalar = value => { if (typeof value === 'string') text(value, 4096); else if (value !== null && typeof value !== 'boolean' && !(typeof value === 'number' && Number.isFinite(value))) fail(); };
export const bindable = {
  text: ['text'], status: ['text', 'tone'], details: ['items'], table: ['rows'], field: ['value'],
  select: ['options', 'value'], radio: ['options', 'value'], slider: ['value'], progress: ['value'],
  meter: ['value'], tree: ['items', 'value'], pager: ['page', 'total'], log: ['lines'],
};

export function boundedData(value) {
  let count = 0, bytes = 0;
  function copy(item, depth) {
    if (++count > 32768 || depth > 12) fail();
    if (item === null || typeof item === 'boolean') return item;
    if (typeof item === 'number') { if (!Number.isFinite(item) || Number.isInteger(item) && !Number.isSafeInteger(item)) fail(); return item; }
    if (typeof item === 'string') { text(item, 65536); bytes += new TextEncoder().encode(item).length; if (bytes > 1048576) fail(); return item; }
    if (Array.isArray(item)) return Object.freeze(list(item, 256).map(entry => copy(entry, depth + 1)));
    if (!item || typeof item !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(item))) fail();
    const entries = Object.entries(item); if (entries.length > 256) fail();
    const result = Object.create(null);
    for (const [key, entry] of entries) {
      text(key, 240); if (unsafe.has(key)) fail(); bytes += key.length;
      result[key] = copy(entry, depth + 1);
    }
    return Object.freeze(result);
  }
  const result = copy(value, 0);
  if (new TextEncoder().encode(JSON.stringify(result)).length > 1048576) fail();
  return result;
}

export function pathValue(value, path) {
  if (!Array.isArray(path) || !path.length || path.length > 8) fail();
  for (const key of path) {
    if (!(typeof key === 'string' && key.length > 0 && key.length <= 96 && !unsafe.has(key) ||
        Number.isInteger(key) && key >= 0 && key < 256)) fail();
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, key)) throw Error('Component data is missing.');
    value = value[key];
  }
  return value;
}

export function validateData(node) {
  if (node.disabled !== undefined && typeof node.disabled !== 'boolean') fail();
  if (node.state !== undefined && !['ready', 'loading', 'empty', 'stale', 'error'].includes(node.state)) fail();
  if (node.message !== undefined) text(node.message, 160);
  const kind = node.type;
  if (kind === 'text' || kind === 'status') {
    text(node.text ?? '');
    if (kind === 'status' && !['neutral', 'good', 'warning', 'error'].includes(node.tone || 'neutral')) fail();
  } else if (kind === 'table') validateTableRows({ ...node, rows: node.rows || [] });
  else if (kind === 'details') for (const item of list(node.items || [], 64)) { text(item.label, 160); scalar(item.value); }
  else if (kind === 'log') for (const line of list(node.lines || [], 128)) text(line, 2048);
  else if (kind === 'field') {
    if (!node.input_type || node.input_type === 'text') text(node.value ?? '');
    else if (node.input_type === 'number' ? typeof node.value !== 'number' || !Number.isFinite(node.value) :
      node.input_type !== 'checkbox' || typeof node.value !== 'boolean') fail();
  } else if (['slider', 'progress', 'meter'].includes(kind)) {
    const low = node.min ?? 0, high = node.max ?? 100, value = node.value ?? 0;
    if (![low, high, value].every(value => typeof value === 'number' && Number.isFinite(value)) || low >= high || value < low || value > high) fail();
    if (kind === 'slider' && !(typeof node.step === 'number' && Number.isFinite(node.step) && node.step > 0)) fail();
  } else if (kind === 'select' || kind === 'radio') {
    const ids = new Set();
    for (const option of list(node.options || [], 64)) {
      ref(option.id); text(option.label, 160);
      if (ids.has(option.id) || option.disabled !== undefined && typeof option.disabled !== 'boolean') fail();
      ids.add(option.id);
    }
    if ((node.value ?? '') !== '' && !ids.has(node.value)) fail();
  } else if (kind === 'tree') {
    const ids = new Set();
    function walk(items, depth = 0) {
      if (depth > 6) fail();
      for (const item of list(items, 128)) {
        ref(item.id); text(item.label, 160); if (ids.size >= 128 || ids.has(item.id)) fail();
        ids.add(item.id); walk(item.children || [], depth + 1);
      }
    }
    walk(node.items || []); if ((node.value ?? '') !== '' && !ids.has(node.value)) fail();
  } else if (kind === 'pager') {
    if (!Number.isInteger(node.page ?? 1) || !Number.isInteger(node.total ?? 1) ||
        (node.page ?? 1) < 1 || (node.page ?? 1) > (node.total ?? 1) || (node.total ?? 1) > 128) fail();
  } else if (kind === 'credential') {
    ref(node.ref); if (!node.ref.startsWith('hostcredential-')) fail();
  }
}

export function tabs(node, label, render, changed) {
  const prefix = `module-tabs-${crypto.randomUUID()}`, controls = [], panels = [];
  const bar = el('div', { role: 'tablist', 'aria-label': label });
  const element = el('section', { class: 'module-tabs' }, bar);
  function select(index, focus = false) {
    controls.forEach((control, i) => {
      control.setAttribute('aria-selected', String(i === index)); control.tabIndex = i === index ? 0 : -1;
      panels[i].hidden = i !== index;
    });
    if (focus) controls[index].focus(); changed();
  }
  node.items.forEach((item, index) => {
    const id = `${prefix}-${index}`;
    const control = button(item.label, () => select(index), { id, role: 'tab', 'aria-controls': `${id}-panel` });
    const panel = el('section', { id: `${id}-panel`, role: 'tabpanel', 'aria-labelledby': id, tabindex: 0 }, item.children.map(render));
    control.addEventListener('keydown', event => {
      const keys = { ArrowRight: (index + 1) % node.items.length, ArrowLeft: (index + node.items.length - 1) % node.items.length,
        Home: 0, End: node.items.length - 1 };
      if (Object.hasOwn(keys, event.key)) { event.preventDefault(); select(keys[event.key], true); }
    });
    controls.push(control); panels.push(panel); bar.append(control); element.append(panel);
  });
  select(0); return { element };
}

export function tree(node, label) {
  let selected = node.value || '', data = node, controls = [], focusId;
  const closed = new Set(), element = el('div', { role: 'tree', 'aria-label': label, class: 'module-tree' });
  function draw() {
    const active = element.contains(document.activeElement) ? document.activeElement.dataset.key : null; controls = [];
    function branch(items, depth, parent) {
      return items.map(item => {
        const children = item.children || [], group = el('div', { role: 'group', id: `module-tree-${crypto.randomUUID()}`, hidden: closed.has(item.id) });
        const control = button(item.label, () => {
          selected = item.id; focusId = item.id;
          if (children.length) { if (closed.has(item.id)) closed.delete(item.id); else closed.add(item.id); }
          draw();
        }, {
          role: 'treeitem', 'aria-label': item.label, 'aria-level': depth, 'aria-selected': String(selected === item.id),
          'aria-expanded': children.length ? String(!closed.has(item.id)) : null, 'aria-owns': children.length ? group.id : null,
          'data-key': item.id, tabindex: -1,
        });
        controls.push(control);
        const toggle = open => { if (open) closed.delete(item.id); else closed.add(item.id); focusId = item.id; draw(); };
        control.addEventListener('focus', () => { focusId = item.id; for (const other of controls) other.tabIndex = other === control ? 0 : -1; });
        control.addEventListener('keydown', event => {
          const shown = controls.filter(item => !item.closest('[hidden]')), index = shown.indexOf(control);
          let destination;
          if (event.key === 'ArrowDown') destination = shown[Math.min(index + 1, shown.length - 1)];
          else if (event.key === 'ArrowUp') destination = shown[Math.max(0, index - 1)];
          else if (event.key === 'Home') destination = shown[0];
          else if (event.key === 'End') destination = shown.at(-1);
          else if (event.key === 'ArrowRight' && children.length) {
            if (closed.has(item.id)) toggle(true); else destination = shown[index + 1];
          } else if (event.key === 'ArrowLeft') {
            if (children.length && !closed.has(item.id)) toggle(false);
            else destination = controls.find(item => item.dataset.key === parent);
          } else return;
          event.preventDefault(); destination?.focus();
        });
        group.append(...branch(children, depth + 1, item.id));
        return el('div', { role: 'none' }, control, children.length > 0 && group);
      });
    }
    element.replaceChildren(...branch(data.items || [], 1, null));
    const current = controls.find(item => item.dataset.key === focusId && !item.closest('[hidden]')) || controls[0];
    if (current) current.tabIndex = 0;
    if (active) (controls.find(item => item.dataset.key === active) || current)?.focus();
    if (!controls.length) element.append(el('p', {}, 'No items'));
  }
  draw(); return { element, read: () => selected, update(value) { data = value; selected = value.value || ''; draw(); } };
}

export function basicComponent(node, label) {
  validateData(node);
  const kind = node.type;
  if (kind === 'tree') return tree(node, label);
  if (kind === 'text' || kind === 'status') {
    const element = el(kind === 'text' ? 'p' : 'output', { class: `module-${kind}` });
    const update = value => { element.textContent = value.text || ''; if (kind === 'status') element.dataset.tone = value.tone || 'neutral'; };
    update(node); return { element, update };
  }
  if (kind === 'details' || kind === 'log') {
    const element = el(kind === 'log' ? 'pre' : 'dl', { class: `module-${kind}`, 'aria-label': label, tabindex: 0 });
    const update = value => {
      if (kind === 'log') element.textContent = (value.lines || []).join('\n') || 'No entries';
      else element.replaceChildren(...(value.items || []).flatMap(item => [el('dt', {}, item.label), el('dd', {}, String(item.value ?? ''))]));
    };
    update(node); return { element, update };
  }
  if (kind === 'credential') return { element: el('div', { class: 'module-field' }, label, el('code', {}, node.ref)), read: () => node.ref };
  if (kind === 'field' || kind === 'slider' || kind === 'select') {
    const type = kind === 'slider' ? 'range' : node.input_type || 'text';
    const input = el(kind === 'select' ? 'select' : 'input', { 'aria-label': label,
      ...(kind === 'select' ? {} : { type, maxlength: 8192 }), ...(kind === 'slider' ? { min: node.min ?? 0, max: node.max ?? 100, step: node.step } : {}) });
    const number = el('output'), element = el('label', { class: 'module-field' }, label, input, kind === 'slider' && number);
    const update = value => {
      if (kind === 'select') input.replaceChildren(el('option', { value: '' }, 'Select an option'), ...(value.options || []).map(item => el('option', { value: item.id, disabled: item.disabled }, item.label)));
      input.value = String(value.value ?? ''); input.checked = value.value === true; number.textContent = input.value;
    };
    input.addEventListener('input', () => { number.textContent = input.value; });
    update(node); return { element, update, read: () => type === 'checkbox' ? input.checked : ['range', 'number'].includes(type) ? input.valueAsNumber : input.value };
  }
  if (kind === 'radio') {
    const name = `module-radio-${crypto.randomUUID()}`, items = el('div'), element = el('fieldset', { class: 'module-radio' }, el('legend', {}, label), items);
    let selected = node.value || '';
    const update = value => {
      const active = items.contains(document.activeElement) ? document.activeElement.value : null; selected = value.value || '';
      items.replaceChildren(...(value.options || []).map(item => {
        const input = el('input', { type: 'radio', name, value: item.id, disabled: item.disabled });
        input.checked = selected === item.id; input.addEventListener('change', () => { selected = input.value; });
        return el('label', {}, input, item.label);
      }));
      if (active) ([...items.querySelectorAll('input')].find(input => input.value === active) || items.querySelector('input:not(:disabled)'))?.focus();
    };
    update(node); return { element, update, read: () => selected };
  }
  if (kind === 'progress' || kind === 'meter') {
    const input = el(kind, { 'aria-label': label, min: node.min ?? 0, max: node.max ?? 100 }), number = el('output');
    const update = value => { input.value = value.value ?? 0; number.textContent = `${input.value} / ${input.max}`; };
    update(node); return { element: el('label', { class: 'module-field' }, label, input, number), update };
  }
  if (kind === 'pager') {
    let page, total;
    const status = el('output', { 'aria-live': 'polite' });
    const previous = button('Previous page', () => { page--; draw(); }), next = button('Next page', () => { page++; draw(); });
    const element = el('nav', { class: 'module-pager', 'aria-label': label }, previous, status, next);
    function draw() { previous.disabled = page === 1; next.disabled = page === total; status.textContent = `Page ${page} of ${total}`; }
    const update = value => { page = value.page ?? 1; total = value.total ?? 1; draw(); };
    update(node); return { element, update, read: () => page };
  }
  return null;
}
