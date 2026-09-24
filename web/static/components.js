// SPDX-License-Identifier: Apache-2.0
// Render safe text, resource values and accessible controls.
export function el(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (value !== false && value != null) node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) {
    if (child != null && child !== false) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
export function button(label, action, extra = {}) {
  return el('button', { type: 'button', onclick: action, ...extra }, label);
}
export function heading(kicker, title, subtitle, actions = []) {
  return el('div', { class: 'page-heading' }, el('div', {}, el('p', { class: 'eyebrow' }, kicker),
    el('h1', {}, title), el('p', { class: 'subtitle' }, subtitle)), el('div', { class: 'actions' }, actions));
}
export function panel(title, content, extra = {}) {
  return el('section', { class: 'panel', ...extra }, el('div', { class: 'panel-title' }, el('h2', {}, title),
    el('span', { 'aria-hidden': 'true' }, '///')), el('div', { class: 'panel-body' }, content));
}
export function state(title, text, action) {
  return el('div', { class: 'state-panel', role: 'status' }, el('h2', {}, title), el('p', {}, text), action);
}
export function errorPanel(error, retry) {
  const denied = error.status === 403;
  return state(denied ? 'Access denied' : error.status === 0 ? 'Service disconnected' : 'Request failed',
    error.message, retry && button('Retry', retry));
}
export function notice(text, kind = 'info') {
  return el('div', { class: `notice ${kind}`, role: kind === 'error' ? 'alert' : 'status' }, text);
}
export function announce(text) { document.querySelector('#announcement').textContent = text; }
export function bytes(value) {
  if (!Number.isFinite(value)) return 'Unknown';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}
export function percent(value) { return Number.isFinite(value) ? `${value.toFixed(1)}%` : 'Unknown'; }
export function time(value) { return value == null ? 'Never observed' : new Date(value * 1000).toLocaleString(); }
export function age(node) {
  if (node.last_seen == null) return 'No sample';
  const seconds = Math.max(0, Math.floor(Date.now() / 1000 - node.last_seen));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}
export function isStale(node) { return node.stale || (node.last_seen != null && Date.now() / 1000 - node.last_seen > 15); }
export function badge(node) {
  const raw = String(node.state ?? 'unknown').toLowerCase();
  const stale = isStale(node);
  const good = ['ready', 'connected', 'online'].includes(raw) && !stale;
  const kind = good ? 'good' : ['unreachable', 'error', 'auth_required', 'authentication_failed', 'host_key_changed'].includes(raw) ? 'bad' : 'warn';
  return el('span', { class: `badge ${kind}` }, el('i', { 'aria-hidden': 'true' }),
    raw.replaceAll('_', ' '), stale && raw !== 'stale' ? ' / stale' : '');
}
export function metric(label, value, ratio = null, note = '') {
  const meter = el('div', { class: 'meter', 'aria-hidden': 'true' });
  if (Number.isFinite(ratio)) {
    const fill = el('span');
    fill.style.width = `${Math.min(100, Math.max(0, ratio))}%`;
    meter.append(fill);
  } else meter.classList.add('unknown');
  return el('div', { class: 'metric' }, el('span', { class: 'metric-label' }, label),
    el('strong', {}, value), meter, el('small', {}, note));
}
export function details(entries) {
  return el('dl', { class: 'details' }, entries.map(([label, value]) => [el('dt', {}, label), el('dd', {}, value)]));
}
export function table(headers, rows, label) {
  return el('div', { class: 'table-scroll', tabindex: '0', role: 'region', 'aria-label': label },
    el('table', {}, el('caption', { class: 'sr-only' }, label),
      el('thead', {}, el('tr', {}, headers.map(text => el('th', { scope: 'col' }, text)))), el('tbody', {}, rows)));
}
export function confirmation(title, description, actionLabel, action) {
  const trigger = document.activeElement;
  const dialog = el('dialog', { class: 'confirm-dialog', 'aria-labelledby': 'confirm-title' });
  const error = el('div');
  const accept = button(actionLabel, async () => {
    accept.disabled = true;
    try { await action(); dialog.close(); }
    catch (failure) { error.replaceChildren(notice(failure.message, 'error')); accept.disabled = false; }
  }, { class: 'danger' });
  dialog.append(el('h2', { id: 'confirm-title' }, title), el('p', {}, description), error,
    el('div', { class: 'actions' }, button('Cancel', () => dialog.close()), accept));
  dialog.addEventListener('close', () => { dialog.remove(); trigger?.focus(); });
  document.body.append(dialog);
  dialog.showModal();
}
