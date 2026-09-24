// SPDX-License-Identifier: Apache-2.0
// Coordinate two registered locations and durable file operations.
import { allowed, getSession, request } from './api.js';
import { button, el, errorPanel, heading, notice, panel, state, table } from './components.js';
import { fileAction, transferPreview } from './file-actions.js';
import { filePane } from './file-pane.js';
import { fileTransfers } from './file-transfers.js';

export function files() {
  let active = true, left, right, transfers, timer, loading = false;
  const demo = getSession().mode === 'demo';
  const status = el('div'), locations = el('div'), history = el('div'), transferArea = el('div');
  const element = el('div', {}, heading('STORAGE / FILES', 'Files', 'Browse registered locations, verify transfers and confirm exact file changes.'),
    demo ? notice('Simulation mode. Live file changes and transfers are unavailable.') : null,
    el('details', { class: 'file-policy' }, el('summary', {}, 'File access boundaries'),
      el('p', {}, 'Registered roots limit API access. Other programs in the same account are trusted; a shell can bypass these limits. An opened object may remain accessible if another program moves it.')),
    status, locations, transferArea, history);
  function refresh() { left?.refresh(); right?.refresh(); }
  function recorded() { refresh(); operations(); }
  function action(kind, pane) { fileAction(kind, pane, recorded, (record, selected) => transfers.received(record, selected)); }
  function copy(source, destination) {
    const from = source.value(), to = destination.value();
    if (!from.entries.length || from.entries.length > 64 || from.entries.some(entry => entry.kind !== 'file')) {
      status.replaceChildren(notice('Select 1 to 64 ordinary source files.', 'warning')); return;
    }
    if (!to.ready || !to.root?.available || !to.root.actions.includes('write') || !allowed('files:write')) {
      status.replaceChildren(notice('The destination requires a writable registered root.', 'warning')); return;
    }
    status.replaceChildren(); transferPreview('copy', from, to, record => transfers.received(record));
  }
  async function load() {
    locations.replaceChildren(state('Loading registered roots', 'Reading available file locations and grants.'));
    try {
      const [{ roots }, inventory] = await Promise.all([request('/file-roots'), allowed('nodes:read') ? request('/nodes') : Promise.resolve({ nodes: [] })]);
      if (!active) return;
      if (!roots.length) {
        locations.replaceChildren(state('No registered file roots', 'Register an existing directory with ficc root-add in the local command line. Only explicitly registered roots appear here.')); return;
      }
      left = filePane('Left', roots, inventory.nodes, action, demo); right = filePane('Right', roots, inventory.nodes, action, demo);
      locations.replaceChildren(el('div', { class: 'file-panes' }, left.element, right.element),
        el('div', { class: 'actions file-copy-actions' },
          button('Copy left to right', () => copy(left, right), { disabled: demo || !allowed('files:write') }),
          button('Copy right to left', () => copy(right, left), { disabled: demo || !allowed('files:write') })));
      transfers = fileTransfers(demo, refresh); transferArea.replaceChildren(transfers.element); operations();
    } catch (error) { if (active) locations.replaceChildren(errorPanel(error, load)); }
  }
  async function operations() {
    if (!active || loading) return;
    loading = true; clearTimeout(timer);
    try {
      const result = await request('/file-operations');
      if (!active) return;
      const focus = history.contains(document.activeElement) ? document.activeElement.dataset.focus : null;
      history.replaceChildren(result.operations.length ? panel('Recorded file changes', [table(['Action', 'State', 'Per-entry results', 'Recovery'],
        result.operations.map(operation => el('tr', {}, el('td', {}, operation.action), el('td', {}, operation.state),
          el('td', {}, operation.items.map(item => el('p', { class: 'wrap' }, `${item.name ?? 'Entry'}: ${item.state}${item.error ? `: ${item.error.message ?? item.error}` : ''}`))),
          el('td', {}, operation.state === 'unknown' && !demo && allowed(`files:${['mkdir', 'rename'].includes(operation.action) ? 'write' : operation.action}`) ?
            button('Check recorded outcome', async () => {
              try {
                await request(`/file-operations/${encodeURIComponent(operation.id)}/reconcile`, { method: 'POST', body: {} });
                status.replaceChildren(notice('Recorded outcome checked. An unresolved result remains unknown; this does not repeat the file change.')); recorded();
              } catch (error) { if (active) status.replaceChildren(errorPanel(error), notice('The recorded file outcome remains unresolved. Do not repeat the change.', 'warning')); }
            }, { 'data-focus': `reconcile-operation-${operation.id}` }) : null))), 'File operation results')]) :
        state('No recorded file changes', 'Mode, name and deletion results appear here, with separate outcomes for each entry.'));
      if (focus) [...history.querySelectorAll('[data-focus]')].find(item => item.dataset.focus === focus)?.focus({ preventScroll: true });
    } catch (error) { if (active) history.replaceChildren(errorPanel(error, operations)); }
    finally { loading = false; if (active) timer = setTimeout(operations, 4000); }
  }
  if (allowed('files:read')) load();
  else locations.append(state('File access denied', 'The files:read grant is required to browse registered locations.'));
  return { element, dispose() { active = false; clearTimeout(timer); left?.dispose(); right?.dispose(); transfers?.dispose(); } };
}
