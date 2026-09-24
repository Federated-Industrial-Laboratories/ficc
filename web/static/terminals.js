// SPDX-License-Identifier: Apache-2.0
// Present recorded terminal lifetimes beside independent machine workspaces.
import { allowed, getSession, request } from './api.js';
import { button, confirmation, el, errorPanel, heading, notice, panel, state, table, time } from './components.js';
import { newTerminal } from './terminal-form.js';
import { terminalWorkspace } from './terminal-workspace.js';

export function terminals() {
  let active = true, loading = false, timer, records = [];
  const demo = getSession().mode === 'demo';
  const history = el('div'), status = el('div');
  const canCreate = !demo && allowed('terminals:execute') && allowed('nodes:read');
  const workspace = terminalWorkspace({ canCreate, changed: () => { if (active) { draw(); load(); } },
    create: (callback, nodeId) => newTerminal(record => { if (!active) return; received(record, false); callback(record); }, nodeId) });
  const refresh = button('Refresh terminals', load);
  const actions = [refresh];
  if (canCreate) actions.push(button('New terminal', () => newTerminal(received), { class: 'primary' }));
  const element = el('div', {}, heading('INTERACTIVE / SSH', 'Terminals', 'Independent terminal tiles, grouped by machine. Every attachment is explicit.', actions),
    demo ? notice('Simulation mode. Live terminal creation, attachment and stopping are unavailable.') : null,
    notice('Machine tabs keep connections open. Leaving Terminals detaches every pane. Ephemeral shells close; tmux sessions can continue. Input is never recorded or replayed.'), status, workspace.element, history);
  function received(record, open = true) {
    if (!active) return;
    records = [record, ...records.filter(item => item.id !== record.id)]; draw(); if (open) workspace.attach(record); load();
  }
  async function openTerminal(id) {
    if (!active || demo || !allowed('terminals:read') || !allowed('terminals:execute') || typeof id !== 'string') return;
    try {
      let record = records.find(item => item.id === id);
      if (!record) {
        const result = await request('/terminals');
        if (!active) return;
        records = result.terminals; draw(); record = records.find(item => item.id === id);
      }
      if (!record || (!workspace.attached(id) && (['exited', 'stopped', 'interrupted', 'unknown'].includes(record.state) ||
          (record.mode !== 'tmux' && !['new', 'connecting'].includes(record.state))))) {
        status.replaceChildren(notice('This terminal is unavailable for attachment. Check its recorded session state.', 'warning')); return;
      }
      workspace.attach(record);
    } catch (error) {
      if (!active) return;
      status.replaceChildren(errorPanel(error));
      if ([401, 403].includes(error.status)) { records = []; history.replaceChildren(); workspace.clear(); }
    }
  }
  function draw() {
    const focus = element.contains(document.activeElement) ? document.activeElement.dataset.focus : null;
    workspace.records(records);
    if (!records.length) { history.replaceChildren(state('No terminals', 'Create a terminal to open an ephemeral shell or a reattachable tmux session.')); return; }
    history.replaceChildren(panel('Recorded sessions', [table(['Label', 'Machine / account', 'Lifetime', 'State', 'Created', 'Actions'], records.map(record => {
      const terminal = ['exited', 'stopped', 'interrupted'].includes(record.state);
      const attached = workspace.attached(record.id);
      const canAttach = !demo && allowed('terminals:execute') && !terminal && record.state !== 'unknown' && !attached &&
        (record.mode === 'tmux' || ['new', 'connecting'].includes(record.state));
      const controls = [];
      if (canAttach) controls.push(button(record.mode === 'tmux' || record.state === 'detached' ? 'Reattach' : 'Attach', () => workspace.attach(record), { 'data-focus': `attach-${record.id}` }));
      if (!demo && allowed('terminals:execute') && record.mode === 'tmux' && record.state === 'unknown') controls.push(button('Check recorded session', async () => {
        try {
          const checked = await request(`/terminals/${encodeURIComponent(record.id)}/reconcile`, { method: 'POST', body: {} });
          if (!active) return;
          records = records.map(item => item.id === record.id ? checked : item); draw();
          status.replaceChildren(notice('Recorded session checked. Reattach is a separate action; this check does not create or attach a shell.'));
        } catch (error) { if (active) status.replaceChildren(errorPanel(error), notice('The session outcome is unresolved. Check the same record again before opening a replacement.', 'warning')); }
      }, { 'data-focus': `reconcile-${record.id}` }));
      if (!demo && allowed('terminals:stop') && !terminal) controls.push(button('Stop session', () => confirmation('Stop terminal session',
        `Stop ${record.label} on ${record.node_name} as ${record.account}? ${record.mode === 'tmux' ? 'This stops the remote tmux session and its programs.' : 'This closes the owned shell connection.'}`,
        'Confirm stop', async () => {
          await request(`/terminals/${encodeURIComponent(record.id)}/stop`, { method: 'POST', body: { confirm_stop: true } });
          if (!active) return;
          workspace.remove(record.id);
          await load();
        }), { class: 'danger', 'data-focus': `stop-${record.id}` }));
      return el('tr', { class: attached ? 'selected' : '' }, el('td', {}, record.label),
        el('td', {}, record.node_name, el('small', { class: 'account-line' }, record.account)),
        el('td', {}, record.mode === 'tmux' ? 'Tmux / reattachable' : 'Ephemeral'),
        el('td', {}, record.state, record.error ? el('p', { class: 'muted wrap' }, record.error.message ?? record.error) : null),
        el('td', {}, time(record.created_at)), el('td', {}, el('div', { class: 'actions' }, controls)));
    }), 'Terminal sessions')]));
    if (focus) [...element.querySelectorAll('[data-focus]')].find(item => item.dataset.focus === focus)?.focus({ preventScroll: true });
  }
  async function load() {
    if (!active || loading || !allowed('terminals:read')) return;
    loading = true; refresh.disabled = true; clearTimeout(timer);
    try {
      const result = await request('/terminals');
      if (active) { records = result.terminals; status.replaceChildren(); draw(); }
    } catch (error) {
      if (!active) return;
      status.replaceChildren(errorPanel(error, load));
      if ([401, 403].includes(error.status)) { records = []; history.replaceChildren(); workspace.clear(); }
    } finally { loading = false; refresh.disabled = false; if (active) timer = setTimeout(load, 4000); }
  }
  if (allowed('terminals:read')) { history.append(state('Loading terminals', 'Reading recorded sessions.')); load(); }
  else { refresh.disabled = true; history.append(state('Terminal access denied', 'The terminals:read grant is required to inspect sessions.')); }
  function leaving() { workspace.clear(); if (active) draw(); }
  window.addEventListener('pagehide', leaving);
  return { element, openTerminal, dispose() { active = false; clearTimeout(timer); window.removeEventListener('pagehide', leaving); workspace.dispose(); } };
}
