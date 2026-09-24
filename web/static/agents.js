// SPDX-License-Identifier: Apache-2.0
// Inspect exact managed agent identities and open their native terminal sessions.
import { allowed, getSession, request } from './api.js';
import { button, confirmation, details, el, errorPanel, heading, notice, panel, state, table, time } from './components.js';
import { newAgent, rebindAgent } from './agent-form.js';

export function agents() {
  let active = true, loading = false, timer, records = [], selected;
  const status = el('div'), inventory = el('div', { class: 'agent-inventory' }), selection = el('div');
  const refresh = button('Refresh agents', load);
  const demo = getSession().mode === 'demo';
  const actions = [refresh];
  if (!demo && allowed('agents:execute') && allowed('agents:read') && allowed('bus:read') && allowed('bus:send')) {
    actions.push(button('Launch agent', () => newAgent(record => { if (active) { selected = record.id; load(); } }), { class: 'primary' }));
  }
  const element = el('div', {}, heading('EXECUTION / AGENTS', 'Coding agents',
    'Registered commands, native terminals and explicit message delivery across machines.', actions),
  demo && notice('Simulation mode. Agent launch and control are unavailable.'), status, inventory, selection);
  function draw() {
    const focus = element.contains(document.activeElement) ? document.activeElement.dataset.focus : null;
    if (!records.length) {
      inventory.replaceChildren(state('No managed agents', 'Register an installed OMP, Codex or generic command with the local FICC CLI, create a bus run, then launch an agent.'));
      selection.replaceChildren(); return;
    }
    if (!records.some(item => item.id === selected)) selected = records[0].id;
    inventory.replaceChildren(panel('Agent processes', table(['Agent / machine', 'Adapter', 'Working directory', 'Delivery', 'State'], records.map(item =>
      el('tr', { class: item.id === selected ? 'selected' : '' },
        el('td', {}, button(item.label, () => { selected = item.id; draw(); }, { class: 'node-select', 'data-focus': item.id,
          'aria-pressed': item.id === selected ? 'true' : 'false' }), el('small', {}, item.node_name ?? item.node_id)),
        el('td', {}, item.adapter), el('td', { class: 'agent-path' }, item.workspace), el('td', {}, item.delivery_method), el('td', {}, item.state))), 'Agent processes')));
    const item = records.find(record => record.id === selected), controls = [];
    if (item.terminal_id && allowed('terminals:read') && allowed('terminals:execute') && !demo) controls.push(button('Open terminal', () =>
      window.dispatchEvent(new CustomEvent('ficc-open-terminal', { detail: { terminalId: item.terminal_id } })), { 'data-focus': 'agent-terminal' }));
    if (!demo && allowed('agents:execute')) {
      controls.push(button('Reconcile agent', () => mutate(item, 'reconcile', {}), { 'data-focus': 'agent-reconcile' }));
      if (['omp', 'codex'].includes(item.adapter)) controls.push(button('Bind runtime session', () => rebindAgent(item, () => { if (active) load(); }), { 'data-focus': 'agent-rebind' }));
    }
    if (!demo && allowed('agents:stop') && !['stopped', 'exited', 'failed'].includes(item.state)) controls.push(button('Stop agent', () => confirmation(
      'Stop managed agent', `Stop ${item.label} on ${item.node_name ?? item.node_id}? Its recorded process and native terminal will close.`, 'Stop exact agent', () => mutate(item, 'stop', { confirm_stop: true }, true)), { class: 'danger', 'data-focus': 'agent-stop' }));
    selection.replaceChildren(panel('Agent identity', [details([['Agent ID', item.id], ['Profile ID', item.profile_id], ['Run ID', item.run_id],
      ['Runtime session', item.runtime_session_id ?? 'Not bound'], ['Observed session', item.observed_session_id ?? 'Not reported'], ['Version', item.version ?? 'Unknown'],
      ['Terminal ID', item.terminal_id ?? 'Unavailable'], ['Last contact', time(item.last_contact)]]),
    item.error && notice(typeof item.error === 'string' ? item.error : JSON.stringify(item.error), 'warning'), el('div', { class: 'actions' }, controls)]));
    const rejected = Array.isArray(item.outbox_rejections) ? item.outbox_rejections.slice(-16) : [];
    if (rejected.length) selection.append(panel('Rejected replies', [
      notice('These replies were refused by the controller. Their original content remains on the node.', 'warning'),
      table(['Reply key', 'Reason', 'Detail', 'Rejected'], rejected.map(reply => el('tr', {},
        el('td', {}, el('code', {}, reply.id)), el('td', {}, reply.code), el('td', {}, reply.detail),
        el('td', {}, time(reply.rejected_at)))), 'Rejected replies'),
    ]));
    if (focus) [...element.querySelectorAll('[data-focus]')].find(item => item.dataset.focus === focus)?.focus({ preventScroll: true });
  }
  async function mutate(item, action, body, propagate = false) {
    try { await request(`/agents/${encodeURIComponent(item.id)}/${action}`, { method: 'POST', body }); if (active) await load(); }
    catch (error) { if (propagate) throw error; if (active) status.replaceChildren(errorPanel(error)); }
  }
  async function load() {
    if (!active || loading || !allowed('agents:read')) return;
    loading = true; refresh.disabled = true; clearTimeout(timer);
    try { const result = await request('/agents'); if (active) { records = result.agents; status.replaceChildren(); draw(); } }
    catch (error) {
      if (active) { status.replaceChildren(errorPanel(error, load)); if ([401, 403].includes(error.status)) { records = []; inventory.replaceChildren(); selection.replaceChildren(); } }
    } finally { loading = false; refresh.disabled = false; if (active) timer = setTimeout(load, 4000); }
  }
  if (allowed('agents:read')) load();
  else { refresh.disabled = true; inventory.append(state('Agent access denied', 'The agents:read grant is required.')); }
  return { element, dispose() { active = false; clearTimeout(timer); } };
}
