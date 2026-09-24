// SPDX-License-Identifier: Apache-2.0
// Read bounded host bus pages and distinguish delivery receipts from work completion.
import { allowed, getSession, request } from './api.js';
import { button, confirmation, el, errorPanel, heading, notice, panel, state, table, time } from './components.js';
import { newMessage, newRun } from './bus-form.js';

const meanings = {
  host_stored: 'Recorded by the controller.', host_uncertain: 'Dispatch began; node storage is not confirmed.', node_stored: 'Stored in the node inbox.',
  adapter_submitted: 'Accepted by the adapter; inclusion is not confirmed.',
  session_included: 'Observed in the bound runtime session.', tool_read: 'Read through the inbox tool.',
  uncertain: 'Outcome is unknown. Do not blindly resend.', failed: 'Delivery failed.', cancelled: 'Delivery cancelled.',
};

export function bus() {
  let active = true, timer, loading = false, generation = 0, runs = [], selected = null, after = 0, next = null, history = [];
  const demo = getSession().mode === 'demo', canSend = allowed('bus:send') && !demo;
  const status = el('div'), inventory = el('div', { class: 'bus-inventory' }), content = el('div');
  const refresh = button('Refresh bus', () => load());
  const actions = [refresh];
  if (canSend && allowed('bus:read')) actions.push(button('Create run', () => newRun(run => { if (active) { selected = run.id; reset(); load(); } }), { class: 'primary' }));
  const element = el('div', {}, heading('COMMUNICATION / BUS', 'Agent bus',
    'Host-owned runs, explicit recipients and durable delivery receipts.', actions),
  demo && notice('Simulation mode. Run creation and message delivery are unavailable.'), status, inventory, content);
  function reset() { after = 0; next = null; history = []; generation++; content.replaceChildren(); }
  function drawRuns() {
    if (!runs.length) { inventory.replaceChildren(state('No bus runs', 'Create a named run, then launch agents into it.')); content.replaceChildren(); return; }
    inventory.replaceChildren(panel('Runs', table(['Run', 'State', 'Agents', 'Messages', 'Created'], runs.map(run =>
      el('tr', { class: run.id === selected ? 'selected' : '' }, el('td', {}, button(run.name, () => {
        if (selected === run.id) return;
        selected = run.id; reset(); drawRuns(); readRun();
      }, { class: 'node-select', 'aria-pressed': run.id === selected ? 'true' : 'false', 'data-focus': `run-${run.id}` })),
      el('td', {}, run.state), el('td', {}, run.agent_ids.length), el('td', {}, run.message_count), el('td', {}, time(run.created_at)))), 'Bus runs')));
  }
  async function closeRun(run) {
    await request(`/bus/runs/${encodeURIComponent(run.id)}/close`, { method: 'POST', body: { confirm_close: true } });
    if (active) await load();
  }
  function drawMessages(run, messages, deliveries) {
    const actions = [];
    if (canSend && run.state === 'open') {
      if (allowed('agents:read')) actions.push(button('Send message', () => newMessage(run, () => { if (active) load(); }), { class: 'primary', 'data-focus': 'bus-send' }));
      actions.push(button('Close run', () => confirmation('Close bus run', `Close ${run.name}? The service refuses unresolved work. Retained messages remain readable.`,
        'Close exact run', () => closeRun(run)), { 'data-focus': 'bus-close' }));
    }
    const previous = button('Previous messages', () => { after = history.pop() ?? 0; readRun(); }, { disabled: !history.length, 'data-focus': 'bus-previous' });
    const forward = button('Next messages', () => { if (next != null) { history.push(after); after = next; readRun(); } }, { disabled: next == null, 'data-focus': 'bus-next' });
    content.replaceChildren(panel(`Run: ${run.name}`, [el('div', { class: 'bus-run-toolbar' }, el('code', {}, run.id), el('div', { class: 'actions' }, actions)),
      notice('A receipt confirms a delivery stage. It does not confirm that requested work is complete.'),
      messages.length ? el('ol', { class: 'bus-messages', 'aria-label': 'Run messages' }, messages.map(message => el('li', { 'data-message': message.id },
        el('div', { class: 'bus-message-heading' }, el('strong', {}, `${message.ordinal}. ${message.type}`), el('span', {}, `${message.sender_id} / sequence ${message.sequence}`), el('time', {}, time(message.created_at))),
        el('code', {}, message.id), el('pre', { class: 'bus-message-body' }, typeof message.body.text === 'string' ? message.body.text : JSON.stringify(message.body, null, 2)),
        el('p', { class: 'muted' }, `Recipients: ${message.recipient_ids.join(', ') || 'None'}`),
        message.reply_to && el('p', {}, `Reply to: ${message.reply_to}`)))) : state('No messages on this page', 'Recorded messages appear here after explicit submission.'),
      el('div', { class: 'actions' }, previous, forward)]),
    panel('Delivery receipts', deliveries.length ? table(['Message / recipient', 'Stage', 'Method', 'Detail', 'Updated'], deliveries.map(item =>
      el('tr', {}, el('td', {}, el('code', {}, item.message_id), el('small', {}, item.agent_id)),
        el('td', {}, el('strong', {}, item.state.replaceAll('-', ' ')), el('small', {}, meanings[item.state.replaceAll('-', '_')] ?? 'Inspect the recorded delivery detail.')),
        el('td', {}, item.method), el('td', {}, typeof item.detail === 'string' ? item.detail : JSON.stringify(item.detail ?? {})), el('td', {}, time(item.updated_at)))), 'Delivery receipts') :
      el('p', {}, 'No delivery receipts recorded.')));
  }
  async function readRun() {
    const run = runs.find(item => item.id === selected); if (!active || !run) return;
    const serial = ++generation, focus = element.contains(document.activeElement) ? document.activeElement.dataset.focus : null;
    try {
      const [page, receipts] = await Promise.all([request(`/bus/runs/${encodeURIComponent(run.id)}/messages?after=${after}&limit=100`),
        request(`/bus/deliveries?run_id=${encodeURIComponent(run.id)}`)]);
      if (!active || serial !== generation) return;
      next = page.next_after; drawMessages(run, page.messages, receipts.deliveries);
      if (focus) [...element.querySelectorAll('[data-focus]')].find(item => item.dataset.focus === focus)?.focus({ preventScroll: true });
    } catch (error) { if (active && serial === generation) { content.replaceChildren(errorPanel(error)); if ([401, 403].includes(error.status)) { inventory.replaceChildren(); runs = []; } } }
  }
  async function load() {
    if (!active || loading || !allowed('bus:read')) return;
    const focus = element.contains(document.activeElement) ? document.activeElement.dataset.focus : null;
    loading = true; refresh.disabled = true; clearTimeout(timer);
    try {
      const result = await request('/bus/runs'); if (!active) return;
      runs = result.runs; status.replaceChildren();
      if (!runs.some(run => run.id === selected)) { selected = runs[0]?.id ?? null; reset(); }
      drawRuns(); await readRun();
      if (active && focus && !document.querySelector('dialog[open]')) [...element.querySelectorAll('[data-focus]')].find(item => item.dataset.focus === focus)?.focus({ preventScroll: true });
    } catch (error) {
      if (active) { status.replaceChildren(errorPanel(error, load)); if ([401, 403].includes(error.status)) { runs = []; inventory.replaceChildren(); reset(); } }
    } finally { loading = false; refresh.disabled = false; if (active) timer = setTimeout(load, 5000); }
  }
  if (allowed('bus:read')) load();
  else { refresh.disabled = true; inventory.append(state('Bus access denied', 'The bus:read grant is required.')); }
  return { element, dispose() { active = false; generation++; clearTimeout(timer); } };
}
