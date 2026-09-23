// SPDX-License-Identifier: Apache-2.0
// Show authoritative per-node job results and explicitly scoped cancellation.
import { allowed, getSession, request } from './api.js';
import { announce, button, bytes, confirmation, details, el, notice, panel, table, time } from './components.js';
import { jobLogs } from './job-logs.js';

const terminalStates = new Set(['succeeded', 'failed', 'cancelled', 'interrupted']);
export function terminal(target) { return terminalStates.has(target.state); }
export function jobBadge(value) {
  const kind = value === 'succeeded' ? 'good' : ['failed', 'interrupted'].includes(value) ? 'bad' : 'warn';
  return el('span', { class: `badge ${kind}` }, String(value ?? 'unknown').replaceAll('_', ' '));
}
function reason(value) { return typeof value === 'string' ? value : value?.message ?? JSON.stringify(value); }
function limits(value) {
  if (!value) return el('p', { class: 'muted' }, 'Not yet verified');
  const names = { cpu_percent: 'CPU quota', memory_high_bytes: 'Memory high', memory_max_bytes: 'Memory maximum',
    memory_swap_max_bytes: 'Swap maximum', tasks_max: 'Process and thread maximum', runtime_seconds: 'Runtime maximum' };
  return details(Object.entries(value).map(([key, amount]) => [names[key] ?? key.replaceAll('_', ' '),
    amount == null ? 'Unknown' : key.endsWith('_bytes') ? bytes(amount) : key === 'cpu_percent' ? `${amount}% of one CPU` :
      key === 'runtime_seconds' ? `${amount} seconds` : typeof amount === 'object' ? JSON.stringify(amount) : String(amount)]));
}
export function operationDetail(onChanged) {
  let operation, selectedNode = null, logs = null, logKey = '', active = true;
  const selectedCancel = new Set();
  const header = el('div'), targets = el('div', { class: 'job-targets' }), targetDetail = el('div'), output = el('div');
  const element = el('div', {}, header, targets, targetDetail, output);

  function update(value, disconnected = false) {
    operation = value;
    const expanded = [...element.querySelectorAll('details[open]')].map(node => node.dataset.disclosure);
    const focus = element.contains(document.activeElement) ? document.activeElement.dataset.focus : null;
    if (!operation.targets.some(target => target.node_id === selectedNode)) selectedNode = operation.targets[0]?.node_id;
    for (const id of selectedCancel) {
      if (!operation.targets.some(target => target.node_id === id && !terminal(target))) selectedCancel.delete(id);
    }
    header.replaceChildren(panel('Operation detail', [el('h3', {}, operation.request.job.label), details([
      ['Operation', operation.id], ['Recorded', time(operation.created_at)], ['Last reconciled', time(operation.updated_at)],
      ['Actor', operation.actor], ['Target count', operation.targets.length],
    ]), disconnected ? notice('Service disconnected. These are cached results. Current execution state is unknown.', 'warning') : null,
    el('details', { class: 'trust-detail', 'data-disclosure': 'request' }, el('summary', { 'data-focus': 'request-summary' }, 'Submitted request'),
      el('pre', { class: 'job-request', tabindex: '0' }, JSON.stringify(operation.request, null, 2)))]));
    const canCancel = allowed('jobs:cancel') && getSession().mode !== 'demo' && !disconnected;
    const cancel = button('Cancel selected jobs', () => cancelJobs(false), { disabled: !selectedCancel.size, 'data-focus': 'cancel-jobs' });
    const force = button('Force stop selected jobs', () => cancelJobs(true), { class: 'danger-text', disabled: !selectedCancel.size, 'data-focus': 'force-jobs' });
    const rows = operation.targets.map((target, index) => {
      const check = el('input', { type: 'checkbox', checked: selectedCancel.has(target.node_id),
        'aria-label': `Select ${target.name} for cancellation`, disabled: terminal(target) || !canCancel,
        'data-focus': `cancel-${target.node_id}` });
      check.addEventListener('change', () => {
        if (check.checked) selectedCancel.add(target.node_id); else selectedCancel.delete(target.node_id);
        cancel.disabled = force.disabled = !selectedCancel.size;
      });
      return el('tr', { class: target.node_id === selectedNode ? 'selected' : '' },
        canCancel ? el('td', {}, check) : null,
        el('td', {}, button(target.name, () => { selectedNode = target.node_id; update(operation); },
          { class: 'node-select', 'aria-pressed': target.node_id === selectedNode ? 'true' : 'false', 'data-focus': `target-${index}` })),
        el('td', {}, jobBadge(target.state)), el('td', {}, target.result?.exit_code == null ? 'Unknown' : String(target.result.exit_code)),
        el('td', { class: 'wrap' }, target.error ? reason(target.error) : target.result?.reason ?? ''));
    });
    targets.replaceChildren(panel('Per-machine execution', [table([...(canCancel ? ['Select'] : []), 'Machine', 'State', 'Exit code', 'Reason'], rows, 'Job target states'),
      canCancel ? el('div', { class: 'actions job-cancel-actions' }, cancel, force) : null,
      el('p', { class: 'muted' }, 'Unknown or interrupted states never imply success. Unknown jobs retain their reservations until reconciled.')]));
    const target = operation.targets.find(item => item.node_id === selectedNode);
    if (target) drawTarget(target); else targetDetail.replaceChildren();
    for (const node of element.querySelectorAll('details')) node.open = expanded.includes(node.dataset.disclosure);
    if (focus) [...element.querySelectorAll('[data-focus]')].find(item => item.dataset.focus === focus)?.focus({ preventScroll: true });
  }
  function drawTarget(target) {
    const reservationRows = (target.reservations ?? []).map(reservation => el('tr', {}, el('td', { class: 'wrap' }, reservation.uuid),
      el('td', {}, bytes(reservation.memory_bytes))));
    const result = target.result;
    targetDetail.replaceChildren(panel('Selected machine', [el('div', { class: 'detail-heading' }, el('h3', {}, target.name), jobBadge(target.state)),
      target.session_lifetime ? notice('This job depends on the remote login session. Signing out remotely may stop it.', 'warning') : null,
      target.state === 'unknown' ? notice('Execution is uncertain. FICC will query the existing job; it will not automatically submit another copy.', 'warning') : null,
      target.error ? notice(reason(target.error), 'warning') : null,
      details([['Job identifier', target.job_id ?? 'Not assigned'], ['Result reason', result?.reason ?? 'Awaiting an authoritative result'],
        ['Exit code', result?.exit_code ?? 'Unknown'], ['Signal', result?.signal ?? 'Unknown'], ['Finished', result?.finished_at ? time(result.finished_at) : 'Not recorded'],
        ['Retained stdout', bytes(result?.stdout_bytes)], ['Retained stderr', bytes(result?.stderr_bytes)], ['Discarded output', bytes(result?.dropped_bytes)]]),
      el('div', { class: 'job-limit-grid' }, el('div', {}, el('h3', { class: 'section-label' }, 'Requested limits'), limits(target.requested_limits)),
        el('div', {}, el('h3', { class: 'section-label' }, 'Effective limits'), limits(target.effective_limits))),
      reservationRows.length ? table(['GPU UUID', 'Reserved memory'], reservationRows, 'Job GPU reservations') : el('p', { class: 'muted' }, 'No GPU reservation.'),
      reservationRows.length ? notice('GPU reservations are advisory. Other processes can still use these devices and memory.', 'warning') : null]));
    const nextKey = `${operation.id}/${target.node_id}`;
    if (nextKey !== logKey) {
      logs?.dispose(); logs = null; logKey = nextKey;
      if (allowed('jobs:logs')) { logs = jobLogs(operation.id, target.node_id); output.replaceChildren(logs.element); }
      else output.replaceChildren(notice('Output access requires the jobs:logs grant. Job results remain available.'));
    }
  }
  function cancelJobs(force) {
    const ids = [...selectedCancel], operationId = operation.id;
    confirmation(force ? 'Force stop these jobs?' : 'Cancel these jobs?',
      `${force ? 'Force stop' : 'Request a graceful stop for'} ${ids.length} selected FICC jobs. Other remote processes are not selected.`,
      force ? 'Confirm force stop' : 'Confirm cancellation', async () => {
        const result = await request(`/operations/${encodeURIComponent(operationId)}/cancel`, { method: 'POST', body: { node_ids: ids, force } });
        if (!active) return;
        selectedCancel.clear(); update(result); onChanged(result); announce('Cancellation intent recorded');
      });
  }
  return { element, update, dispose() { active = false; logs?.dispose(); } };
}
