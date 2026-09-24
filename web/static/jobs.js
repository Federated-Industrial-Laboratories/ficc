// SPDX-License-Identifier: Apache-2.0
// Reconcile job history without resubmitting work or hiding partial outcomes.
import { allowed, getSession, request } from './api.js';
import { button, el, errorPanel, heading, notice, panel, state, table, time } from './components.js';
import { newJob } from './job-form.js';
import { jobBadge, operationDetail } from './job-detail.js';

export function jobs() {
  let active = true, loading = false, timer, operations = [], selected = null, detail;
  const demo = getSession().mode === 'demo';
  const status = el('div'), inventory = el('div', { class: 'jobs-history' }), selection = el('div');
  const update = button('Refresh jobs', load);
  const actions = [update];
  if (allowed('jobs:execute') && allowed('nodes:read') && !demo) actions.push(button('New job', () => newJob(received), { class: 'primary' }));
  const element = el('div', {}, heading('EXECUTION / JOBS', 'Managed jobs',
    'Submit bounded work, inspect per-machine results, and recover after a disconnect.', actions),
  demo ? notice('Simulation mode. Job submission, helper upgrades and cancellation are unavailable.') : null,
  notice('Closing the browser or stopping the controller does not cancel remote jobs. Remote login lifetime and node shutdown can still affect execution.'),
  status, inventory, selection);
  function received(operation) {
    selected = operation.id;
    operations = [operation, ...operations.filter(item => item.id !== operation.id)].slice(0, 200);
    draw(); load();
  }
  function draw(disconnected = false) {
    const focus = element.contains(document.activeElement) ? document.activeElement.dataset.focus : null;
    if (!operations.length) {
      inventory.replaceChildren(state('No managed jobs', 'Recorded jobs appear here. Start a job to inspect its limits, output and result.'));
      selection.replaceChildren(); detail?.dispose(); detail = null; return;
    }
    if (!operations.some(operation => operation.id === selected)) selected = operations[0].id;
    inventory.replaceChildren(panel('Recent operations', [el('p', { class: 'muted' }, 'Up to 200 operations. Each machine keeps its own execution state.'),
      table(['Job', 'Recorded', 'Machines', 'Per-machine states'], operations.map(operation => {
        const counts = new Map();
        for (const target of operation.targets) counts.set(target.state, (counts.get(target.state) ?? 0) + 1);
        return el('tr', { class: selected === operation.id ? 'selected' : '' },
          el('td', {}, button(operation.request.job.label, () => { selected = operation.id; draw(); },
            { class: 'node-select', 'aria-pressed': selected === operation.id ? 'true' : 'false', 'data-focus': `operation-${operation.id}` })),
          el('td', { class: 'numeric' }, time(operation.created_at)), el('td', {}, operation.targets.length),
          el('td', {}, el('div', { class: 'job-states' }, [...counts].map(([value, count]) => el('span', {}, jobBadge(value), ` ${count}`)))));
      }), 'Managed operations')]));
    if (!detail) { detail = operationDetail(received); selection.replaceChildren(detail.element); }
    detail.update(operations.find(operation => operation.id === selected), disconnected);
    if (focus) [...element.querySelectorAll('[data-focus]')].find(item => item.dataset.focus === focus)?.focus({ preventScroll: true });
  }
  async function load() {
    if (!active || loading || !allowed('jobs:read')) return;
    loading = true; update.disabled = true; clearTimeout(timer);
    try {
      const result = await request('/operations');
      if (!active) return;
      operations = result.operations; status.replaceChildren(); draw();
      document.querySelector('#connection').textContent = demo ? 'Simulation service connected' : 'Local service connected';
    } catch (error) {
      if (!active) return;
      status.replaceChildren(errorPanel(error, load));
      if (error.status === 0 && operations.length) draw(true);
      if ([401, 403].includes(error.status)) {
        operations = []; detail?.dispose(); detail = null; inventory.replaceChildren(); selection.replaceChildren();
      }
      document.querySelector('#connection').textContent = error.status === 0 ? 'Local service disconnected' : 'Request unavailable';
    } finally {
      loading = false; update.disabled = false;
      if (active) timer = setTimeout(load, 4000);
    }
  }
  if (allowed('jobs:read')) { inventory.append(state('Loading jobs', 'Reading recorded operations.')); load(); }
  else { update.disabled = true; inventory.append(state('Job access denied', 'This account needs the jobs:read grant to inspect managed jobs.')); }
  return { element, dispose() { active = false; clearTimeout(timer); detail?.dispose(); } };
}
