// SPDX-License-Identifier: Apache-2.0
// Reconcile project workload state and discard data when ownership changes.
import { allowed, getSession, request } from './api.js';
import { button, el, errorPanel, heading, notice, panel, state, table, time } from './components.js';
import { workloadDetail } from './workloads-detail.js';
import { workloadForm } from './workloads-form.js';
import { words } from './workloads-model.js';
import { offerView } from './workloads-offers.js';

export function workloads() {
  const session = getSession(), controller = new AbortController();
  let active = true, loading = false, timer, jobs = [], offers = [], selected = null, detail, form, available = false;
  let inventoryKey = '', offersKey = '', epoch = 0, dataVersion = 0;
  const status = el('div'), inventory = el('div'), selection = el('div'), offerStatus = el('div'), usage = el('div');
  const offered = offerView();
  const refresh = button('Refresh workloads', load);
  const submit = button('New workload', () => {
    if (valid() && available) form = workloadForm(offers.filter(value =>
      value.snapshot.offer.projects.includes(session.principal.project_id)), send, received, valid);
  }, { class: 'primary', disabled: true });
  const element = el('div', { class: 'workloads' }, heading('EXECUTION / CONTRIBUTORS', 'Contributor workloads',
    'Queue container computation within approved runtimes and local resource offers.',
    [refresh, allowed('jobs:execute') && allowed('contributors:read') && session.mode !== 'demo' ? submit : null]),
    notice('Use workloads for bounded batch computation on contributor machines. Local owners control availability. Loss of authority stops lease renewal; a disconnected executor can leave an unknown outcome. Retained output consumes storage until explicitly released.'),
    status, usage, inventory, selection, offerStatus, allowed('contributors:read') ? offered.element :
      notice('Contributor offers require the contributors:read grant.'));
  function valid() { return active && getSession() === session; }
  function clear() {
    epoch++;
    jobs = []; offers = []; available = false; selected = null; inventoryKey = ''; offersKey = '';
    form?.dispose(); form = null; detail?.dispose(); detail = null;
    inventory.replaceChildren(); selection.replaceChildren(); usage.replaceChildren(); offered.update([]); submit.disabled = true;
    for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  }
  async function send(path, options = {}) {
    if (!valid()) throw new Error('This project session is no longer active.');
    const started = epoch;
    try {
      const result = await request(path, { ...options, signal: controller.signal });
      if (!valid() || started !== epoch) throw new Error('This workload view changed while the request was pending.');
      return result;
    }
    catch (error) {
      if (valid() && ([401, 403, 404].includes(error.status) || ['project_changed', 'session_changed'].includes(error.code))) {
        clear(); status.replaceChildren(errorPanel(error, load));
      }
      throw error;
    }
  }
  function received(job) {
    if (!valid()) return;
    dataVersion++;
    if (job) { selected = job.id; jobs = [job, ...jobs.filter(value => value.id !== job.id)]; }
    else { jobs = jobs.filter(value => value.id !== selected); selected = null; }
    draw(); void load();
  }
  function draw(enabled = available) {
    if (!jobs.some(value => value.id === selected)) selected = jobs[0]?.id || null;
    const binding = JSON.stringify([jobs, selected]);
    if (binding !== inventoryKey) {
      inventoryKey = binding;
      const focus = inventory.contains(document.activeElement) ? document.activeElement.dataset.workload : null;
      inventory.replaceChildren(jobs.length ? panel('Project queue', [
        el('p', { class: 'muted' }, `${jobs.length} retained workloads. Select a record to inspect its attempt and output.`),
        table(['Workload', 'State / reason', 'Attempt / node', 'Updated'], jobs.map(job =>
          el('tr', { 'aria-selected': selected === job.id ? 'true' : 'false' },
            el('td', {}, button(job.request.job.name, () => { selected = job.id; draw(); },
              { 'data-workload': job.id, 'aria-pressed': selected === job.id ? 'true' : 'false' }),
              el('small', { class: 'cell-note' }, job.id)),
            el('td', {}, el('span', { class: `badge ${job.state === 'succeeded' ? 'good' : ['failed', 'unknown'].includes(job.state) ? 'bad' : 'warn'}` }, words(job.state)),
              el('small', { class: 'cell-note' }, words(job.reason))),
            el('td', {}, job.attempt ? `Generation ${job.generation} / ${words(job.attempt.state)}` : 'Not assigned',
              el('small', { class: 'cell-note' }, job.attempt?.node_id || `${job.request.node_ids.length} candidates`)),
            el('td', {}, time(job.updated_at)))), 'Project workloads')]) :
        state('No contributor workloads', 'Submit a workload using an approved local offer. Requests are retained in this project.'));
      if (focus) [...inventory.querySelectorAll('[data-workload]')].find(value => value.dataset.workload === focus)?.focus({ preventScroll: true });
    }
    if (selected) {
      if (!detail) { detail = workloadDetail(send, received, valid); selection.replaceChildren(detail.element); }
      detail.update(jobs.find(value => value.id === selected), enabled);
    } else { detail?.dispose(); detail = null; selection.replaceChildren(); }
  }
  async function load() {
    if (!valid() || loading) return;
    const started = dataVersion;
    loading = true; refresh.disabled = true; clearTimeout(timer);
    try {
      const result = await send('/workloads');
      if (!valid() || started !== dataVersion) return;
      jobs = result.workloads; available = result.configured && !result.suspended && !result.scheduler_error && session.mode !== 'demo';
      if (result.usage) {
        const value = result.usage, held = value.reservations;
        usage.replaceChildren(el('details', {}, el('summary', {}, `Project usage: ${value.attempts} retained attempts / ${value.unreleased_attempts} unreleased`),
          table(['Measure', 'Recorded value'], [
            ['Reported outcomes', Object.entries(value.states).map(([key, count]) => `${words(key)}: ${count}`).join(' / ') || 'None'],
            ['CPU reservation (millicores)', held.cpu_millis], ['Memory reservation (bytes)', held.memory_bytes],
            ['Storage reservation (bytes)', held.storage_bytes], ['GPU device reservations', value.reserved_gpu_devices],
            ['Declared input bytes across attempts', value.declared_input_bytes],
            ['Reported stdout bytes', value.reported_stdout_bytes], ['Reported stderr bytes', value.reported_stderr_bytes],
          ].map(([label, count]) => el('tr', {}, el('th', { scope: 'row' }, label), el('td', {}, String(count)))), 'Project attempt usage'),
          el('p', { class: 'muted' }, 'Totals cover retained attempts in this project, including retries. Reservations include completed or uncertain attempts until release; they are resource ceilings, not measured utilization. Removing records reduces these totals. This is not a lifetime billing meter.')));
      }
      status.replaceChildren(...(!result.configured ? [notice('Workload scheduling is not configured. The administrator must install and enable a scheduler.')] :
        result.suspended ? [notice('Dispatch is suspended. The installation administrator must resolve the suspension.')] :
          result.scheduler_error ? [notice('The dispatcher reported an error. Refresh after the administrator restores it.', 'error')] : []));
      draw(available);
      if (allowed('contributors:read')) {
        const result = await send('/workload-offers');
        if (!valid()) return;
        offers = result.offers;
        const binding = JSON.stringify(offers);
        if (binding !== offersKey) { offered.update(offers); offersKey = binding; }
        offerStatus.replaceChildren();
      }
      submit.disabled = !available || !offers.some(value => value.snapshot.offer.projects.includes(session.principal.project_id));
    } catch (error) {
      if (!valid()) return;
      available = false; submit.disabled = true;
      if (![401, 403, 404].includes(error.status)) {
        status.replaceChildren(errorPanel(error, load), notice('Displayed records may be stale. Refresh before taking an action.'));
        draw(false);
      }
    } finally {
      loading = false; refresh.disabled = false;
      if (valid()) timer = setTimeout(load, 5000);
    }
  }
  inventory.append(state('Loading workloads', 'Reading this project queue.')); void load();
  return { element, dispose() { active = false; clearTimeout(timer); controller.abort(); clear(); element.replaceChildren(); } };
}
