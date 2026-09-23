// SPDX-License-Identifier: Apache-2.0
// Prepare bounded jobs and confirm an immutable, expiring operation preview.
import { request } from './api.js';
import { announce, button, details, el, errorPanel, notice, state, table, time } from './components.js';
import { jobNodes } from './job-nodes.js';

export function newJob(onSubmitted) {
  const trigger = document.activeElement;
  let active = true, busy = false, expiryTimer;
  const dialog = el('dialog', { class: 'job-dialog', 'aria-labelledby': 'job-title' });
  const close = button('Close', () => dialog.close(), { class: 'quiet' });
  const content = el('div');
  dialog.append(el('div', { class: 'dialog-heading' }, el('h2', { id: 'job-title' }, 'New managed job'), close), content);
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { active = false; clearTimeout(expiryTimer); dialog.remove(); trigger?.focus(); });
  document.body.append(dialog); dialog.showModal();
  function working(value) { busy = value; close.disabled = value; }

  async function load() {
    content.replaceChildren(state('Loading target machines', 'Reading the enrolled inventory.'));
    try {
      const { nodes } = await request('/nodes');
      if (!active) return;
      if (!nodes.length) { content.replaceChildren(state('No target machines', 'Enroll a machine in Overview before you create a job.')); return; }
      compose(nodes);
    } catch (error) { if (active) content.replaceChildren(errorPanel(error, load)); }
  }
  function compose(nodes) {
    const targets = jobNodes(nodes);
    const label = el('input', { id: 'job-label', maxlength: 80, required: true, autocomplete: 'off' });
    const mode = el('select', { id: 'job-mode' }, el('option', { value: 'argv' }, 'Executable and arguments (JSON array)'),
      el('option', { value: 'shell' }, 'Shell script (/bin/sh -lc)'));
    const command = el('textarea', { id: 'job-command', rows: 4, required: true, maxlength: 32768, spellcheck: false },
      '["/usr/bin/printf", "Hello from FICC\\n"]');
    const commandLabel = el('label', { for: 'job-command' }, 'Executable and arguments');
    mode.addEventListener('change', () => {
      commandLabel.textContent = mode.value === 'shell' ? 'Shell script' : 'Executable and arguments';
      command.value = mode.value === 'shell' ? "printf 'Hello from FICC\\n'" : '["/usr/bin/printf", "Hello from FICC\\n"]';
    });
    const cwd = el('input', { id: 'job-cwd', maxlength: 4096, placeholder: 'Remote home directory', autocomplete: 'off' });
    const env = el('textarea', { id: 'job-env', rows: 2, maxlength: 16384, spellcheck: false }, '{}');
    const specs = [
      ['cpu_percent', 'CPU quota (% of one CPU)', 100, 1, 6400],
      ['memory_high_bytes', 'Memory high (MiB)', 192, 16, 1048576],
      ['memory_max_bytes', 'Memory maximum (MiB)', 256, 32, 1048576],
      ['memory_swap_max_bytes', 'Swap maximum (MiB)', 0, 0, 1048576],
      ['tasks_max', 'Process and thread maximum', 32, 4, 4096],
      ['runtime_seconds', 'Runtime maximum (seconds)', 300, 1, 86400],
    ];
    const fields = specs.map(([key, title, value, min, max]) => {
      const input = el('input', { id: `job-${key}`, type: 'number', required: true, value, min, max, step: 1 });
      return { key, input, element: el('div', {}, el('label', { for: input.id }, title), input) };
    });
    const lifetime = el('input', { id: 'job-lifetime', type: 'checkbox' });
    const error = el('div');
    const preview = el('button', { type: 'submit', class: 'primary' }, 'Preview job');
    const form = el('form', { onsubmit: async event => {
      event.preventDefault(); if (busy) return;
      error.replaceChildren();
      try {
        const { node_ids, gpu_reservations } = targets.value();
        const argv = mode.value === 'shell' ? ['/bin/sh', '-lc', command.value] : JSON.parse(command.value);
        if (!Array.isArray(argv) || !argv.length || argv.length > 128 || argv.some(item => typeof item !== 'string')) {
          throw new Error('Enter a JSON array of 1 to 128 strings, starting with the executable.');
        }
        if (!argv[0] || argv.some(item => new TextEncoder().encode(item).length > 4096)) {
          throw new Error('The executable cannot be empty. Each argument must fit within 4096 bytes.');
        }
        if (argv.some(item => item.includes('\0')) || new TextEncoder().encode(JSON.stringify(argv)).length > 32768) {
          throw new Error('Arguments must fit within 32 KiB and cannot contain NUL.');
        }
        const environment = JSON.parse(env.value);
        if (!environment || Array.isArray(environment) || typeof environment !== 'object' || Object.entries(environment).some(([key, value]) =>
          !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key) || key === 'CUDA_VISIBLE_DEVICES' || typeof value !== 'string' || value.includes('\0'))) {
          throw new Error('Environment must be a JSON object of valid names and string values. CUDA_VISIBLE_DEVICES is reserved.');
        }
        if (Object.keys(environment).length > 64) throw new Error('Use at most 64 environment variables.');
        if (cwd.value && !cwd.value.startsWith('/')) throw new Error('Use an absolute working directory, or leave it blank for the remote home.');
        const limits = Object.fromEntries(fields.map(({ key, input }) => [key,
          Number(input.value) * (key.endsWith('_bytes') ? 1048576 : 1)]));
        if (limits.memory_high_bytes > limits.memory_max_bytes) throw new Error('Memory high cannot exceed the memory maximum.');
        working(true); preview.disabled = true;
        const result = await request('/operation-previews', { method: 'POST', body: {
          action: 'job.submit', node_ids, job: { label: label.value.trim(), argv, cwd: cwd.value, env: environment,
            limits, allow_session_lifetime: lifetime.checked, gpu_reservations },
        } });
        if (active) confirm(result, () => { content.replaceChildren(form); preview.focus(); });
      } catch (failure) { if (active) error.replaceChildren(notice(failure.message, 'error')); }
      finally { working(false); preview.disabled = false; }
    } }, notice('Execution grants full authority in each remote SSH account. Limits and GPU visibility do not sandbox the program.', 'warning'),
    targets.element, el('label', { for: label.id }, 'Job label / purpose'), label,
    el('label', { for: mode.id }, 'Command mode'), mode, commandLabel, command,
    el('label', { for: cwd.id }, 'Working directory'), cwd,
    el('details', { class: 'trust-detail' }, el('summary', {}, 'Environment variables'),
      el('label', { for: env.id }, 'Environment (JSON object)'), env,
      el('p', { class: 'muted' }, 'Only the supplied values are sent. GPU visibility follows the selected reservations.')),
    el('fieldset', { class: 'job-fieldset' }, el('legend', {}, 'Required resource limits'),
      el('div', { class: 'job-limit-grid' }, fields.map(field => field.element))),
    el('label', { class: 'check-label', for: lifetime.id }, lifetime,
      'Allow a job that depends on the remote login session. It may stop when that user signs out.'),
    el('p', { class: 'muted' }, 'Unchecked: each node must support logout persistence. Controller restart and browser close do not cancel a running job.'),
    error, el('div', { class: 'actions' }, preview));
    content.replaceChildren(form); label.focus();
  }
  function confirm(preview, back) {
    clearTimeout(expiryTimer);
    const idempotencyKey = crypto.randomUUID();
    let attempted = false;
    const error = el('div'), expiry = el('div');
    const consent = el('input', { id: 'job-confirm-authority', type: 'checkbox' });
    const accept = button('Confirm and start job', async () => {
      if (busy || accept.disabled) return;
      attempted = true; working(true); accept.disabled = true; previous.disabled = true;
      error.replaceChildren(notice('Recording the operation. Keep this window open until the service responds.'));
      try {
        const operation = await request('/operations', { method: 'POST', body: { preview_id: preview.preview_id }, idempotencyKey });
        if (!active) return;
        dialog.close(); announce('Managed job recorded'); onSubmitted(operation);
      } catch (failure) {
        if (!active) return;
        error.replaceChildren(errorPanel(failure), notice('The outcome may be uncertain. Retry uses the same submission key. Check job history before creating another job.', 'warning'));
        accept.textContent = 'Retry same submission';
      } finally { working(false); update(); }
    }, { class: 'primary', disabled: true });
    const previous = button('Back', () => { clearTimeout(expiryTimer); back(); });
    function update() {
      const expired = Date.now() / 1000 >= preview.expires_at;
      accept.disabled = busy || !consent.checked || !preview.targets.every(target => target.ready) || (expired && !attempted);
      if (expired) expiry.replaceChildren(notice(attempted ? 'The preview expired. A retry can only recover this submission.' :
        'This preview expired. Select Back to inspect the targets again.', 'warning'));
    }
    consent.addEventListener('change', update);
    expiryTimer = setTimeout(update, Math.max(0, preview.expires_at * 1000 - Date.now()));
    content.replaceChildren(el('h3', {}, 'Confirm frozen targets'),
      el('p', {}, 'Only the machines and settings below are submitted. Admission rechecks permissions, capacity and required controls.'),
      details([['Job', preview.request.job.label], ['Target count', preview.targets.length], ['Preview expires', time(preview.expires_at)]]),
      table(['Machine', 'Admission', 'Details'], preview.targets.map(target => el('tr', {},
        el('td', {}, target.name), el('td', {}, target.ready ? 'Ready' : 'Not ready'),
        el('td', { class: 'wrap' }, [...(target.errors ?? []), ...(target.warnings ?? [])].map(message =>
          el('p', {}, typeof message === 'string' ? message : message.message ?? JSON.stringify(message)))))), 'Frozen job targets'),
      ...(preview.warnings ?? []).map(message => notice(String(message), 'warning')),
      preview.request.job.allow_session_lifetime ? notice('This request accepts dependence on remote login sessions. Signing out remotely may stop these jobs.', 'warning') : null,
      el('details', { class: 'trust-detail' }, el('summary', {}, 'Frozen command, limits and reservations'),
        el('pre', { class: 'job-request', tabindex: '0' }, JSON.stringify(preview.request, null, 2))),
      el('label', { class: 'check-label', for: consent.id }, consent,
        'Start this exact request with full remote-account authority on the listed machines.'), expiry, error,
      el('div', { class: 'actions' }, previous, accept));
    update(); consent.focus();
  }
  load();
}
