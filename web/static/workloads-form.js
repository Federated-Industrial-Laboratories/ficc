// SPDX-License-Identifier: Apache-2.0
// Submit an immutable request using runtimes and limits from approved offers.
import { button, details, el, notice } from './components.js';
import { allowed } from './api.js';
import { commonRuntimes, limitFields, nodeLabel, runtimeKey } from './workloads-model.js';
import { workloadTemplates } from './workload-templates.js';

export function workloadForm(offers, send, received, valid) {
  const trigger = document.activeElement;
  let active = true, busy = false, frozen = null, uncertain = false, runtimeValues = [];
  let preferredRuntime = null, templateSensitive = false;
  const key = crypto.randomUUID(), chosen = new Set();
  const dialog = el('dialog', { class: 'workload-dialog', 'aria-labelledby': 'workload-form-title' });
  const errors = el('div', { role: 'status' }), runtimeDetails = el('div'), gpuOptions = el('div');
  const fields = el('fieldset', { class: 'workload-fields' });
  const name = el('input', { required: true, maxlength: '80', 'aria-label': 'Workload name' });
  const runtime = el('select', { required: true, 'aria-label': 'Approved runtime' });
  const argv = el('textarea', { 'aria-label': 'Executable and arguments (JSON)', spellcheck: 'false' }, '["/usr/bin/printf", "Hello from FICC\\n"]');
  const environment = el('textarea', { 'aria-label': 'Environment variables (JSON)', spellcheck: 'false' }, '{}');
  const outputs = el('textarea', { 'aria-label': 'Output declarations (JSON)', spellcheck: 'false' }, '[]');
  const inputs = el('textarea', { 'aria-label': 'Input references (JSON)', spellcheck: 'false' }, '[]');
  let datasetValue = null, datasetCursor = null;
  const dataset = el('select', { 'aria-label': 'Input dataset' }, el('option', { value: '' }, 'Use approved local input references'));
  const datasetDetails = el('div');
  const loadDatasets = button('Browse datasets', async () => {
    try {
      const value = await send('/datasets' + (datasetCursor ? `?before=${encodeURIComponent(datasetCursor)}` : ''));
      if (!active || !valid()) return;
      for (const item of value.datasets) {
        if (![...dataset.options].some(option => option.value === item.id)) {
          dataset.append(el('option', { value: item.id }, `${item.name} / ${item.file_count} files`));
        }
      }
      datasetCursor = value.next_cursor;
      loadDatasets.textContent = datasetCursor ? 'Load more datasets' : 'Refresh datasets';
    } catch (error) { if (active && valid()) errors.replaceChildren(notice(error.message, 'error')); }
  }, { disabled: !allowed('files:read') });
  dataset.addEventListener('change', async () => {
    datasetValue = null; datasetDetails.replaceChildren(); inputs.disabled = Boolean(dataset.value);
    const selected = dataset.value;
    if (!selected) return;
    try {
      const value = await send(`/datasets/${selected}`);
      if (!active || !valid() || dataset.value !== selected) return;
      if (value.files.length > 64) throw new Error('Select a dataset with at most 64 files for one workload.');
      datasetValue = value;
      datasetDetails.replaceChildren(details([['Manifest', value.manifest_digest], ...value.files.map((file, index) => {
        const name = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(file.name) ? file.name : `input-${String(index).padStart(3, '0')}`;
        return [`/inputs/${name}`, `${file.size} bytes / SHA256 ${file.sha256}`];
      })]));
    } catch (error) { if (active && valid()) errors.replaceChildren(notice(error.message, 'error')); }
  });
  const sensitive = el('input', { type: 'checkbox' });
  const limits = Object.fromEntries(limitFields.map(([key, label]) => [key,
    el('input', { type: 'number', min: key === 'swap_bytes' ? '0' : '1', step: '1', required: true, 'aria-label': label })]));
  const count = el('p', { class: 'muted', role: 'status' }, 'Select up to 64 candidate contributors. One workload runs on one eligible candidate.');
  function currentOffers() { return offers.filter(value => chosen.has(value.snapshot.node_id)); }
  function refresh() {
    const values = currentOffers(), prior = preferredRuntime || runtimeValues[Number(runtime.value)];
    runtimeValues = commonRuntimes(values);
    runtime.replaceChildren(...runtimeValues.map((value, index) => el('option', { value: index },
      `${value.provider} / ${value.isolation} / ${value.network} / ${value.image_digest.slice(7, 19)}`)));
    const previous = runtimeValues.findIndex(value => prior && runtimeKey(value) === runtimeKey(prior));
    if (previous >= 0) runtime.value = String(previous);
    else if (preferredRuntime) runtime.value = '';
    for (const [key, , fallback] of limitFields) {
      const maximum = values.length ? Math.min(...values.map(value => value.snapshot.offer.limits[key]), Number.MAX_SAFE_INTEGER) : 0;
      limits[key].max = String(maximum);
      const entered = Number(limits[key].value);
      limits[key].value = String(Math.min(limits[key].value === '' || entered < Number(limits[key].min) ? fallback : entered, maximum));
    }
    const devices = values.length ? values[0].snapshot.offer.limits.gpu_devices.filter(device =>
      values.every(value => value.snapshot.offer.limits.gpu_devices.includes(device))) : [];
    const checked = new Set([...gpuOptions.querySelectorAll('input:checked')].map(input => input.value));
    gpuOptions.replaceChildren(...devices.map(device => el('label', { class: 'check-label' },
      el('input', { type: 'checkbox', value: device, checked: checked.has(device) }), `GPU ${device}`)));
    sensitive.disabled = !values.length || values.some(value => value.snapshot.offer.mode !== 'managed' || !value.snapshot.offer.accept_sensitive);
    if (sensitive.disabled && !templateSensitive) sensitive.checked = false;
    count.textContent = `${chosen.size} candidates selected. ${runtimeValues.length ? 'One workload runs on one eligible candidate.' : 'Select contributors with an approved runtime in common.'}`;
    showRuntime();
    submit.disabled = !chosen.size || chosen.size > 64 || !runtimeValues.length || runtime.value === '';
  }
  function showRuntime() {
    const value = runtime.value === '' ? null : runtimeValues[Number(runtime.value)];
    runtimeDetails.replaceChildren(...(value ? [details([['Provider package', value.package_digest], ['Container image', value.image_digest],
      ['Isolation', value.isolation], ['Network', value.network]])] : []));
  }
  runtime.addEventListener('change', showRuntime);
  runtime.addEventListener('change', () => { preferredRuntime = null; });
  const candidates = offers.map(value => {
    const input = el('input', { type: 'checkbox', 'aria-label': `Candidate ${value.snapshot.node_id}` });
    input.addEventListener('change', () => { input.checked ? chosen.add(value.snapshot.node_id) : chosen.delete(value.snapshot.node_id); refresh(); });
    return el('label', { class: 'check-label' }, input, el('span', {}, nodeLabel(value),
      el('small', { class: 'cell-note' }, value.snapshot.node_id),
      el('small', { class: 'cell-note' }, `${value.snapshot.offer.control} / ${value.available ? 'connected' : 'unavailable; may wait in queue'}`)));
  });
  function json(field, kind, label) {
    let value;
    try { value = JSON.parse(field.value); } catch { throw new Error(`${label} must be valid JSON.`); }
    if (kind === 'array' ? !Array.isArray(value) : !value || Array.isArray(value) || typeof value !== 'object') {
      throw new Error(`${label} must be a JSON ${kind}.`);
    }
    return value;
  }
  function build() {
    if (!name.value.trim()) throw new Error('Enter a workload name.');
    if (sensitive.checked && sensitive.disabled) throw new Error('Select managed contributors that accept sensitive data.');
    const command = json(argv, 'array', 'Executable and arguments');
    if (!command.length || command.length > 256 || command.some(item => typeof item !== 'string' || item.includes('\0') || item.length > 16384) || !command[0].startsWith('/')) {
      throw new Error('Enter up to 256 string arguments, beginning with an absolute container executable.');
    }
    const resources = { gpu_devices: [...gpuOptions.querySelectorAll('input:checked')].map(input => input.value) };
    for (const [key, label] of limitFields) {
      const value = Number(limits[key].value);
      if (!Number.isSafeInteger(value) || value < Number(limits[key].min) || value > Number(limits[key].max)) {
        throw new Error(`${label} must be an integer within the selected local ceilings.`);
      }
      resources[key] = value;
    }
    const environmentValue = json(environment, 'object', 'Environment variables');
    if (Object.entries(environmentValue).length > 64 || Object.entries(environmentValue).some(([key, value]) =>
      !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key) || typeof value !== 'string' || value.includes('\0') || value.length > 16384)) {
      throw new Error('Use up to 64 named environment variables with string values.');
    }
    if (dataset.value && !datasetValue) throw new Error('Wait for the selected dataset manifest or select another dataset.');
    const inputValues = datasetValue ? [] : json(inputs, 'array', 'Input references'), outputValues = json(outputs, 'array', 'Output declarations');
    if (inputValues.length > 64 || outputValues.length > 64) throw new Error('Use no more than 64 input references or output declarations.');
    const runtimeValue = runtime.value === '' ? null : runtimeValues[Number(runtime.value)];
    if (!runtimeValue || !chosen.size || chosen.size > 64) throw new Error('Select up to 64 candidates with a common approved runtime.');
    return { requests: [{ key, request: { node_ids: [...chosen],
      ...(datasetValue ? { dataset: { id: datasetValue.id, manifest_digest: datasetValue.manifest_digest } } : {}),
      job: { name: name.value.trim(), runtime: runtimeValue,
      payload: { argv: command, environment: environmentValue }, limits: resources,
      inputs: inputValues, outputs: outputValues, sensitive: sensitive.checked } } }] };
  }
  const close = button('Close', () => dialog.close());
  const submit = button('Submit workload', async () => {
    if (busy || !active || !valid()) return;
    try { frozen ??= build(); }
    catch (error) { errors.replaceChildren(notice(error.message, 'error')); return; }
    busy = true; fields.disabled = true; submit.disabled = true; close.disabled = true;
    errors.replaceChildren();
    try {
      const response = await send('/workloads', { method: 'POST', body: frozen });
      if (!active || !valid()) return;
      const result = response.results?.[0];
      if (response.results?.length !== 1 || result?.key !== key) throw new Error('The submission acknowledgement is invalid.');
      if (!result.ok) {
        frozen = null; uncertain = false;
        throw new Error(result.error?.message || 'The workload was refused.');
      }
      received(result.workload); dialog.close();
    } catch (error) {
      if (!active || !valid()) return;
      if (error.status === 403 || error.status === 401) { dialog.close(); return; }
      if (error.status >= 400 && error.status < 500) frozen = null;
      uncertain = frozen !== null;
      errors.replaceChildren(notice(uncertain ? `${error.message} The submission outcome may be uncertain. Retry sends the identical request and key. Check recorded workloads before creating a replacement.` : error.message, 'error'));
    } finally {
      busy = false; fields.disabled = uncertain; submit.disabled = false; close.disabled = false;
      submit.textContent = uncertain ? 'Retry same submission' : 'Submit workload';
    }
  }, { class: 'primary', disabled: true });
  const form = el('form', { onsubmit: event => { event.preventDefault(); submit.click(); } }, fields);
  const templates = workloadTemplates(send, valid, () => build().requests[0].request.job, job => {
    preferredRuntime = job.runtime; templateSensitive = job.sensitive;
    name.value = job.name; argv.value = JSON.stringify(job.payload.argv); environment.value = '{}';
    outputs.value = JSON.stringify(job.outputs); inputs.value = '[]';
    dataset.value = ''; datasetValue = null; datasetDetails.replaceChildren(); inputs.disabled = false;
    refresh();
    for (const [key] of limitFields) limits[key].value = String(job.limits[key]);
    for (const input of gpuOptions.querySelectorAll('input')) input.checked = false;
    sensitive.checked = job.sensitive;
    if (!runtimeValues.some(value => runtimeKey(value) === runtimeKey(job.runtime))) {
      runtime.value = ''; runtimeDetails.replaceChildren(notice('Select contributors that offer this exact template runtime.'));
    }
  });
  fields.append(el('legend', { class: 'sr-only' }, 'Workload request'), templates.element, el('label', {}, 'Workload name', name),
    el('h3', {}, 'Candidate contributors'), count,
    el('div', { class: 'actions' }, button('Select all candidates', () => {
      if (offers.length > 64) return;
      for (const candidate of candidates) { candidate.querySelector('input').checked = true; }
      for (const value of offers) chosen.add(value.snapshot.node_id);
      refresh();
    }, { disabled: offers.length > 64 }), button('Clear candidates', () => {
      chosen.clear(); for (const candidate of candidates) candidate.querySelector('input').checked = false; refresh();
    })), el('div', { class: 'workload-candidates' }, candidates),
    el('label', {}, 'Approved runtime', runtime), runtimeDetails,
    el('label', {}, 'Executable and arguments (JSON)', argv),
    el('p', { class: 'muted' }, 'Arguments run inside the approved container image. Specify each argument separately; shell syntax is not expanded.'),
    el('h3', {}, 'Resource limits'), el('div', { class: 'workload-limit-grid' }, limitFields.map(([key, label]) => el('label', {}, label, limits[key]))), gpuOptions,
    el('label', { class: 'check-label' }, sensitive, 'Contains sensitive data (requires managed contributors that accept sensitive data)'),
    el('h3', {}, 'Dataset inputs'), el('label', {}, 'Input dataset', dataset), loadDatasets, datasetDetails,
    el('p', { class: 'muted' }, 'Registered dataset files pass through the controller to the selected contributor and are verified before execution. Allow storage for inputs, the runtime and output. Current project and source permissions apply throughout transfer.'),
    el('details', {}, el('summary', {}, 'Environment, inputs and outputs'),
      el('label', {}, 'Environment variables (JSON)', environment),
      el('label', {}, 'Input references (JSON)', inputs),
      el('p', { class: 'muted' }, 'Without a selected dataset, use existing approved local objects: [{"id":"32 hex characters","digest":"sha256:...","bytes":123,"name":"input.dat"}].'),
      el('label', {}, 'Output declarations (JSON)', outputs),
      el('p', { class: 'muted' }, 'Declare relative paths below the work directory, for example [{"name":"result","path":"result.json"}].')));
  dialog.append(el('h2', { id: 'workload-form-title' }, 'New workload'),
    el('p', {}, 'Submit batch computation to a contributor. The controller queues it until policy, local consent and capacity permit execution. Closing this browser does not cancel work. Local availability can change.'),
    form, errors, el('div', { class: 'actions' }, close, submit));
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { active = false; templates.dispose(); dialog.remove(); if (trigger?.isConnected) trigger.focus(); });
  document.body.append(dialog); dialog.showModal(); name.focus();
  return { dispose() { active = false; dialog.close(); dialog.remove(); } };
}
