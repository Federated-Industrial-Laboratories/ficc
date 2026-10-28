// SPDX-License-Identifier: Apache-2.0
// Choose a model, approved runtime and explicit per-node GPU placements.
import { button, bytes, el, notice } from './components.js';
import { commonRuntimes, nodeLabel } from './workloads-model.js';

export function inferenceForm(models, offers, send, done, existing = null) {
  const chosen = new Map();
  let runtimes = [], frozen;
  const dialog = el('dialog', { class: 'workload-dialog' });
  const status = el('div'), model = el('select', { 'aria-label': 'Model revision' }, models.filter(item => item.ready).map(item => el('option', { value: item.id }, `${item.manifest.name} / ${item.manifest.revision}`)));
  const alias = el('input', { 'aria-label': 'Service name', value: 'local-assistant', pattern: '[a-z][a-z0-9_.-]*' });
  const engine = el('select', { 'aria-label': 'Engine adapter' }, ['llama_cpp', 'ollama', 'vllm'].map(name => el('option', { value: name }, name)));
  const executable = el('input', { 'aria-label': 'Engine executable in approved image', value: '/app/llama-server' });
  engine.addEventListener('change', () => { executable.value = { llama_cpp: '/app/llama-server', ollama: '/bin/ollama', vllm: '/usr/local/bin/vllm' }[engine.value]; });
  const context = el('input', { type: 'number', min: '128', value: '4096', 'aria-label': 'Context tokens' });
  const concurrency = el('input', { type: 'number', min: '1', max: '32', value: '1', 'aria-label': 'Concurrent requests per replica' });
  const runtime = el('select', { 'aria-label': 'Approved runtime image' });
  function refresh() {
    frozen = null;
    runtimes = commonRuntimes(offers.filter(item => chosen.has(item.snapshot.node_id)));
    runtime.replaceChildren(...runtimes.map((item, index) => el('option', { value: String(index) }, `${item.provider} / ${item.image_digest.slice(0, 28)}`)));
    start.disabled = true;
  }
  const nodes = offers.filter(item => item.available && item.snapshot.endpoint_version === 1).map(item => {
    const id = item.snapshot.node_id, select = el('input', { type: 'checkbox', checked: existing?.spec.placements.some(value => value.node_id === id) });
    const gpu = item.snapshot.capacity.available.gpu_devices.map((device, index, list) => el('label', { class: 'check-label' }, el('input', { type: 'checkbox', value: device, checked: existing ? existing.spec.placements.find(value => value.node_id === id)?.limits.gpu_devices.includes(device) : index === list.length - 1 }), device));
    const gpuPanel = el('div', {}, gpu);
    if (select.checked) chosen.set(id, { item, gpuPanel });
    select.addEventListener('change', () => { if (select.checked) chosen.set(id, { item, gpuPanel }); else chosen.delete(id); refresh(); });
    return el('fieldset', {}, el('legend', {}, el('label', {}, select, ` Replica on ${nodeLabel(item)}`)), gpuPanel,
      el('p', {}, `Available RAM ${bytes(item.snapshot.capacity.available.memory_bytes)} / storage ${bytes(item.snapshot.capacity.available.storage_bytes)}. Each selected card is reserved exclusively.`));
  });
  function specification() {
    if (!model.value || !chosen.size || !runtimes.length) throw new Error('Choose a ready model and compatible connected contributors.');
    return { alias: alias.value, model_id: model.value, engine: engine.value, executable: executable.value,
      runtime: runtimes[Number(runtime.value)], context: Number(context.value), concurrency: Number(concurrency.value),
      placements: [...chosen.entries()].map(([node_id, { item, gpuPanel }]) => ({ node_id, limits: {
        ...item.snapshot.capacity.available, processes: Math.min(512, item.snapshot.capacity.available.processes),
        gpu_devices: [...gpuPanel.querySelectorAll('input:checked')].map(input => input.value),
      } })) };
  }
  const start = button('Start service', async () => {
    try { start.disabled = true; await send(existing ? `/inference/${existing.id}` : '/inference', { method: existing ? 'PUT' : 'POST', body: existing ? { revision: existing.revision, spec: frozen } : frozen }); dialog.close(); await done(); }
    catch (error) { status.replaceChildren(notice(error.message, 'error')); start.disabled = false; }
  }, { disabled: true, class: 'primary' });
  const preview = button('Preview resources', async () => {
    try {
      frozen = specification();
      const result = await send('/inference/preview', { method: 'POST', body: frozen });
      status.replaceChildren(notice(`${result.replicas} independent replicas. ${bytes(result.reserved_bytes)} reserved storage across contributors. Weights are already verified; node staging and engine loading follow.`));
      start.disabled = false;
    } catch (error) { status.replaceChildren(notice(error.message, 'error')); start.disabled = true; }
  });
  dialog.addEventListener('change', () => { frozen = null; start.disabled = true; });
  const field = (label, control) => el('label', { class: 'field' }, el('span', {}, label), control);
  dialog.append(el('h2', {}, 'New inference service'), field('Service name', alias), field('Model revision', model), field('Engine', engine),
    field('Executable in the approved image', executable), field('Context tokens', context), field('Concurrent requests per replica', concurrency),
    ...nodes, field('Approved image common to selected contributors', runtime), status, preview, start, button('Cancel', () => dialog.close()));
  if (existing) { alias.value = existing.spec.alias; model.value = existing.spec.model_id; engine.value = existing.spec.engine; executable.value = existing.spec.executable; context.value = existing.spec.context; concurrency.value = existing.spec.concurrency; refresh(); }
  dialog.addEventListener('close', () => dialog.remove()); document.body.append(dialog); dialog.showModal();
  return dialog;
}
