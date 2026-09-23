// SPDX-License-Identifier: Apache-2.0
// Select explicit job targets and advisory GPU memory reservations.
import { bytes, button, el, isStale, notice, percent } from './components.js';

export function jobNodes(nodes) {
  const selected = new Map();
  const count = el('p', { class: 'muted', role: 'status' }, '0 machines selected');
  const entries = nodes.map((node, index) => {
    const check = el('input', { type: 'checkbox', id: `job-node-${index}` });
    const gpuFields = [];
    const gpuBox = el('div', { class: 'gpu-options', hidden: true });
    for (const [gpuIndex, gpu] of (node.resources?.gpus ?? []).entries()) {
      const gpuCheck = el('input', { type: 'checkbox', id: `job-gpu-${index}-${gpuIndex}` });
      const memory = el('input', { type: 'number', min: 1, step: 1, value: 256,
        'aria-label': `GPU memory MiB for ${node.name} ${gpu.uuid}`, disabled: true });
      gpuCheck.addEventListener('change', () => { memory.disabled = !gpuCheck.checked; });
      gpuBox.append(el('div', { class: 'gpu-option' },
        el('label', { class: 'check-label', for: gpuCheck.id }, gpuCheck, `${gpu.name} / ${gpu.uuid}`),
        el('small', { class: 'muted' }, `Observed total use: ${percent(gpu.utilization_percent)}; ${bytes(gpu.memory_used_bytes)} of ${bytes(gpu.memory_total_bytes)} memory. This can include external jobs.`),
        el('label', { for: `job-memory-${index}-${gpuIndex}` }, 'Reserve memory (MiB)'), memory));
      memory.id = `job-memory-${index}-${gpuIndex}`;
      gpuFields.push({ check: gpuCheck, memory, uuid: gpu.uuid });
    }
    function change() {
      if (check.checked) selected.set(node.id, gpuFields); else selected.delete(node.id);
      gpuBox.hidden = !check.checked || !gpuFields.length;
      count.textContent = `${selected.size} machines selected / maximum 64`;
    }
    check.addEventListener('change', change);
    const capabilities = node.capabilities ?? node.resources?.capabilities ?? {};
    const warnings = [];
    if (!capabilities.jobs) warnings.push('Managed jobs unavailable. Check the helper and system controls in Overview.');
    if (!capabilities.logout_persistent) warnings.push('Logout persistence is unavailable or unverified.');
    if (isStale(node)) warnings.push('Sample is stale. Admission requires fresh capacity.');
    const element = el('div', { class: 'job-node-option' },
      el('label', { class: 'check-label', for: check.id }, check, el('span', {}, el('strong', {}, node.name),
        el('small', { class: 'cell-note' }, `${node.account}@${node.host}`))),
      warnings.length ? el('p', { class: 'muted' }, warnings.join(' ')) : null, gpuBox);
    return { check, change, element };
  });
  const element = el('fieldset', { class: 'job-fieldset' }, el('legend', {}, 'Target machines'),
    el('div', { class: 'actions' }, button('Select all machines', () => {
      for (const entry of entries.slice(0, 64)) { entry.check.checked = true; entry.change(); }
    }), button('Clear selection', () => {
      for (const entry of entries) { entry.check.checked = false; entry.change(); }
    })), count, el('div', { class: 'job-node-list' }, entries.map(entry => entry.element)),
    notice('GPU reservations coordinate FICC jobs. They do not enforce VRAM limits or isolate devices from other processes.', 'warning'));
  return { element, value() {
    if (!selected.size || selected.size > 64) throw new Error('Select between 1 and 64 machines.');
    const gpu_reservations = {};
    for (const [id, fields] of selected) {
      const reservations = fields.filter(field => field.check.checked).map(field => {
        const memory = Number(field.memory.value);
        if (!Number.isSafeInteger(memory) || memory < 1) throw new Error('GPU memory must be a positive whole number of MiB.');
        return { uuid: field.uuid, memory_bytes: memory * 1048576 };
      });
      if (reservations.length) gpu_reservations[id] = reservations;
    }
    return { node_ids: [...selected.keys()], gpu_reservations };
  } };
}
