// SPDX-License-Identifier: Apache-2.0
// Operate durable replicas and exercise their scoped compatible endpoints.
import { allowed, getSession, request } from './api.js';
import { button, el, heading, notice, panel, table } from './components.js';
import { attachedForm } from './inference-attached.js';
import { inferenceForm } from './inference-form.js';

export function inference() {
  const session = getSession(), abort = new AbortController();
  let active = true, timer, selected, promptAbort, profiles = [];
  const status = el('div'), list = el('div'), prompt = el('textarea', { 'aria-label': 'Test prompt' }, 'Explain what this model can help with.'), answer = el('pre', { class: 'job-request', 'aria-live': 'polite' });
  const valid = () => active && getSession() === session;
  const dialogs = new Set();
  const send = (path, options = {}) => {
    if (!valid()) return Promise.reject(new Error('The selected project has changed. Reopen this view.'));
    return request(path, { ...options, signal: abort.signal });
  };
  async function run(action) { try { await action(); if (valid()) await load(); } catch (error) { if (valid()) status.replaceChildren(notice(error.message, 'error')); } }
  function attach(existing = null) { dialogs.add(attachedForm(profiles, send, load, existing)); }
  async function create(existing = null) {
    if (existing?.spec.engine === 'attached') return attach(existing);
    await run(async () => { const [models, offers] = await Promise.all([send('/models'), send('/workload-offers')]);
      if (valid()) dialogs.add(inferenceForm(models.models, offers.offers, send, load, existing)); });
  }
  function control(item, operation) {
    const change = acknowledge => send(`/inference/${item.id}/control/${operation}`, { method: 'POST', body: { revision: item.revision, acknowledge_unknown: acknowledge } });
    if (operation !== 'start' || !item.replicas.some(replica => replica.state === 'unknown')) return run(() => change(false));
    const dialog = el('dialog', {}, el('h2', {}, 'Start after an unknown outcome'),
      el('p', {}, 'An earlier replica stopped without a confirmed result. Its resources must be released before new attempts start. Previous inference requests will not be replayed.'),
      button('Acknowledge and start new attempts', () => run(async () => { await change(true); dialog.close(); })),
      button('Cancel', () => dialog.close()));
    dialogs.add(dialog); dialog.addEventListener('close', () => { dialogs.delete(dialog); dialog.remove(); }); document.body.append(dialog); dialog.showModal();
  }
  async function logs(replica) {
    await run(async () => {
      const result = await send(`/workloads/${replica.id}/output`, { method: 'POST', body: { reads: [{ object: 'stderr', offset: 0, length: 65536 }] } });
      const row = result.results?.[0];
      if (!row?.ok) throw new Error(row?.error?.message || 'The runtime log is not available.');
      const content = new TextDecoder().decode(Uint8Array.from(atob(row.data), value => value.charCodeAt(0)));
      const dialog = el('dialog', {}, el('h2', {}, 'Engine diagnostics'), el('pre', {}, content || 'No stderr has been reported.'), button('Close', () => dialog.close()));
      dialogs.add(dialog); dialog.addEventListener('close', () => { dialogs.delete(dialog); dialog.remove(); }); document.body.append(dialog); dialog.showModal();
    });
  }
  async function tryPrompt() {
    if (!selected) return;
    promptAbort?.abort(); promptAbort = new AbortController(); answer.textContent = '';
    try {
      const response = await fetch(`/api/v1/inference/${selected.id}/v1/chat/completions`, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf, 'X-FICC-Project': session.principal.project_id, 'X-FICC-Session': session.principal.id },
        body: JSON.stringify({ messages: [{ role: 'user', content: prompt.value }], stream: true, max_tokens: 256 }), signal: promptAbort.signal });
      if (!response.ok) throw new Error((await response.json()).error?.message || 'Inference failed.');
      const reader = response.body.getReader(), decoder = new TextDecoder(); let pending = '';
      while (valid()) {
        const { done, value } = await reader.read(); if (done) break;
        pending += decoder.decode(value, { stream: true });
        let boundary;
        while ((boundary = pending.indexOf('\n')) >= 0) {
          const line = pending.slice(0, boundary).trim(); pending = pending.slice(boundary + 1);
          if (!line.startsWith('data:') || line === 'data: [DONE]') continue;
          const event = JSON.parse(line.slice(5)); answer.textContent += event.choices?.[0]?.delta?.content || '';
        }
      }
    } catch (error) { if (valid() && error.name !== 'AbortError') answer.textContent += `\n${error.message}`; }
  }
  async function load() {
    clearTimeout(timer);
    try {
      const result = await send('/inference'); if (!valid()) return;
      profiles = result.endpoint_profiles || [];
      if (selected) selected = result.services.find(item => item.id === selected.id);
      selected ||= result.services[0];
      list.replaceChildren(panel('Services', [table(['Service', 'State', 'Replicas', 'Actions'], result.services.map(item => el('tr', {},
        el('td', {}, button(item.spec.alias, () => { selected = item; endpoint.textContent = `${location.origin}${item.endpoint}`; }), el('small', { class: 'cell-note' }, item.spec.engine)),
        el('td', {}, item.state, el('small', { class: 'cell-note' }, item.reason || '')),
        el('td', {}, item.replicas.map(replica => el('div', {}, `${replica.attempt?.node_id || 'Awaiting placement'}: ${replica.state}`, button('Engine logs', () => logs(replica), { disabled: !replica.attempt || !allowed('jobs:logs') })))),
        el('td', {}, button('Configure', () => create(item), { disabled: !allowed('inference:manage') || item.state !== 'stopped' }), ['start', 'drain', 'stop', 'remove'].map(operation => button(operation[0].toUpperCase() + operation.slice(1), () => control(item, operation), { disabled: !allowed('inference:manage') || (['start', 'remove'].includes(operation) ? item.state !== 'stopped' : item.state === 'stopped') }))))), 'Inference services')]));
      endpoint.textContent = selected ? `${location.origin}${selected.endpoint}` : 'Create a service to obtain its client endpoint.';
    } catch (error) { if (valid()) status.replaceChildren(notice(error.message, 'error')); }
    if (valid()) timer = setTimeout(load, 3000);
  }
  const endpoint = el('code', { class: 'wrap' });
  const element = el('div', {}, heading('CLUSTER / INFERENCE', 'Inference', 'Run verified models on one or several local contributors.', [button('New service', () => create(), { disabled: !allowed('inference:manage') }), button('Attach endpoint', () => attach(), { disabled: !allowed('inference:manage') }), button('Refresh', load)]), status, list,
    panel('Try the selected service', [endpoint, el('p', {}, 'Use an inference:invoke project token as the Bearer credential in compatible clients.'), prompt,
      button('Send prompt', tryPrompt, { disabled: !allowed('inference:invoke') }), button('Cancel request', () => promptAbort?.abort()), button('Create client token', () => run(async () => { if (!selected) return; const value = await send(`/inference/${selected.id}/tokens`, { method: 'POST', body: { lifetime: 3600 } }); answer.textContent = `Bearer token (shown once, expires in one hour):\n${value.token}\nEndpoint: ${location.origin}${value.endpoint}`; }), { disabled: !allowed('tokens:manage') }), answer]));
  void load();
  return { element, dispose() { active = false; clearTimeout(timer); abort.abort(); for (const dialog of dialogs) dialog.close(); promptAbort?.abort(); } };
}
