// SPDX-License-Identifier: Apache-2.0
// Confirm exact recipients and preserve message identity after uncertain submission.
import { request } from './api.js';
import { button, el, errorPanel, notice, state } from './components.js';

function modal(title) {
  const trigger = document.activeElement;
  let active = true, busy = false;
  const content = el('div'), close = button('Close', () => dialog.close());
  const dialog = el('dialog', { class: 'agent-dialog', 'aria-labelledby': 'bus-form-title' },
    el('div', { class: 'dialog-heading' }, el('h2', { id: 'bus-form-title' }, title), close), content);
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { active = false; dialog.remove(); trigger?.focus(); });
  document.body.append(dialog); dialog.showModal();
  return { content, close() { dialog.close(); }, get active() { return active; }, get busy() { return busy; },
    working(value) { busy = value; close.disabled = value; } };
}

export function newRun(received) {
  const view = modal('Create bus run');
  let frozen;
  const name = el('input', { id: 'bus-run-name', required: true, maxlength: 80, pattern: '[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', autocomplete: 'off' });
  const errors = el('div'), submit = el('button', { type: 'submit', class: 'primary' }, 'Create run');
  view.content.append(el('form', { onsubmit: async event => {
    event.preventDefault(); if (view.busy) return;
    frozen ??= { name: name.value.trim(), idempotency_key: crypto.randomUUID() };
    name.disabled = true; submit.disabled = true; view.working(true);
    try { const run = await request('/bus/runs', { method: 'POST', body: frozen }); if (view.active) { view.close(); received(run); } }
    catch (error) { if (view.active) { errors.replaceChildren(errorPanel(error)); submit.textContent = 'Retry same run'; } }
    finally { view.working(false); submit.disabled = false; }
  } }, el('label', { for: name.id }, 'Run name'), name,
  el('p', { class: 'muted' }, 'Use letters, numbers, dots, underscores or hyphens. Agents join this run when launched.'), errors,
  el('div', { class: 'actions' }, submit))); name.focus();
}

export function newMessage(run, received) {
  const view = modal('Send agent message');
  let frozen;
  async function load() {
    view.content.replaceChildren(state('Reading run participants', 'Only agents enrolled in this run can receive this message.'));
    try {
      const { agents } = await request('/agents');
      if (!view.active) return;
      const members = agents.filter(agent => agent.run_id === run.id && run.agent_ids.includes(agent.id));
      if (!members.length) { view.content.replaceChildren(state('No run participants', 'Launch an agent into this run before sending a message.')); return; }
      compose(members);
    } catch (error) { if (view.active) view.content.replaceChildren(errorPanel(error, load)); }
  }
  function compose(members) {
    const chosen = new Set();
    const recipients = el('fieldset', { class: 'bus-recipients' }, el('legend', {}, 'Exact recipients'), members.map(agent => {
      const checkbox = el('input', { type: 'checkbox', value: agent.id, 'aria-label': `${agent.label} / ${agent.node_name ?? agent.node_id}`,
        onchange: () => { if (checkbox.checked) chosen.add(agent.id); else chosen.delete(agent.id); } });
      return el('label', { class: 'check-label' }, checkbox, el('span', {}, `${agent.label} / ${agent.node_name ?? agent.node_id}`,
        el('small', {}, `${agent.adapter} / ${agent.delivery_method} / ${agent.state}`), el('code', {}, agent.id)));
    }));
    const kind = el('select', { id: 'bus-message-type' }, el('option', { value: 'note' }, 'Note'), el('option', { value: 'question' }, 'Question'));
    const delivery = el('select', { id: 'bus-delivery' }, el('option', { value: 'inbox' }, 'Inbox: wait for an explicit tool read'),
      el('option', { value: 'direct' }, 'Direct: submit to supported running agents'));
    const text = el('textarea', { id: 'bus-message-text', required: true, maxlength: 7000, rows: 7 });
    const consent = el('input', { id: 'bus-message-consent', type: 'checkbox', required: true });
    const errors = el('div'), submit = el('button', { type: 'submit', class: 'primary' }, 'Send exact message');
    const form = el('form', { onsubmit: async event => {
      event.preventDefault(); if (view.busy) return;
      if (!chosen.size) { errors.replaceChildren(notice('Select at least one exact recipient.', 'error')); return; }
      if (new TextEncoder().encode(JSON.stringify({ text: text.value })).length > 8192) {
        errors.replaceChildren(notice('The message body exceeds 8192 UTF-8 bytes.', 'error')); return;
      }
      frozen ??= { type: kind.value, body: { text: text.value }, recipient_ids: [...chosen], delivery: delivery.value,
        reply_to: null, idempotency_key: crypto.randomUUID(), confirm_delivery: true };
      for (const control of form.querySelectorAll('input,select,textarea,fieldset')) control.disabled = true;
      submit.disabled = true; view.working(true);
      try {
        const result = await request(`/bus/runs/${encodeURIComponent(run.id)}/messages`, { method: 'POST', body: frozen });
        if (view.active) { view.close(); received(result); }
      } catch (error) {
        if (view.active) {
          errors.replaceChildren(errorPanel(error), notice('Submission may already be recorded. Retry uses the same message identity and recipients.', 'warning'));
          submit.textContent = 'Retry same message';
        }
      } finally { view.working(false); submit.disabled = false; }
    } }, el('p', {}, 'Run: ', el('strong', {}, run.name)), recipients,
    el('label', { for: kind.id }, 'Message type'), kind, el('label', { for: delivery.id }, 'Delivery method'), delivery,
    notice('Direct delivery can start an agent turn. Messages identify their sender and do not grant operator approval.', 'warning'),
    el('label', { for: text.id }, 'Message body'), text,
    el('label', { for: consent.id, class: 'check-label' }, consent, 'Send this exact text to the selected recipients using this delivery method.'),
    errors, el('div', { class: 'actions' }, submit));
    view.content.replaceChildren(form); text.focus();
  }
  load();
}
