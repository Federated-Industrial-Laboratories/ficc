// SPDX-License-Identifier: Apache-2.0
// Preview a registered command and retain one launch identity across lost replies.
import { request } from './api.js';
import { button, details, el, errorPanel, notice, state } from './components.js';

export function newAgent(received) {
  const trigger = document.activeElement;
  let active = true, busy = false, frozen;
  const content = el('div'), close = button('Close', () => dialog.close());
  const dialog = el('dialog', { class: 'agent-dialog', 'aria-labelledby': 'agent-title' },
    el('div', { class: 'dialog-heading' }, el('h2', { id: 'agent-title' }, 'Launch agent'), close), content);
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { active = false; dialog.remove(); trigger?.focus(); });
  document.body.append(dialog); dialog.showModal();
  async function load() {
    content.replaceChildren(state('Loading profiles', 'Reading registered commands and open runs.'));
    try {
      const [{ profiles }, { runs }] = await Promise.all([request('/agent-profiles'), request('/bus/runs')]);
      if (!active) return;
      const open = runs.filter(run => run.state === 'open');
      if (!profiles.length || !open.length) {
        content.replaceChildren(state('Agent setup required', !profiles.length ?
          'Register and verify an installed command with the local ficc agent-profile-add command.' : 'Create an open run on the Bus page first.')); return;
      }
      compose(profiles, open);
    } catch (error) { if (active) content.replaceChildren(errorPanel(error, load)); }
  }
  function compose(profiles, runs) {
    const profile = el('select', { id: 'agent-profile' }, profiles.map(item => el('option', { value: item.id }, `${item.name} / ${item.node_id}`)));
    const run = el('select', { id: 'agent-run' }, runs.map(item => el('option', { value: item.id }, item.name)));
    const label = el('input', { id: 'agent-label', required: true, maxlength: 80, value: 'Coding agent', autocomplete: 'off' });
    const errors = el('div');
    const submit = el('button', { type: 'submit', class: 'primary' }, 'Preview agent');
    const form = el('form', { onsubmit: async event => {
      event.preventDefault(); if (busy) return;
      busy = true; submit.disabled = true;
      const body = { profile_id: profile.value, label: label.value.trim(), run_id: run.value, cols: 100, rows: 30 };
      try {
        const preview = await request('/agent-previews', { method: 'POST', body });
        if (active) confirm(preview, body);
      } catch (error) { if (active) errors.replaceChildren(errorPanel(error)); }
      finally { busy = false; submit.disabled = false; }
    } }, el('label', { for: profile.id }, 'Registered agent profile'), profile,
    el('label', { for: run.id }, 'Agent bus run'), run, el('label', { for: label.id }, 'Agent label'), label, errors,
    el('div', { class: 'actions' }, submit));
    content.replaceChildren(form); profile.focus();
  }
  function confirm(preview, requested) {
    const profile = preview.profile, consent = el('input', { id: 'agent-consent', type: 'checkbox', required: true });
    const errors = el('div'), submit = el('button', { type: 'submit', class: 'primary' }, 'Confirm and launch agent');
    const form = el('form', { onsubmit: async event => {
      event.preventDefault(); if (busy) return;
      frozen ??= { preview_id: preview.preview_id, idempotency_key: crypto.randomUUID(), confirm_execution: true };
      busy = true; close.disabled = true; submit.disabled = true; consent.disabled = true;
      try {
        const agent = await request('/agents', { method: 'POST', body: frozen });
        if (active) { dialog.close(); received(agent); }
      } catch (error) {
        if (active) {
          errors.replaceChildren(errorPanel(error), notice('Check the agent list before starting another agent. Retry keeps this exact launch identity.', 'warning'));
          submit.textContent = 'Retry same agent';
        }
      } finally { busy = false; close.disabled = false; submit.disabled = false; }
    } }, notice('This command has the authority of the remote account. The agent keeps its own approval and provider settings.', 'warning'),
    details([['Machine / account', `${preview.node.name} / ${preview.node.account}`], ['Profile', profile.name],
      ['Adapter / version', `${profile.adapter} / ${profile.version ?? 'Unverified'}`], ['Working directory', profile.workspace],
      ['Command arguments', el('code', { class: 'agent-command' }, JSON.stringify(profile.argv))], ['Delivery', preview.delivery_method],
      ['Run identity', requested.run_id], ['Label', requested.label]]),
    el('label', { for: consent.id, class: 'check-label' }, consent, 'Launch this exact command on this machine and enroll it in this run.'),
    errors, el('div', { class: 'actions' }, submit));
    content.replaceChildren(form); consent.focus();
  }
  load();
}

export function rebindAgent(agent, received) {
  const trigger = document.activeElement;
  let active = true, busy = false;
  const session = el('input', { id: 'agent-rebind-session', required: true, maxlength: 100, autocomplete: 'off' });
  const consent = el('input', { id: 'agent-rebind-consent', type: 'checkbox', required: true });
  const errors = el('div'), close = button('Cancel', () => dialog.close());
  const submit = el('button', { type: 'submit', class: 'primary' }, 'Bind exact session');
  const dialog = el('dialog', { class: 'agent-dialog', 'aria-labelledby': 'rebind-title' },
    el('h2', { id: 'rebind-title' }, 'Bind agent runtime session'),
    el('form', { onsubmit: async event => {
      event.preventDefault(); if (busy) return;
      busy = true; close.disabled = true; submit.disabled = true; session.disabled = true; consent.disabled = true;
      try {
        const result = await request(`/agents/${encodeURIComponent(agent.id)}/rebind`, { method: 'POST',
          body: { runtime_session_id: session.value.trim(), confirm_rebind: true } });
        if (active) { dialog.close(); received(result); }
      } catch (error) { if (active) errors.replaceChildren(errorPanel(error)); }
      finally { busy = false; close.disabled = false; submit.disabled = false; session.disabled = false; consent.disabled = false; }
    } }, notice(`Direct delivery to ${agent.label} follows the exact bound runtime session. Confirm the new session identity in its terminal before rebinding.`, 'warning'),
    el('label', { for: session.id }, 'Exact runtime session ID'), session,
    el('label', { for: consent.id, class: 'check-label' }, consent, 'Permit direct delivery to this exact runtime session.'), errors,
    el('div', { class: 'actions' }, close, submit)));
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { active = false; dialog.remove(); trigger?.focus(); });
  document.body.append(dialog); dialog.showModal(); session.focus();
}
