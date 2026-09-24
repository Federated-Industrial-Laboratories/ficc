// SPDX-License-Identifier: Apache-2.0
// Confirm full account execution and retain a creation key across uncertain replies.
import { request } from './api.js';
import { button, el, errorPanel, notice, state } from './components.js';

export function newTerminal(received) {
  const trigger = document.activeElement;
  let active = true, busy = false, frozen;
  const dialog = el('dialog', { class: 'terminal-dialog', 'aria-labelledby': 'terminal-title' });
  const content = el('div'), close = button('Close', () => dialog.close(), { class: 'quiet' });
  dialog.append(el('div', { class: 'dialog-heading' }, el('h2', { id: 'terminal-title' }, 'Open terminal'), close), content);
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { active = false; dialog.remove(); trigger?.focus(); });
  document.body.append(dialog); dialog.showModal();
  async function load() {
    content.replaceChildren(state('Loading machines', 'Checking available terminal modes.'));
    try {
      const { nodes } = await request('/nodes');
      if (!active) return;
      const targets = nodes.filter(node => node.capabilities?.terminals_ephemeral);
      if (!targets.length) { content.replaceChildren(state('No terminal targets', 'No enrolled machine currently reports terminal support. Refresh Overview to inspect its capabilities.')); return; }
      compose(targets);
    } catch (error) { if (active) content.replaceChildren(errorPanel(error, load)); }
  }
  function compose(nodes) {
    const target = el('select', { id: 'terminal-target' }, nodes.map(node => el('option', { value: node.id }, `${node.name} / ${node.account}`)));
    const mode = el('select', { id: 'terminal-mode' });
    function modes() {
      mode.replaceChildren(el('option', { value: 'ephemeral' }, 'Ephemeral shell'));
      if (nodes.find(node => node.id === target.value).capabilities.terminals_tmux) mode.append(el('option', { value: 'tmux' }, 'Reattachable tmux session'));
    }
    modes(); target.addEventListener('change', modes);
    const label = el('input', { id: 'terminal-label', maxlength: 80, required: true, value: 'Interactive shell', autocomplete: 'off' });
    const consent = el('input', { id: 'terminal-consent', type: 'checkbox', required: true });
    const error = el('div'), submit = el('button', { type: 'submit', class: 'primary' }, 'Confirm and open terminal');
    const form = el('form', { onsubmit: async event => {
      event.preventDefault(); if (busy) return;
      frozen ??= { node_id: target.value, mode: mode.value, label: label.value.trim(), cols: 80, rows: 24,
        confirm_execution: true, idempotency_key: crypto.randomUUID() };
      busy = true; close.disabled = true; submit.disabled = true;
      for (const field of [target, mode, label, consent]) field.disabled = true;
      error.replaceChildren(notice('Recording this terminal. Keep the dialog open until the service responds.'));
      try {
        const record = await request('/terminals', { method: 'POST', body: frozen });
        if (active) { dialog.close(); received(record); }
      } catch (failure) {
        if (active) {
          error.replaceChildren(errorPanel(failure), notice('The result may be uncertain. Retry uses the same creation key. Check the terminal list before opening another session.', 'warning'));
          submit.textContent = 'Retry same terminal';
        }
      } finally { busy = false; close.disabled = false; submit.disabled = false; }
    } }, notice('A terminal provides full access to the remote SSH account. File-root restrictions do not restrict shell commands.', 'warning'),
    el('label', { for: target.id }, 'Terminal machine and account'), target,
    el('label', { for: mode.id }, 'Terminal lifetime'), mode,
    notice('Ephemeral: leaving this view closes the shell connection. Tmux: leaving detaches; the remote session can continue until it exits or you explicitly stop it. Neither mode replays input.'),
    el('label', { for: label.id }, 'Terminal label'), label,
    el('label', { for: consent.id, class: 'check-label' }, consent, 'Open a shell with full authority in the selected remote account.'),
    error, el('div', { class: 'actions' }, submit));
    content.replaceChildren(form); target.focus();
  }
  load();
}
