// SPDX-License-Identifier: Apache-2.0
// Confirm frozen file effects and keep one key through an uncertain acknowledgement.
import { request } from './api.js';
import { button, bytes, details, el, errorPanel, notice, state, table, time } from './components.js';

export function fileDialog(title) {
  const trigger = document.activeElement;
  let active = true, busy = false, timer;
  const content = el('div'), close = button('Close', () => dialog.close(), { class: 'quiet' });
  const dialog = el('dialog', { class: 'file-dialog', 'aria-labelledby': 'file-dialog-title' },
    el('div', { class: 'dialog-heading' }, el('h2', { id: 'file-dialog-title' }, title), close), content);
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { active = false; clearTimeout(timer); dialog.remove(); trigger?.focus(); });
  document.body.append(dialog); dialog.showModal();
  return { dialog, content, active: () => active, busy: () => busy,
    working(value) { busy = value; close.disabled = value; },
    async preview(path, body, submitPath, received, context = []) {
      this.working(true); content.replaceChildren(state('Checking exact entries', 'Resolving identities, permissions and destination conflicts.'));
      try {
        const preview = await request(path, { method: 'POST', body });
        if (!active) return;
        const key = crypto.randomUUID(), errors = el('div'), expiry = el('div');
        const consent = el('input', { id: 'file-confirm', type: 'checkbox' });
        let attempted = false;
        const accept = button('Confirm exact request', async () => {
          if (busy || accept.disabled) return;
          attempted = true; this.working(true); update();
          errors.replaceChildren(notice('Recording this request. Keep the dialog open until the service responds.'));
          try {
            const result = await request(submitPath, { method: 'POST', body: { preview_id: preview.preview_id, confirm: true }, idempotencyKey: key });
            if (active) { dialog.close(); received(result); }
          } catch (error) {
            if (active) {
              errors.replaceChildren(errorPanel(error), notice('The outcome may be uncertain. Retry uses the same request key. Check recorded activity before creating another request.', 'warning'));
              accept.textContent = 'Retry same request';
            }
          } finally { this.working(false); update(); }
        }, { class: body.action === 'delete' ? 'danger' : 'primary', disabled: true });
        function update() {
          const expired = Date.now() / 1000 >= preview.expires_at;
          accept.disabled = busy || !consent.checked || (expired && !attempted);
          if (expired) expiry.replaceChildren(notice(attempted ? 'Preview expired. Retry can only recover this request.' : 'Preview expired. Close and preview the selection again.', 'warning'));
        }
        consent.addEventListener('change', update);
        timer = setTimeout(update, Math.max(0, preview.expires_at * 1000 - Date.now()));
        content.replaceChildren(el('h3', {}, 'Confirm frozen file request'),
          details([...context, ['Action', preview.action ?? preview.kind], ['Expires', time(preview.expires_at)],
            ['Selected entries', preview.count ?? preview.items?.length ?? preview.entries?.length ?? 0]]),
          body.action === 'delete' ? notice('Deletion removes only the exact listed entries. Directories must be empty. This cannot be undone through FICC.', 'warning') : null,
          preview.relay ? notice('This transfer relays bytes through the controller between remote machines.') : null,
          body.overwrite ? notice('Overwrite was explicitly selected. Only the destination identities in this preview can be replaced.', 'warning') : null,
          table(['Exact name', 'Type', 'Size'], (preview.items ?? preview.entries ?? []).map(item => el('tr', {},
            el('td', { class: 'file-name' }, item.name ?? 'Selected entry'), el('td', {}, item.kind ?? 'file'),
            el('td', {}, item.size == null ? 'Not applicable' : bytes(item.size)))), 'Exact selected entries'),
          ...(preview.effects ?? []).map(effect => notice(String(effect))),
          ...(preview.conflicts ?? []).map(conflict => notice(`Existing destination: ${conflict.name}. Replacement requires the approved destination identity.`, 'warning')),
          el('label', { for: consent.id, class: 'check-label' }, consent, 'Apply this exact request to the entries and destinations shown.'),
          expiry, errors, el('div', { class: 'actions' }, accept));
        this.working(false); update(); consent.focus();
      } catch (error) { if (active) content.replaceChildren(errorPanel(error)); }
      finally { this.working(false); }
    },
  };
}
