// SPDX-License-Identifier: Apache-2.0
// Confirm helper replacement against the existing enrolled host identity.
import { request } from './api.js';
import { announce, button, details, el, errorPanel, notice } from './components.js';

export function upgradeHelper(node, onComplete) {
  const trigger = document.activeElement;
  let active = true, busy = false;
  const dialog = el('dialog', { 'aria-labelledby': 'upgrade-title' });
  const consent = el('input', { type: 'checkbox', id: 'upgrade-consent' });
  const error = el('div');
  const close = button('Cancel', () => dialog.close());
  const accept = button('Confirm helper upgrade', async () => {
    if (!consent.checked || busy) return;
    busy = true; accept.disabled = close.disabled = true;
    error.replaceChildren(notice('Checking the pinned host identity and installing the job helper.'));
    try {
      await request(`/nodes/${encodeURIComponent(node.id)}/helper-upgrade`, { method: 'POST', body: { expected_fingerprint: node.fingerprint } });
      if (!active) return;
      dialog.close(); announce('Node helper upgraded'); await onComplete();
    } catch (failure) { if (active) error.replaceChildren(errorPanel(failure)); }
    finally { busy = false; accept.disabled = !consent.checked; close.disabled = false; }
  }, { class: 'primary', disabled: true });
  consent.addEventListener('change', () => { accept.disabled = !consent.checked; });
  dialog.append(el('h2', { id: 'upgrade-title' }, 'Upgrade the node helper?'),
    details([['Machine', node.name], ['Remote account', `${node.account}@${node.host}`]]),
    el('p', {}, 'Install the managed-job helper in this remote account. The enrolled identity and node ID are preserved.'),
    el('p', { class: 'section-label' }, 'Enrolled SSH host fingerprint'), el('code', { class: 'fingerprint' }, node.fingerprint),
    notice('The service checks this pinned fingerprint again. Incompatible active work prevents replacement.', 'warning'),
    el('label', { class: 'check-label', for: consent.id }, consent, 'Install the updated FICC helper on this enrolled host.'),
    error, el('div', { class: 'actions' }, close, accept));
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { active = false; dialog.remove(); trigger?.focus(); });
  document.body.append(dialog); dialog.showModal();
}
