// SPDX-License-Identifier: Apache-2.0
// Require a verified host identity before node enrollment.
import { request } from './api.js';
import { announce, button, details, el, errorPanel, notice, state, time } from './components.js';

export async function enroll(onComplete) {
  const trigger = document.activeElement;
  let active = true, expiryTimer;
  const dialog = el('dialog', { class: 'enroll-dialog', 'aria-labelledby': 'enroll-title' });
  const content = el('div');
  dialog.append(el('div', { class: 'dialog-heading' }, el('h2', { id: 'enroll-title' }, 'Enroll a machine'),
    button('Close', () => dialog.close(), { class: 'quiet' })), content);
  dialog.addEventListener('close', () => { active = false; clearTimeout(expiryTimer); dialog.remove(); trigger?.focus(); });
  document.body.append(dialog);
  dialog.showModal();
  async function profiles() {
    clearTimeout(expiryTimer);
    content.replaceChildren(state('Loading approved profiles', 'Only profiles approved through the local command line are available.'));
    try {
      const result = await request('/profiles');
      if (!active) return;
      if (!result.profiles.length) {
        content.replaceChildren(state('No approved profiles', 'Configure an SSH profile with the local FICC command line, then reopen this window.'));
        return;
      }
      const select = el('select', { id: 'profile', required: true }, result.profiles.map(profile => el('option', { value: profile.id }, profile.label)));
      const name = el('input', { id: 'node-name', required: true, maxlength: '80', autocomplete: 'off', placeholder: 'Example: Compute node 01' });
      const error = el('div');
      const next = el('button', { type: 'submit', class: 'primary' }, 'Inspect host identity');
      const form = el('form', { onsubmit: async event => {
        event.preventDefault(); next.disabled = true; error.replaceChildren();
        try {
          const preview = await request('/node-previews', { method: 'POST', body: { profile: select.value, name: name.value.trim() } });
          if (active) confirmPreview(preview);
        } catch (failure) { if (active) error.replaceChildren(errorPanel(failure)); }
        finally { next.disabled = false; }
      } }, el('p', {}, 'Inspect the SSH account and pinned host key before enrollment.'),
      el('label', { for: 'profile' }, 'Approved SSH profile'), select,
      el('label', { for: 'node-name' }, 'Machine name'), name, error, el('div', { class: 'actions' }, next));
      content.replaceChildren(form);
      select.focus();
    } catch (failure) { if (active) content.replaceChildren(errorPanel(failure, profiles)); }
  }
  function confirmPreview(preview) {
    const checked = el('input', { type: 'checkbox', id: 'verify-host' });
    const fingerprint = el('input', { id: 'fingerprint-check', autocomplete: 'off', spellcheck: 'false', required: true });
    const install = el('input', { type: 'checkbox', id: 'install-helper' });
    const error = el('div');
    const expiry = el('div');
    const accept = el('button', { type: 'submit', class: 'primary', disabled: true }, 'Confirm enrollment');
    const trusted = preview.trust === 'trusted';
    const update = () => {
      accept.disabled = !trusted || !checked.checked || fingerprint.value.trim() !== preview.fingerprint ||
        (preview.helper_install_required && !install.checked) || Date.now() / 1000 >= preview.expires_at;
    };
    const expire = () => { accept.disabled = true; expiry.replaceChildren(notice('This preview expired. Select Back to inspect the host again.', 'warning')); };
    expiryTimer = setTimeout(expire, Math.max(0, preview.expires_at * 1000 - Date.now()));
    for (const input of [checked, fingerprint, install]) input.addEventListener('input', update);
    const form = el('form', { onsubmit: async event => {
      event.preventDefault(); update(); if (accept.disabled) return;
      accept.disabled = true;
      try {
        await request('/nodes', { method: 'POST', body: { preview_id: preview.preview_id,
          expected_fingerprint: fingerprint.value.trim(), install_helper: install.checked } });
        if (!active) return;
        dialog.close(); announce('Machine enrolled'); await onComplete();
      } catch (failure) { if (active) { error.replaceChildren(errorPanel(failure)); update(); } }
    } }, notice(trusted ? 'The host key matches the configured trusted key.' : 'This host key is not trusted. Verify and pin it through OpenSSH before enrollment.', trusted ? 'info' : 'warning'),
    details([['Machine', preview.name], ['Host', preview.host], ['Account', preview.account], ['Profile', preview.profile],
      ['Helper version', preview.helper_version ?? 'Not installed'], ['Preview expires', time(preview.expires_at)]]),
    el('p', { class: 'section-label' }, 'SSH host fingerprint'), el('code', { class: 'fingerprint' }, preview.fingerprint),
    preview.warnings.map(warning => notice(warning, 'warning')),
    el('label', { class: 'check-label', for: 'verify-host' }, checked, 'I verified this fingerprint through an independent trusted source.'),
    el('label', { for: 'fingerprint-check' }, 'Enter the verified fingerprint'), fingerprint,
    preview.helper_install_required ? el('label', { class: 'check-label', for: 'install-helper' }, install,
      'Install the FICC helper in this remote user account. No root access is requested.') :
      el('p', { class: 'muted' }, 'The compatible helper is already installed. Enrollment does not install it again.'),
    expiry, error, el('div', { class: 'actions' }, button('Back', profiles), accept));
    content.replaceChildren(form);
    checked.focus();
  }
  await profiles();
}
