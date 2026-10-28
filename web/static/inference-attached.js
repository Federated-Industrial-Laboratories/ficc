// SPDX-License-Identifier: Apache-2.0
// Attach an administrator-approved compatible endpoint without process control.
import { button, el, notice } from './components.js';

export function attachedForm(profiles, send, done, existing = null) {
  const alias = el('input', { 'aria-label': 'Attached service name', value: existing?.spec.alias || 'existing-assistant' });
  const profile = el('select', { 'aria-label': 'Approved endpoint profile' }, profiles.map(item => el('option', { value: item.name }, `${item.name} / ${item.model} / ${item.capabilities.join(', ')}`)));
  if (existing) profile.value = existing.spec.profile;
  const status = el('div');
  const dialog = el('dialog', {}, el('h2', {}, 'Attach existing inference'),
    el('p', {}, 'Choose a profile approved for this project. Stop and drain control FICC routing; the external server keeps its own process and model management.'),
    el('label', { class: 'field' }, el('span', {}, 'Service name'), alias),
    el('label', { class: 'field' }, el('span', {}, 'Approved endpoint'), profile), status,
    button('Attach service', async () => {
      try {
        const selected = profiles.find(item => item.name === profile.value);
        if (!selected) throw new Error('An administrator must configure an endpoint profile for this project first.');
        const spec = { alias: alias.value, engine: 'attached', profile: selected.name, profile_digest: selected.digest };
        await send('/inference/preview', { method: 'POST', body: spec });
        await send(existing ? `/inference/${existing.id}` : '/inference', { method: existing ? 'PUT' : 'POST', body: existing ? { revision: existing.revision, spec } : spec });
        dialog.close(); await done();
      } catch (error) { status.replaceChildren(notice(error.message, 'error')); }
    }, { class: 'primary' }), button('Cancel', () => dialog.close()));
  dialog.addEventListener('close', () => dialog.remove()); document.body.append(dialog); dialog.showModal();
  return dialog;
}
