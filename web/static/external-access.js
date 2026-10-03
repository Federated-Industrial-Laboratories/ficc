// SPDX-License-Identifier: Apache-2.0
// Approve exact external subjects and revoke their local identity mappings.
import { request } from './api.js';
import { button, confirmation, el, errorPanel, panel, table } from './components.js';

export function externalAccess() {
  let disposed = false;
  const element = el('div'), message = el('div', { role: 'status' });
  async function load() {
    try {
      const [{ mappings, provider }, { identities }] = await Promise.all([
        request('/external-identities'), request('/identities'),
      ]);
      if (disposed) return;
      const issuer = el('input', { type: 'url', maxlength: '2048', 'aria-label': 'Identity issuer', value: provider.issuer || '' });
      const external = el('input', { maxlength: '255', 'aria-label': 'External subject identifier' });
      const identity = el('select', { 'aria-label': 'Approved local identity' }, identities.filter(value =>
        !value.disabled && value.id !== '00000000000000000000000000000001').map(value =>
        el('option', { value: value.id }, value.label)));
      const save = button('Approve external identity', async () => {
        save.disabled = true;
        try {
          if (mappings.some(value => value.issuer === issuer.value && value.external_subject === external.value))
            throw new Error('This external subject already has a mapping. Use its existing entry.');
          await request('/external-identities', { method: 'PUT', body: {
            issuer: issuer.value, external_subject: external.value, subject_id: identity.value, disabled: false, revision: 0,
          } });
          await load(); message.textContent = 'Identity approved. Existing project membership determines access.';
        } catch (error) { if (!disposed) message.replaceChildren(errorPanel(error)); }
        finally { save.disabled = !identity.value; }
      }, { disabled: !identity.value });
      const rows = mappings.map(value => el('tr', {},
        el('td', { class: 'wrap' }, value.issuer, el('small', { class: 'cell-note' }, value.external_subject)),
        el('td', {}, identities.find(user => user.id === value.subject_id)?.label || value.subject_id),
        el('td', {}, value.disabled ? 'Disabled' : 'Approved'),
        el('td', {}, String(value.revision)),
        el('td', {}, button(value.disabled ? 'Enable mapping' : 'Disable mapping', () => confirmation(
          value.disabled ? 'Enable external identity?' : 'Disable external identity?',
          value.disabled ? 'New sign-ins will use the existing local identity and project grants.' :
            'Current FICC sessions using this mapping will lose access. Existing local grants remain recorded.',
          value.disabled ? 'Enable mapping' : 'Disable mapping', async () => {
            const { id, ...body } = value;
            await request('/external-identities', { method: 'PUT', body: { ...body, disabled: !value.disabled } });
            await load();
          })))));
      element.replaceChildren(panel('External sign-in', [
        el('p', {}, provider.remote ? provider.ready ? 'Identity service ready.' : 'Identity service is not ready.' : 'Local controller mode.'),
        el('p', {}, 'Approve the exact issuer and subject reported by your identity administrator. Email addresses and group claims do not grant access.'),
        el('div', { class: 'actions' }, el('label', {}, 'Issuer', issuer), el('label', {}, 'External subject', external),
          el('label', {}, 'Local identity', identity), save),
        table(['External identity', 'Local identity', 'State', 'Revision', 'Action'], rows, 'External identity mappings'),
        el('p', { class: 'muted' }, 'Local changes apply to current requests. External authority uses a verification lease of at most 30 seconds.'), message]));
    } catch (error) { if (!disposed) element.replaceChildren(errorPanel(error, load)); }
  }
  void load();
  return { element, dispose() { disposed = true; } };
}
