// SPDX-License-Identifier: Apache-2.0
// Display effective permissions, credential revocation and audit records.
import { allowed, request } from './api.js';
import { announce, button, confirmation, details, el, errorPanel, heading, panel, state, table, time } from './components.js';

function rootScope(ids) {
  if (ids === null) return 'All registered roots';
  if (ids === undefined) return 'Not reported';
  return ids.length ? ids.join(', ') : 'No file roots';
}

export function access() {
  let active = true;
  const content = el('div');
  const element = el('div', {}, heading('AUTHORITY / ACCESS', 'Access and credentials',
    'Inspect effective permissions and revoke API credentials.'), content);
  async function load() {
    content.replaceChildren(state('Loading access', 'Reading the current account permissions.'));
    try {
      const permissions = await request('/permissions');
      if (!active) return;
      const grants = panel('Effective permissions', details([
        ['Capabilities', permissions.scopes.length ? el('ul', { class: 'scope-list' }, permissions.scopes.map(scope => el('li', {}, scope))) : 'No capabilities'],
        ['Machine scope', permissions.node_ids === null ? 'All enrolled machines' : permissions.node_ids.join(', ') || 'No machines'],
        ['File root scope', rootScope(permissions.root_ids)],
      ]));
      content.replaceChildren(grants);
      if (!allowed('tokens:manage')) { content.append(state('Credential access denied', 'This account cannot list or revoke API credentials.')); return; }
      const { tokens } = await request('/tokens');
      if (!active) return;
      const rows = tokens.map(token => el('tr', {},
        el('td', {}, el('strong', {}, token.label), el('small', { class: 'cell-note' }, token.id)),
        el('td', {}, token.scopes.join(', ')), el('td', {}, token.node_ids === null ? 'All machines' : token.node_ids.join(', ')),
        el('td', { class: 'wrap' }, rootScope(token.root_ids)),
        el('td', {}, time(token.expires_at)), el('td', {}, button('Revoke', () => confirmation('Revoke API credential?',
          `Revoke ${token.label} immediately. Clients that use it will lose access.`, 'Revoke credential', async () => {
            await request(`/tokens/${encodeURIComponent(token.id)}`, { method: 'DELETE' });
            await load(); announce('API credential revoked');
          }), { class: 'danger-text', 'aria-label': `Revoke ${token.label}` }))));
      content.append(panel('API credentials', [el('p', { class: 'muted' },
        'Create scoped credentials with the local command line. Secret values are never displayed here.'),
      tokens.length ? table(['Credential', 'Capabilities', 'Machines', 'File roots', 'Expires', 'Action'], rows, 'API credentials') :
        state('No API credentials', 'No active API credentials are available to revoke.')]));
    } catch (error) { if (active) content.replaceChildren(errorPanel(error, load)); }
  }
  load();
  return { element, dispose() { active = false; } };
}

export function activity() {
  let active = true;
  const content = el('div');
  const element = el('div', {}, heading('RECORD / ACTIVITY', 'Activity history',
    'Recent recorded actions, ordered newest first.', [button('Refresh activity', load)]), content);
  async function load() {
    content.replaceChildren(state('Loading activity', 'Reading the local audit record.'));
    try {
      const { events } = await request('/audit');
      if (!active) return;
      content.replaceChildren(panel('Audit record', events.length ? table(['Time', 'Action', 'Target', 'Outcome'],
        events.map(event => el('tr', {}, el('td', {}, time(event.at)), el('td', {}, event.action),
          el('td', { class: 'wrap' }, event.target), el('td', {}, event.outcome))), 'Recent audit events') :
        state('No activity recorded', 'Recorded actions will appear here.')));
    } catch (error) { if (active) content.replaceChildren(errorPanel(error, load)); }
  }
  load();
  return { element, dispose() { active = false; } };
}
