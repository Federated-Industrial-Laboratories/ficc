// SPDX-License-Identifier: Apache-2.0
// Approve contributor keys and inspect their current authenticated connections.
import { allowed, request } from './api.js';
import { button, bytes, confirmation, el, errorPanel, heading, panel, state, table, time } from './components.js';

export function contributors() {
  let disposed = false, busy = false;
  const content = el('div'), message = el('div', { role: 'status' });
  const name = el('input', { maxlength: '80', 'aria-label': 'Contributor name' });
  const mode = el('select', { 'aria-label': 'Contributor control mode' },
    el('option', { value: 'voluntary' }, 'Voluntary contribution'), el('option', { value: 'managed' }, 'Centrally managed'));
  const invite = button('Download invitation', async () => {
    if (busy || !name.value.trim()) return;
    busy = true; invite.disabled = true;
    try {
      const value = await request('/contributor-invitations', { method: 'POST', body: { name: name.value.trim(), mode: mode.value } });
      if (disposed) return;
      const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2) + '\n'], { type: 'application/json' }));
      const link = el('a', { href: url, download: `ficc-node-${value.node_id}.json` });
      document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      message.textContent = `Invitation expires ${time(value.expires_at)}. Share it privately with the intended machine owner. Set the file permissions to 600 before running ficc node-join.`;
      name.value = '';
    } catch (error) { if (!disposed) message.replaceChildren(errorPanel(error)); }
    finally { busy = false; invite.disabled = !allowed('contributors:manage'); }
  }, { disabled: !allowed('contributors:manage') });
  const invitations = panel('Invite a machine', [
    el('p', {}, 'An invitation permits a key request. Approve that key before this machine can connect.'),
    el('div', { class: 'actions' }, el('label', {}, 'Machine name', name), el('label', {}, 'Control mode', mode), invite), message]);
  const element = el('div', {}, heading('NETWORK / CONTRIBUTORS', 'Contributor connections',
    'Approve machine identities and inspect secure outbound connections.', [button('Refresh contributors', load)]),
  allowed('contributors:manage') ? invitations : null, content);

  function approve(node, pending) {
    const key = el('input', { maxlength: '64', size: '48', autocomplete: 'off', spellcheck: 'false',
      'aria-label': 'Independently verified public key' });
    confirmation(`Approve ${node.name}?`, el('span', {},
      'Obtain the public-key fingerprint directly from the machine owner or its local console. Enter it below.',
      el('label', {}, 'Verified public key', key)), 'Approve this key', async () => {
      if (!/^[0-9a-f]{64}$/.test(key.value.trim())) throw new Error('Enter the complete 64-character public-key fingerprint.');
      await request(`/contributor-requests/${pending.id}/approve`, { method: 'POST', body: {
        public_key: key.value.trim(), revision: pending.revision,
      } });
      await load();
    });
  }

  async function load() {
    try {
      const result = await request('/contributors');
      if (disposed) return;
      invite.disabled = !result.configured || !allowed('contributors:manage');
      if (!result.configured) {
        content.replaceChildren(state('Contributor access is not configured',
          'The installation administrator must configure the certificate authority and node gateway. Existing SSH machines remain available in Overview.'));
        return;
      }
      const rows = result.contributors.map(node => {
        const current = node.certificates.find(cert => cert.status === 'current');
        const pending = node.requests.filter(item => ['awaiting_approval', 'failed', 'issuing'].includes(item.status) && item.kind === 'enroll');
        const resources = node.sample?.resources;
        return el('tr', {},
          el('td', {}, el('strong', {}, node.name), el('small', { class: 'cell-note' }, node.id)),
          el('td', {}, node.mode === 'managed' ? 'Managed' : 'Voluntary'),
          el('td', {}, node.disabled ? 'Revoked' : node.connected ? 'Connected' : current ? 'Disconnected' : 'Awaiting enrollment',
            el('small', { class: 'cell-note' }, node.connection || 'No live channel')),
          el('td', {}, resources ? `${resources.cpu_count} CPUs / ${bytes(resources.memory_total_bytes)}` : 'No current sample',
            el('small', { class: 'cell-note' }, resources ? 'Reported by node' : '')),
          el('td', {}, current ? time(current.expires_at) : 'No active certificate'),
          el('td', {}, time(node.last_seen)),
          el('td', {}, allowed('contributors:manage') && !node.disabled ? [
            pending.map(item => button('Approve key', () => approve(node, item), { 'aria-label': `Approve key for ${node.name}` })),
            button('Revoke', () => confirmation(`Revoke ${node.name}?`,
              'This identity will lose access. Existing channels close and certificate renewal is refused. Rejoining requires a new invitation.',
              'Revoke contributor', async () => {
                await request(`/contributors/${node.id}/disable`, { method: 'POST', body: { revision: node.revision } });
                await load();
              }), { 'aria-label': `Revoke ${node.name}` }),
          ] : allowed('contributors:manage') ? button('Remove', () => confirmation(`Remove ${node.name}?`,
            'Remove this revoked identity and its enrollment records. Audit events remain. Rejoining requires a new invitation.',
            'Remove contributor', async () => {
              await request(`/contributors/${node.id}/remove`, { method: 'POST', body: { revision: node.revision } });
              await load();
            }), { 'aria-label': `Remove ${node.name}` }) : 'No action'));
      });
      content.replaceChildren(panel('Approved network', [
        el('p', {}, result.issuer_ready ? 'Certificate issuer ready.' : 'Certificate issuance is unavailable. Current certificates remain subject to their expiry and approval.'),
        el('p', {}, `Connection authority expires within ${result.lease_seconds} seconds without a valid response.`),
        rows.length ? table(['Machine', 'Control', 'Connection', 'Resources', 'Certificate expires', 'Last observed', 'Actions'], rows, 'Contributor machines') :
          state('No contributors', 'Download an invitation, enroll a machine, then confirm its public key.'),
        !result.execution_available ? el('p', { class: 'muted' }, 'Contributor workload execution is not enabled on this controller.') : null,
      ]));
    } catch (error) { if (!disposed) content.replaceChildren(errorPanel(error, load)); }
  }
  void load();
  return { element, dispose() { disposed = true; } };
}
