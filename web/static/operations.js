// SPDX-License-Identifier: Apache-2.0
// Show observed installation health and explicit diagnostic and audit exports.
import { request } from './api.js';
import { button, el, heading, notice, table } from './components.js';

export function operations() {
  const element = el('section'), content = el('div'), message = el('div', { role: 'status' });
  let disposed = false, loading = false;
  const download = (label, path) => el('a', { class: 'button', href: `/api/v1/operational-status/${path}`, download: '' }, label);
  element.append(heading('OPERATIONS', 'Installation health', 'Observed service state and recovery evidence.'),
    el('div', { class: 'toolbar' }, button('Refresh', refresh),
      download('Download redacted diagnostics', 'diagnostics'), download('Export retained audit events', 'audit')),
    message, content);
  const recorded = value => value.state === 'recorded' ? new Date(value.at * 1000).toLocaleString() : value.state.replaceAll('_', ' ');
  function row(name, status, detail) { return el('tr', {}, el('th', { scope: 'row' }, name), el('td', {}, status), el('td', {}, detail)); }
  async function refresh() {
    if (loading || disposed) return;
    loading = true;
    try {
      const value = await request('/operational-status');
      if (disposed) return;
      const health = value.connections;
      const rows = [row('Managed connections', `${health.ready} current / ${health.stale} stale / ${health.unreachable} unreachable`, 'From the latest saved observations.'),
        row('Policy evaluator', value.policy.state.replaceAll('_', ' '), `Revision ${value.policy.revision}; enforcement ${value.policy.required ? 'required' : 'not configured'}.`),
        row('Metadata backup', recorded(value.backup), 'Records completion of a FICC metadata export. External datasets and secret keys require separate backups.'),
        row('Isolated restore', recorded(value.restore), 'Records archive verification and restoration. External work must be reconciled before execution resumes.'),
        row('Source backups', 'Not observed', 'A successful database connection does not prove that its backup can be restored.'),
        row('Storage encryption', 'Managed externally', 'Use encrypted storage for state, working data and backups. This view does not certify the host storage configuration.'),
        row('Secret provider', value.secret_store.replaceAll('_', ' '), 'Source credentials use the configured trusted secret store. Key custody and recovery are managed separately.'),
        row('Audit delivery', value.audit_delivery.state.replaceAll('_', ' '), `${value.audit_delivery.required ? 'Required admission' : 'Best effort'}; ${value.audit_delivery.pending_events} events pending; ${value.audit_delivery.retention_gap_events} missing events recorded. Destination acknowledgements require separate custody.`),
        row('Gateway certificate', value.gateway_certificate === 'not_applicable' ? 'Not applicable' : 'Managed by the gateway', 'Gateway certificate renewal is separate from the contributor authority.'),
        row('Retained audit', `${value.audit.retained_events} events`, value.audit.earlier_events_removed ? 'Older local events have been removed. Export records include retention gaps.' : 'Local retention is bounded. Keep a separate authorised audit destination.')];
      for (const certificate of value.certificates) rows.push(row('Contributor authority', certificate.state,
        `Expires ${new Date(certificate.expires_at * 1000).toLocaleString()}.`));
      for (const [name, failed] of Object.entries(value.background_errors)) rows.push(row(`${name} maintenance`, failed ? 'Degraded' : 'No recorded error', 'Status from the running maintenance task.'));
      content.replaceChildren(table(['Service', 'Observed status', 'Coverage'], rows, 'Observed installation health'),
        el('p', { class: 'muted' }, 'Diagnostics contain only the displayed status and counters. Audit exports include actor and resource identities; review them before sharing.'));
      message.replaceChildren();
    } catch (error) { if (!disposed) message.replaceChildren(notice(error.message, 'error')); }
    finally { loading = false; }
  }
  void refresh();
  return { element, dispose() { disposed = true; } };
}
