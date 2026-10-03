// SPDX-License-Identifier: Apache-2.0
// Show current owner safety controls separately from immutable dataset bytes.
import { allowed, request } from './api.js';
import { button, details, el, errorPanel, notice, panel, table, time } from './components.js';
import { fileDialog } from './file-dialog.js';

const outcomes = { no_detection: 'No detection within recorded coverage', detected: 'Detection reported',
  incomplete: 'Incomplete coverage', unavailable: 'Inspection unavailable', error: 'Inspection error' };

export function datasetSafety(id, view) {
  let timer, settings, value;
  const content = el('div'), errors = el('div'), element = panel('Dataset safety', [content, errors]);
  view.dialog.addEventListener('close', () => clearTimeout(timer));

  async function send(path, body) {
    try { await request(path, { method: 'PUT', body }); await load(); }
    catch (error) { errors.replaceChildren(errorPanel(error)); }
  }

  function controls() {
    const dialog = fileDialog('Owner dataset safety controls'), status = el('div');
    const sensitive = el('input', { id: 'safety-sensitive', type: 'checkbox', checked: value.controls.sensitive });
    const required = el('input', { id: 'safety-required', type: 'checkbox', checked: value.controls.inspection_required });
    const quarantined = el('input', { id: 'safety-quarantined', type: 'checkbox', checked: value.controls.quarantined });
    const reason = el('textarea', { id: 'safety-reason', required: true, maxlength: 1024, rows: 3 });
    dialog.content.append(notice('Inherited restrictions still apply. This changes policy, not the immutable manifest or source files.'),
      el('form', { onsubmit: async event => {
        event.preventDefault(); if (dialog.busy()) return; dialog.working(true);
        try {
          await request(`/datasets/${id}/safety`, { method: 'PUT', body: { revision: value.controls.revision,
            sensitive: sensitive.checked, inspection_required: required.checked, quarantined: quarantined.checked, reason: reason.value } });
          dialog.dialog.close(); await load();
        } catch (error) { status.replaceChildren(errorPanel(error)); }
        finally { dialog.working(false); }
      } }, el('label', { for: sensitive.id }, sensitive, 'Sensitive: approved managed workload placement'),
      el('label', { for: required.id }, required, 'Require no detection within recorded coverage before use or publication'),
      el('label', { for: quarantined.id }, quarantined, 'Quarantine: block dataset use and publication'),
      el('label', { for: reason.id }, 'Audited reason'), reason, status,
      el('button', { type: 'submit', class: 'primary' }, 'Save owner controls')));
  }

  function exemption() {
    const dialog = fileDialog('Exempt this dataset'), status = el('div');
    const reason = el('textarea', { id: 'exemption-reason', required: true, maxlength: 1024, rows: 3 });
    const until = el('input', { id: 'exemption-until', type: 'datetime-local' });
    const consent = el('input', { id: 'exemption-consent', type: 'checkbox', required: true });
    dialog.content.append(notice('An exemption permits this dataset despite its current inspection/quarantine result. It does not remove sensitivity or grant node trust. New scans and changed lineage policy invalidate it.', 'warning'),
      el('form', { onsubmit: async event => {
        event.preventDefault(); if (dialog.busy()) return; dialog.working(true);
        try {
          await request(`/datasets/${id}/exemption`, { method: 'PUT', body: { revision: value.controls.revision, enabled: true,
            reason: reason.value, expires_at: until.value ? new Date(until.value).getTime() / 1000 : null } });
          dialog.dialog.close(); await load();
        } catch (error) { status.replaceChildren(errorPanel(error)); }
        finally { dialog.working(false); }
      } }, el('label', { for: reason.id }, 'Audited exemption reason'), reason,
      el('label', { for: until.id }, 'Expiry (optional, local time)'), until,
      el('label', { for: consent.id }, consent, 'I authorise this exception for the exact current dataset safety state.'),
      status, el('button', { type: 'submit', class: 'danger' }, 'Grant exemption')));
  }

  function configure() {
    const dialog = fileDialog('Local inspection settings'), status = el('div');
    const config = el('textarea', { id: 'inspection-config', rows: 16, required: true }, JSON.stringify(settings.configuration, null, 2));
    dialog.content.append(notice('Install the trusted scanner package, engine and rules on this controller first. The worker has no network. Remote dataset files are unavailable here; they are never relayed for scanning.'),
      el('form', { onsubmit: async event => {
        event.preventDefault(); if (dialog.busy()) return; dialog.working(true);
        try { await request('/inspection-settings', { method: 'PUT', body: JSON.parse(config.value) }); dialog.dialog.close(); await load(); }
        catch (error) { status.replaceChildren(errorPanel(error)); }
        finally { dialog.working(false); }
      } }, el('label', { for: config.id }, 'Owner scanner configuration'), config, status,
      el('button', { type: 'submit', class: 'primary' }, 'Approve local inspection settings')));
  }

  async function coverage(run, after = null, dialog = fileDialog('Inspection coverage')) {
    try {
      const result = await request(`/inspections/${run.id}/files${after === null ? '' : `?after=${after}`}`);
      if (!dialog.active()) return;
      dialog.content.replaceChildren(...[details([['Inspection', run.id], ['Outcome', outcomes[run.outcome]], ['Finished', time(run.finished_at)],
        ['Files completed', `${run.completed_files} / ${run.total_files}`], ['Reason', run.reason ?? 'None']]),
      ...result.files.map(file => panel(`File ${file.file_index + 1}: ${outcomes[file.outcome]}`, [
        details([['SHA-256', file.sha256], ['Bytes', String(file.bytes)], ['Engine', file.engine.version ?? 'Unavailable'],
          ['Engine SHA-256', file.engine.sha256 ?? 'Unavailable'], ['Findings', file.findings?.join(', ') || 'None reported']]),
        el('pre', { class: 'file-content' }, JSON.stringify(file.coverage, null, 2)),
        table(['Signature file', 'SHA-256', 'Modified'], (file.signatures.files ?? []).map(item => el('tr', {},
          el('td', {}, item.name), el('td', { class: 'wrap transfer-hash' }, item.sha256), el('td', {}, time(item.modified_at)))), 'Recorded signature provenance')])),
      result.next_cursor === null ? null : button('Next file receipts', () => coverage(run, result.next_cursor, dialog))].filter(Boolean));
    } catch (error) { if (dialog.active()) dialog.content.replaceChildren(errorPanel(error)); }
  }

  async function load() {
    clearTimeout(timer);
    try {
      [value, settings] = await Promise.all([request(`/datasets/${id}/safety`), request('/inspection-settings')]);
      if (!view.active()) return;
      const run = value.inspection, active = run && run.state !== 'completed';
      content.replaceChildren(notice(value.blocked ? 'Dataset use and publication are blocked.' : value.exempt ? 'An explicit owner exemption permits use.' : 'Current dataset safety controls permit use.', value.blocked ? 'warning' : 'info'),
        details([['Sensitive', value.sensitive ? 'Yes' : 'No'], ['Inspection required', value.inspection_required ? 'Yes' : 'No'],
          ['Quarantine', value.quarantined ? 'Yes' : 'No'], ['Inherited datasets', value.inherited_count],
          ['Inspection', run ? active ? run.state : outcomes[run.outcome] : 'Not inspected'],
          ['Scanner', settings.configured ? settings.available ? settings.provider : 'Configured provider unavailable' : 'Not configured'],
          ['Exemption', value.exempt ? value.exemption.reason : 'None active']]),
        notice('Inspection records coverage, not a guarantee of safety. Original files are never deleted or moved by quarantine.'),
        el('div', { class: 'actions' }, button(active ? 'Inspection running' : 'Inspect / re-scan locally', async () => {
          try { await request(`/datasets/${id}/inspections`, { method: 'POST', body: {}, idempotencyKey: crypto.randomUUID() }); await load(); }
          catch (error) { errors.replaceChildren(errorPanel(error)); }
        }, { disabled: active || !allowed('files:write') }),
        active ? button('Cancel inspection', async () => {
          try { await request(`/inspections/${run.id}/cancel`, { method: 'POST', body: {}, timeout: null }); await load(); }
          catch (error) { errors.replaceChildren(errorPanel(error)); }
        }, { disabled: !allowed('files:write') }) : null,
        run ? button('Coverage and provenance', () => coverage(run)) : null,
        settings.can_manage ? button('Owner safety controls', controls) : null,
        settings.can_manage ? button('Explicit exemption', exemption) : null,
        settings.can_manage && value.exemption ? button('Revoke exemption', () => send(`/datasets/${id}/exemption`, {
          revision: value.controls.revision, enabled: false, reason: 'Owner revoked the dataset exemption.', expires_at: null })) : null,
        settings.can_manage ? button('Local scanner settings', configure) : null, button('Refresh safety', load)));
      if (active) timer = setTimeout(load, 2000);
    } catch (error) { if (view.active()) errors.replaceChildren(errorPanel(error)); }
  }
  load();
  return element;
}
