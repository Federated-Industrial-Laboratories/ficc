// SPDX-License-Identifier: Apache-2.0
// Inspect trusted policy packages, role assignments, activation, and effective access.
import { request } from './api.js';
import { button, confirmation, el, errorPanel, panel, table } from './components.js';

function encode(bytes) {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value);
}

export function policyAccess(owner) {
  const element = el('div'), message = el('div', { role: 'status' });
  let disposed = false, generation = 0, busy = false;
  const fail = error => { if (!disposed) message.replaceChildren(errorPanel(error)); };
  async function mutate(action, success) {
    if (busy || disposed) return;
    busy = true; element.inert = true; message.replaceChildren();
    try { await action(); await load(); message.textContent = success; }
    catch (error) { fail(error); }
    finally { busy = false; element.inert = false; }
  }
  async function load() {
    const serial = ++generation;
    try {
      if (!owner) {
        const state = await request('/policy-status');
        if (disposed || serial !== generation) return;
        element.replaceChildren(panel('Policy enforcement', [el('p', {}, state.required ?
          `Policy revision ${state.revision}: ${state.ready ? 'ready' : 'access denied while unavailable'}.` :
          'Current host grants apply. No policy package is active.'), previewForm(null, [], [])]), message);
        return;
      }
      const data = await request('/policies');
      const [{ identities }, { projects }] = await Promise.all([request('/identities'), request('/projects')])
        .catch(() => [{ identities: [] }, { projects: [] }]);
      if (disposed || serial !== generation) return;
      const state = data.state;
      const selected = el('select', { 'aria-label': 'Policy package' }, data.packages.map(item =>
        el('option', { value: item.digest }, `${item.manifest.id} ${item.manifest.release} / ${item.digest.slice(0, 12)}`)));
      if (state.active) selected.value = state.active;
      const detail = el('div');
      function inspect() {
        const item = data.packages.find(value => value.digest === selected.value);
        detail.replaceChildren(...(item ? [
          el('p', { class: 'fingerprint' }, `Publisher: ${item.publisher}. SHA256: ${item.digest}`),
          table(['Role', 'Purpose'], item.manifest.roles.map(role => el('tr', {},
            el('td', {}, role.label, el('small', { class: 'cell-note' }, role.id)),
            el('td', {}, role.description))), 'Policy package roles'),
          table(['Signed payload', 'SHA256'], Object.entries(item.manifest.files).map(([name, digest]) =>
            el('tr', {}, el('td', {}, name), el('td', { class: 'wrap' }, digest))), 'Signed policy payloads'),
        ] : [el('p', {}, 'Install a signed policy package to inspect its roles and payload.') ]));
      }
      selected.addEventListener('change', inspect); inspect();
      const publisherId = el('input', { 'aria-label': 'Policy publisher identifier', maxlength: '64' });
      const publicKey = el('textarea', { 'aria-label': 'Policy publisher public key', rows: '2', maxlength: '1024' });
      const trust = button('Trust policy publisher', () => confirmation('Trust this policy publisher?',
        'Policy packages control access decisions. Verify this public key through a trusted channel. An ordinary module cannot grant policy authority.',
        'Trust publisher', () => mutate(() => request('/policy-publishers', { method: 'PUT', body: {
          id: publisherId.value.trim(), public_key: publicKey.value.trim(), enabled: true, revision: 0,
        } }), 'Policy publisher trusted.')));
      const archive = el('input', { type: 'file', accept: '.zip,.ficcpolicy', 'aria-label': 'Signed policy package' });
      const install = button('Install policy package', async () => {
        const file = archive.files[0];
        if (!file || file.size > 512 * 1024) { message.textContent = 'Select a signed policy archive no larger than 512 KiB.'; return; }
        await mutate(async () => {
          const bytes = new Uint8Array(await file.arrayBuffer());
          await request('/policy-packages', { method: 'POST', body: { archive_base64: encode(bytes) } });
        }, 'Signed policy package installed. Activation is a separate action.');
      });
      const activate = digest => confirmation('Activate this policy package?',
        'Current operations and streams will use the new policy. Existing identity and resource grants remain upper limits. The local owner retains policy recovery access.',
        'Activate policy', () => mutate(() => request('/policy-activation', { method: 'POST', body: {
          digest, revision: state.revision,
        } }), 'Policy activated at a new revision.'));
      element.replaceChildren(
        panel('Policy enforcement', [el('p', {}, state.required ?
          `Revision ${state.revision}. ${state.ready ? 'The required evaluator is ready.' : 'Normal access is denied while the evaluator is unavailable.'}` :
          'No policy package is active. Current host grants apply.'),
          el('p', {}, state.error || (state.provider_configured ? 'A trusted evaluator is configured.' :
            'Install a trusted evaluator and configure it with the local command line before activation.')),
          el('p', {}, 'Contributor workload admission requires a qualified executor and lease. Managed shell and job access retain full remote-account authority.'),
          selected, detail, el('div', { class: 'actions' },
            button('Activate selected policy', () => activate(selected.value), { disabled: !data.packages.length }),
            button('Roll back policy', () => activate(state.previous), { disabled: !state.previous })),
          archive, install]),
        panel('Trusted policy publishers', [
          table(['Publisher', 'Public key fingerprint', 'State', 'Action'], data.publishers.map(item => el('tr', {},
            el('td', {}, item.id), el('td', { class: 'wrap' }, item.fingerprint),
            el('td', {}, item.enabled ? 'Trusted' : 'Disabled'),
            el('td', {}, button(item.enabled ? 'Disable publisher' : 'Enable publisher', () => confirmation(
              `${item.enabled ? 'Disable' : 'Enable'} policy publisher?`,
              item.enabled ? 'Access will be denied if the active policy uses this publisher.' : 'Verify the displayed key before restoring trust. Activate the policy again to resume access.',
              item.enabled ? 'Disable publisher' : 'Enable publisher', () => mutate(() => request('/policy-publishers', {
                method: 'PUT', body: { id: item.id, public_key: item.public_key, enabled: !item.enabled, revision: item.revision },
              }), 'Publisher trust updated.')))))), 'Policy publishers'),
          el('label', {}, 'Publisher identifier', publisherId), el('label', {}, 'Ed25519 public key', publicKey), trust]),
        bindingsForm(data, identities, projects), previewForm(selected, identities, projects), message);
    } catch (error) { fail(error); if (!element.childNodes.length) element.append(message); }
  }
  function bindingsForm(data, identities, projects) {
    if (!identities.length || !projects.length) return panel('Policy role assignments', [el('p', {},
      'Identity and project lists are unavailable until policy access is restored. Existing assignments are retained.')]);
    const project = el('select', { 'aria-label': 'Policy role project' }, projects.map(value => el('option', { value: value.id }, value.label)));
    const subject = el('select', { 'aria-label': 'Policy role identity' }, identities.map(value => el('option', { value: value.id }, value.label)));
    const list = el('div', { class: 'scope-list' }), rows = el('div');
    const choices = new Map(); let bindings = [], serial = 0, reading = false;
    const roles = [...new Map(data.packages.flatMap(item => item.manifest.roles).map(role => [role.id, role])).values()];
    function select() {
      const current = bindings.find(item => item.subject_id === subject.value);
      choices.clear(); list.replaceChildren(...roles.map(role => {
        const checkbox = el('input', { type: 'checkbox', checked: current?.roles.includes(role.id) || false });
        choices.set(role.id, checkbox); return el('label', {}, checkbox, ` ${role.label} (${role.id}) `);
      }));
    }
    async function read() {
      const id = ++serial; reading = true; save.disabled = true;
      bindings = []; choices.clear(); list.replaceChildren(); rows.textContent = 'Loading policy role assignments.';
      let loaded = false;
      if (!project.value) return;
      try {
        const response = await request(`/projects/${project.value}/policy-roles`);
        if (disposed || id !== serial) return;
        bindings = response.bindings; select();
        loaded = true;
        rows.replaceChildren(table(['Identity', 'Roles', 'Revision'], bindings.map(item => el('tr', {},
          el('td', {}, identities.find(value => value.id === item.subject_id)?.label || item.subject_id),
          el('td', {}, item.roles.join(', ') || 'No policy roles'), el('td', {}, String(item.revision)))), 'Policy role bindings'));
      } catch (error) { fail(error); }
      finally { if (id === serial) { reading = false; save.disabled = !loaded || !subject.value; } }
    }
    const save = button('Save policy roles', () => {
      if (reading) return;
      const selectedProject = project.value, selectedSubject = subject.value;
      const body = { revision: bindings.find(item => item.subject_id === selectedSubject)?.revision || 0,
        roles: [...choices].filter(([, input]) => input.checked).map(([role]) => role) };
      void mutate(() => request(`/projects/${selectedProject}/policy-roles/${selectedSubject}`, { method: 'PUT', body }), 'Policy roles saved.');
    }, { disabled: true });
    project.addEventListener('change', read); subject.addEventListener('change', select); void read();
    return panel('Policy role assignments', [el('p', {}, 'Roles come from installed packages. They restrict explicit project membership and resource grants. Unknown roles grant no access.'),
      project, subject, list, save, rows]);
  }
  function previewForm(selected, identities, projects) {
    const output = el('div');
    const action = el('input', { 'aria-label': 'Policy preview action', value: 'workspaces:write' });
    const node = el('input', { 'aria-label': 'Policy preview machine', placeholder: 'Optional machine ID' });
    const root = el('input', { 'aria-label': 'Policy preview folder', placeholder: 'Optional folder ID' });
    const subject = el('select', { 'aria-label': 'Policy preview identity' }, el('option', { value: '' }, 'Current credential'),
      identities.map(item => el('option', { value: item.id }, item.label)));
    const project = el('select', { 'aria-label': 'Policy preview project' }, el('option', { value: '' }, 'Current project'),
      projects.map(item => el('option', { value: item.id }, item.label)));
    const candidate = el('input', { type: 'checkbox', 'aria-label': 'Preview selected policy package', disabled: !selected });
    const run = button('Preview effective access', async () => {
      run.disabled = true; output.replaceChildren();
      try {
        const result = await request('/policy-preview', { method: 'POST', body: {
          requests: [{ action: action.value.trim(), node_id: node.value.trim() || null, root_id: root.value.trim() || null }],
          digest: candidate.checked ? selected.value : null,
          subject_id: subject.value || null, project_id: project.value || null,
        } });
        if (disposed) return;
        output.replaceChildren(el('p', {}, `Revision ${result.revision}. ${result.membership_preview ?
          'Membership ceiling preview; issued credentials can be narrower.' : 'Current credential preview.'}`),
        table(['Action', 'Host grants', 'Policy', 'Effective result', 'Reason'], result.decisions.map(item => el('tr', {},
          el('td', {}, item.action), el('td', {}, item.host_allowed ? 'Allow' : 'Deny'),
          el('td', {}, item.policy_allowed ? 'Allow' : 'Deny'), el('td', {}, item.allowed ? 'Allow' : 'Deny'),
          el('td', {}, item.reason))), 'Effective policy decisions'));
      } catch (error) { fail(error); }
      finally { run.disabled = false; }
    });
    return panel('Effective access preview', [action, node, root, subject, project,
      el('label', {}, candidate, ' Preview the selected package without activating it'), run, output]);
  }
  void load();
  return { element, dispose() { disposed = true; generation++; } };
}
