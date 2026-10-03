// SPDX-License-Identifier: Apache-2.0
// Administer durable identities and explicit project membership grants.
import { request } from './api.js';
import { button, confirmation, el, errorPanel, panel, table } from './components.js';
import { projectResources } from './project-resources.js';

export function projectAccess() {
  const element = el('div', { class: 'project-access' }), message = el('div', { role: 'status' });
  let disposed = false, resources = null;
  const fail = error => { if (!disposed) message.replaceChildren(errorPanel(error)); };
  async function load() {
    try {
      const [{ identities }, { projects, project_scopes: scopes }] = await Promise.all([
        request('/identities'), request('/projects'),
      ]);
      if (disposed) return;
      const userName = el('input', { 'aria-label': 'New identity label', maxlength: '80' });
      const projectName = el('input', { 'aria-label': 'New project label', maxlength: '80' });
      const create = async (path, input) => {
        try { await request(path, { method: 'POST', body: { label: input.value.trim() } }); await load(); window.dispatchEvent(new Event('ficc-projects-changed')); }
        catch (error) { fail(error); }
      };
      const entries = (items, path, recovery) => items.map(item => el('tr', {},
        el('td', {}, item.label, el('small', { class: 'cell-note' }, item.id)),
        el('td', {}, item.disabled ? 'Disabled' : 'Enabled'),
        el('td', {}, button(item.disabled ? 'Enable' : 'Disable', () => {
          confirmation(`${item.disabled ? 'Enable' : 'Disable'} ${item.label}?`,
            item.disabled ? 'Existing membership grants will apply to new credentials.' : 'Active credentials for this identity or project will be revoked.',
            item.disabled ? 'Enable' : 'Disable', async () => {
              await request(`${path}/${item.id}`, { method: 'PUT', body: {
                label: item.label, disabled: !item.disabled, revision: item.revision,
              } }); await load();
            });
        }, { disabled: item.id === recovery, 'aria-label': `${item.disabled ? 'Enable' : 'Disable'} ${item.label}` }))));
      const project = el('select', { 'aria-label': 'Membership project' }, projects.map(item => el('option', { value: item.id }, item.label)));
      const subject = el('select', { 'aria-label': 'Membership identity' }, identities.filter(item => item.id !== '00000000000000000000000000000001')
        .map(item => el('option', { value: item.id }, item.label)));
      const grantList = el('div', { class: 'scope-list' }), memberRows = el('div');
      const selected = new Map(); let members = [], generation = 0;
      function grants() {
        const current = members.find(item => item.subject_id === subject.value);
        selected.clear();
        grantList.replaceChildren(...scopes.map(scope => {
          const checkbox = el('input', { type: 'checkbox', checked: current?.scopes.includes(scope) || false });
          selected.set(scope, checkbox);
          return el('label', {}, checkbox, ` ${scope} `);
        }));
      }
      async function readMembers() {
        const serial = ++generation;
        save.disabled = true; selected.clear(); grantList.replaceChildren();
        memberRows.textContent = 'Loading project membership.';
        try {
          const response = await request(`/projects/${project.value}/members`);
          if (disposed || serial !== generation) return;
          members = response.members; grants(); save.disabled = !subject.value;
          memberRows.replaceChildren(table(['Identity', 'Capabilities', 'Revision'], members.map(member => el('tr', {},
            el('td', {}, identities.find(item => item.id === member.subject_id)?.label || member.subject_id),
            el('td', {}, member.scopes.join(', ') || 'No access'), el('td', {}, String(member.revision)))), 'Project memberships'));
        } catch (error) { fail(error); }
      }
      project.addEventListener('change', readMembers);
      subject.addEventListener('change', grants);
      const save = button('Save membership', async () => {
        save.disabled = true;
        try {
          const revision = members.find(item => item.subject_id === subject.value)?.revision || 0;
          await request(`/projects/${project.value}/members/${subject.value}`, { method: 'PUT', body: {
            revision, scopes: [...selected].filter(([, input]) => input.checked).map(([scope]) => scope),
          } }); await readMembers();
          message.textContent = 'Membership saved. Current requests use the updated grants.';
        } catch (error) { fail(error); }
        finally { save.disabled = !subject.value; }
      }, { disabled: !subject.value });
      resources?.dispose(); resources = projectResources(projects);
      element.replaceChildren(
        panel('User identities', [el('p', {}, 'Local control creates sign-in links. Membership grants determine project access.'),
          el('div', { class: 'actions' }, el('label', {}, 'Identity label', userName), button('Create identity', () => create('/identities', userName))),
          table(['Identity', 'State', 'Action'], entries(identities, '/identities', '00000000000000000000000000000001'), 'User identities')]),
        panel('Projects', [el('div', { class: 'actions' }, el('label', {}, 'Project label', projectName), button('Create project', () => create('/projects', projectName))),
          table(['Project', 'State', 'Action'], entries(projects, '/projects', '00000000000000000000000000000002'), 'Projects')]),
        panel('Project membership', [el('p', {}, 'Select explicit capabilities. Job execution and terminals have full remote-account authority; folder restrictions do not constrain shell commands. Clear all grants to revoke membership.'),
          project, subject, grantList, save, memberRows]), resources.element, message);
      await readMembers();
    } catch (error) { fail(error); }
  }
  void load();
  return { element, dispose() { disposed = true; resources?.dispose(); } };
}
