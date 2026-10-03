// SPDX-License-Identifier: Apache-2.0
// Explicitly share clean panel recipes and apply them through existing module grants.
import { allowed, request } from './api.js';
import { button, confirmation, el, notice, table } from './components.js';

export function workspaceTemplates(current, apply) {
  const dialog = el('dialog', { class: 'module-manager', 'aria-label': 'Project templates' });
  const content = el('div'), status = el('div', { role: 'status' });
  const name = el('input', { 'aria-label': 'Template name', maxlength: '80', value: current?.name || '' });
  let disposed = false;
  const fail = error => { if (!disposed) status.replaceChildren(notice(error.message, 'error')); };
  async function refresh() {
    try {
      const { templates } = await request('/workspace-templates');
      if (disposed) return;
      content.replaceChildren(table(['Template', 'Version', 'Panels', 'Actions'], templates.map(value => el('tr', {},
        el('td', {}, value.name), el('td', {}, String(value.version)), el('td', {}, value.panels.map(panel => panel.title).join(', ')),
        el('td', {}, button('Add panels to open workspace', async event => {
          event.currentTarget.disabled = true;
          try { if (await apply(value)) dialog.close(); else event.currentTarget.disabled = false; }
          catch (error) { fail(error); if (!disposed) event.currentTarget.disabled = false; }
        }, { disabled: !current || !allowed('workspaces:write') }),
        button('Remove template version', () => confirmation('Remove template version?',
          'Existing workspaces keep their panels and data.', 'Remove version', async () => {
            await request(`/workspace-templates/${value.id}`, { method: 'DELETE' }); await refresh();
          }), { disabled: !allowed('workspaces:write') })))), 'Shared project templates'));
    } catch (error) { fail(error); }
  }
  dialog.append(el('h2', {}, 'Project templates'),
    el('p', {}, 'Share a versioned list of module packages and panel titles with this project. Notes, saved inputs, system targets, permissions and private window layouts are excluded.'),
    el('p', {}, 'Open the destination workspace before applying a template. Its modules need current grants; choose targets when prompted.'),
    el('div', { class: 'toolbar' }, name, button('Share current panel template', async () => {
      try {
        if (!current) throw Error('Open a workspace first.');
        const workspace = await request(`/workspaces/${current.id}`);
        await request('/workspace-templates', { method: 'POST', body: { workspace_id: workspace.id, revision: workspace.revision, name: name.value.trim() } });
        status.replaceChildren(notice('A new template version is shared with this project.')); await refresh();
      } catch (error) { fail(error); }
    }, { disabled: !current || !allowed('workspaces:write') })), status, content, button('Close', () => dialog.close()));
  dialog.addEventListener('close', () => { disposed = true; dialog.remove(); });
  document.body.append(dialog); dialog.showModal(); void refresh();
  return { dispose() { dialog.close(); } };
}
