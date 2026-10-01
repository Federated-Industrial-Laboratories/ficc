// SPDX-License-Identifier: Apache-2.0
// Resume saved window layouts and remove unused records without changing module data.
import { request } from './api.js';
import { button, confirmation, el, notice, table } from './components.js';

export function savedLayouts(spaces, activeSurface, activeViews, openSurface) {
  const dialog = el('dialog', { class: 'module-manager', 'aria-label': 'Saved layouts' });
  const content = el('div'), status = el('div', { role: 'status' });
  const name = id => spaces.find(space => space.id === id)?.name || id;
  let disposed = false;
  const fail = error => { if (!disposed) status.replaceChildren(notice(error.message, 'error')); };
  function remove(url, label) {
    confirmation('Remove saved layout?', `${label}. Workspace data and module instances are retained. Close that window first to prevent it saving again.`,
      'Remove saved layout', async () => {
        await request(url, { method: 'DELETE' }); await refresh();
      });
  }
  async function refresh() {
    try {
      const value = await request('/workspace-layouts'); if (disposed) return;
      content.replaceChildren(el('h3', {}, `Window layouts (${value.surfaces.length}/64)`),
        table(['Window', 'Workspaces', 'Action'], value.surfaces.map(surface => el('tr', {},
          el('td', {}, surface.id === activeSurface ? 'Current window' : surface.id.slice(0, 12)),
          el('td', {}, surface.tiles.map(tile => name(tile.workspace_id)).join(', ') || 'Empty'),
          el('td', {}, button('Resume window layout', async event => {
            const control = event.currentTarget; control.disabled = true;
            try { await openSurface(surface.id); }
            catch (error) { fail(error); control.disabled = false; }
          }, { disabled: surface.id === activeSurface }),
          button('Remove window layout', () => remove(`/workspace-surfaces/${surface.id}?revision=${surface.revision}`,
            'The selected window arrangement is removed'), { disabled: surface.id === activeSurface })))), 'Saved window layouts'),
        el('h3', {}, `Unreferenced views (${value.unused_views.length})`),
        table(['Workspace', 'View', 'Action'], value.unused_views.map(view => el('tr', {},
          el('td', {}, name(view.workspace_id)), el('td', {}, view.id.slice(0, 12)),
          el('td', {}, button('Remove unused view', () => remove(`/workspaces/${view.workspace_id}/views/${view.id}?revision=${view.revision}`,
            'The selected panel arrangement is removed'), { disabled: activeViews.has(view.id) })))), 'Unused workspace views'));
    } catch (error) { fail(error); }
  }
  dialog.append(el('h2', {}, 'Saved layouts'), el('p', {}, 'Workspaces and module data are stored separately from window and panel arrangements.'),
    el('p', {}, 'Resume a saved layout in this window. Close its original window first. Open in window creates an independent arrangement.'),
    status, content, button('Refresh', () => { void refresh(); }), button('Close', () => dialog.close()));
  dialog.addEventListener('close', () => { disposed = true; dialog.remove(); });
  document.body.append(dialog); dialog.showModal(); void refresh();
  return { dispose() { dialog.close(); } };
}
