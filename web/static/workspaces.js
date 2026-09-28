// SPDX-License-Identifier: Apache-2.0
// Arrange saved workspaces in independent authenticated browser surfaces.
import { createDockview, themeLight } from './dockview.js';
import { request } from './api.js';
import { button, confirmation, el, heading, notice } from './components.js';
import { getAudioManager } from './audio-manager.js';
import { fullscreen } from './fullscreen.js';
import { moduleManager } from './module-manager.js';
import { identity, workspaceLayout } from './workspace-layout.js';
import { savedLayouts } from './workspace-saved-layouts.js';
import { vmProfiles } from './vm-profiles.js';
import { containerProfiles } from './container-profiles.js';
import { adminProfiles } from './admin-profiles.js';
import { adapterProfiles } from './adapter-profiles.js';
import { windowsEndpoints } from './windows-endpoints.js';

export function workspaces() {
  const query = new URLSearchParams(location.search), valid = value => /^[a-f0-9]{32}$/.test(value || '');
  const surfaceId = valid(query.get('surface')) ? query.get('surface') : identity();
  query.set('surface', surfaceId); history.replaceState(null, '', `/?${query}`);
  const element = el('section', { class: 'workspaces' }), message = el('div', { role: 'status' });
  const canvas = el('div', { class: 'workspace-surface' }), workspaceSelect = el('select', { 'aria-label': 'Saved workspace' });
  const moduleSelect = el('select', { 'aria-label': 'Installed module' });
  const name = el('input', { 'aria-label': 'Workspace name', maxlength: '80', placeholder: 'Workspace name' });
  let spaces = [], modules = [], tiles = [], revision = 0, disposed = false, ready = false, saveTimer, manager;
  let saveWork = Promise.resolve(), pending = 0; const layouts = new Map(), drafts = new Map(), closing = new Set();
  const dirty = () => [...drafts.values()].some(items => [...items.values()].some(value => Object.keys(value).length));
  const unload = event => {
    if (dirty() || pending || saveTimer || closing.size || [...layouts.values()].some(layout => layout.pending)) {
      event.preventDefault(); event.returnValue = '';
    }
  };
  window.addEventListener('beforeunload', unload);
  function fail(error) { if (!disposed) message.replaceChildren(notice(error.message, 'error')); }
  const audio = getAudioManager({ authority: {
    loadPreferences: () => request('/audio/preferences'),
    savePreferences: body => request('/audio/preferences', { method: 'PUT', body }),
    acquire: instance => request('/audio/leases', { method: 'POST', body: { instance_id: instance, surface_id: surfaceId } }),
    heartbeat: (instance, lease) => request(`/audio/leases/${lease.id}`, { method: 'PUT', body: { surface_id: surfaceId } }),
    release: (instance, lease) => request(`/audio/leases/${lease.id}`, { method: 'DELETE', body: { surface_id: surfaceId } }),
  } });
  const sound = audio.controls();
  function selected() {
    const tile = api.activePanel && tiles.find(item => item.id === api.activePanel.id);
    return tile && layouts.get(tile.id);
  }
  function updateSelects() {
    const previous = workspaceSelect.value, packageId = moduleSelect.value;
    workspaceSelect.replaceChildren(...spaces.map(space => el('option', { value: space.id }, space.name)));
    if (spaces.some(space => space.id === previous)) workspaceSelect.value = previous;
    moduleSelect.replaceChildren(...modules.filter(module => module.enabled && module.manifest.role !== 'provider-adapter').map(module =>
      el('option', { value: module.digest }, module.manifest.display_name || module.manifest.id)));
    if (modules.some(module => module.digest === packageId && module.enabled && module.manifest.role !== 'provider-adapter')) moduleSelect.value = packageId;
  }
  const api = createDockview(canvas, { theme: themeLight, disableFloatingGroups: true,
    createComponent(options) {
      const frame = el('section', { class: 'workspace-tile' }); let layout;
      return { element: frame, init() {
        const tile = tiles.find(item => item.id === options.id), workspace = tile && spaces.find(item => item.id === tile.workspace_id);
        if (!workspace) { frame.append(notice('The workspace is unavailable. Close this tile and select another workspace.')); return; }
        if (!drafts.has(workspace.id)) drafts.set(workspace.id, new Map());
        layout = workspaceLayout({ workspace, viewId: tile.view_id, modules, audio, error: fail, drafts: drafts.get(workspace.id),
          changed: value => { spaces = spaces.map(item => item.id === value.id ? value : item); updateSelects();
            api.getPanel(tile.id)?.api.setTitle(value.name); } });
        layouts.set(tile.id, layout); frame.append(layout.element);
      }, dispose() {
        const completion = layout?.dispose();
        if (completion) { closing.add(completion); void completion.catch(fail).finally(() => closing.delete(completion)); }
        layouts.delete(options.id);
      } };
    },
  });
  function saveSoon() {
    if (!ready || disposed) return;
    clearTimeout(saveTimer); saveTimer = setTimeout(saveSurface, 250);
  }
  function saveSurface() {
      clearTimeout(saveTimer); saveTimer = null;
      if (!ready || disposed) return saveWork;
      const layout = api.toJSON(), visible = tiles.filter(tile => api.getPanel(tile.id)); tiles = visible;
      pending++;
      saveWork = saveWork.catch(() => {}).then(async () => {
        const result = await request(`/workspace-surfaces/${surfaceId}`, { method: 'PUT', body: { revision, tiles: visible, layout } });
        revision = result.revision;
      }).finally(() => { pending--; });
      void saveWork.catch(fail); return saveWork;
  }
  const subscription = api.onDidLayoutChange(saveSoon);
  function open(workspaceId = workspaceSelect.value, direction = 'right') {
    if (!spaces.some(item => item.id === workspaceId)) return;
    const existing = tiles.find(item => item.workspace_id === workspaceId && api.getPanel(item.id));
    if (existing) { api.getPanel(existing.id).api.setActive(); return; }
    if (api.panels.length >= 4) { fail(Error('Close a workspace tile before opening another. The limit is four.')); return; }
    const tile = { id: identity(), workspace_id: workspaceId, view_id: identity() }; tiles.push(tile);
    api.addPanel({ id: tile.id, component: 'workspace', title: spaces.find(item => item.id === workspaceId).name,
      minimumWidth: 260, minimumHeight: 220, position: { direction } }); saveSoon();
  }
  const expand = button('Expand workspace area', () => screen.expand());
  const full = button('Fullscreen', () => { void screen.toggle().catch(fail); });
  const screen = fullscreen(element, state => {
    expand.textContent = state.expanded ? 'Restore workspace area' : 'Expand workspace area';
    full.textContent = state.fullscreen ? 'Exit fullscreen' : 'Fullscreen';
  });
  const actions = el('div', { class: 'workspace-toolbar' }, workspaceSelect,
    button('Open', () => open()), button('Split right', () => open(workspaceSelect.value, 'right')),
    button('Split below', () => open(workspaceSelect.value, 'below')),
    button('Open in window', () => {
      if (!workspaceSelect.value) return;
      const url = `/?workspace=${workspaceSelect.value}&surface=${identity()}&window=1`;
      const child = window.open(url, '_blank');
      if (child) child.opener = null;
      else message.replaceChildren(notice('The browser blocked the workspace window.'), el('a', { href: url, target: '_blank', rel: 'noopener' }, 'Open workspace window'));
    }), expand, full,
    button('Recover panels', () => selected()?.recover()), button('Show hidden panels', () => selected()?.showAll()),
    button('Reload saved workspace', () => { void selected()?.reload().catch(fail); }),
    button('Saved layouts', () => { manager?.dispose(); manager = savedLayouts(spaces, surfaceId, new Set([...layouts.values()].map(layout => layout.viewId))); }),
    button('Discard unsaved text', () => confirmation('Discard unsaved text?', 'Unsaved text in this window is removed. Saved notes are retained.',
      'Discard unsaved text', () => { for (const layout of layouts.values()) layout.discard();
        for (const items of drafts.values()) for (const draft of items.values()) for (const key of Object.keys(draft)) delete draft[key]; })));
  const edit = el('div', { class: 'workspace-toolbar' }, name,
    button('New workspace', async () => {
      try { const value = await request('/workspaces', { method: 'POST', body: { name: name.value.trim() } });
        spaces.push(value); updateSelects(); workspaceSelect.value = value.id; open(value.id); name.value = ''; }
      catch (error) { fail(error); }
    }), button('Rename', () => {
      if (selected() && name.value.trim()) void selected().rename(name.value.trim()).catch(fail);
    }), button('Delete workspace', () => {
      const current = spaces.find(item => item.id === workspaceSelect.value); if (!current) return;
      confirmation('Delete workspace?', 'The saved panels and notes are deleted. Managed machines and workloads are unchanged.', 'Delete workspace', async () => {
        await request(`/workspaces/${current.id}?revision=${current.revision}`, { method: 'DELETE' });
        for (const tile of tiles.filter(item => item.workspace_id === current.id)) { const panel = api.getPanel(tile.id); if (panel) api.removePanel(panel); }
        spaces = spaces.filter(item => item.id !== current.id); drafts.delete(current.id); updateSelects();
        const surface = await request(`/workspace-surfaces/${surfaceId}`); revision = surface.revision; saveSoon();
      });
    }), moduleSelect, button('Add module', () => {
      const module = modules.find(item => item.digest === moduleSelect.value);
      if (module && selected()) void selected().addModule(module).catch(fail);
      else fail(Error('Open a workspace and enable a module first.'));
    }), button('Manage modules', () => { manager = moduleManager(spaces, value => {
      modules.splice(0, modules.length, ...value); updateSelects(); for (const layout of layouts.values()) layout.refreshPackages();
    }); }), button('VM providers', () => { manager?.dispose(); manager = vmProfiles(); }),
    button('Container providers', () => { manager?.dispose(); manager = containerProfiles(); }),
    button('Administration profiles', () => { manager?.dispose(); manager = adminProfiles(); }),
    button('Provider adapters', () => { manager?.dispose(); manager = adapterProfiles(); }),
    button('Windows endpoints', () => { manager?.dispose(); manager = windowsEndpoints(); }));
  element.append(heading('PERSISTENT / LOCAL', 'Workspace', 'Arrange module panels and open separate workspace windows.'), actions, edit, sound.element, message, canvas);
  void Promise.all([request('/workspaces'), request('/modules'), request(`/workspace-surfaces/${surfaceId}`)]).then(([saved, packages, surface]) => {
    if (disposed) return;
    spaces = saved.workspaces; modules.push(...packages.modules); updateSelects(); revision = surface.revision;
    tiles = surface.tiles.filter(tile => spaces.some(space => space.id === tile.workspace_id));
    if (surface.layout?.grid && tiles.length === surface.tiles.length) {
      try { api.fromJSON(surface.layout); } catch { api.clear(); tiles = []; }
    }
    ready = true;
    const initial = valid(query.get('workspace')) ? query.get('workspace') : spaces[0]?.id;
    if (!api.panels.length && initial) open(initial);
    if (!spaces.length) message.replaceChildren(notice('Create a workspace, then install and enable modules with Manage modules.'));
  }).catch(fail);
  return { element, async prepareLeave() {
    if (dirty()) { fail(Error('Save or discard unsaved text before leaving Workspace. Open their workspace and select Show hidden panels if needed.')); return false; }
    try { await Promise.all([...layouts.values()].map(layout => layout.flush())); await Promise.all(closing); await saveSurface(); return true; }
    catch (error) { fail(error); return false; }
  }, dispose() { if (disposed) return; disposed = true; clearTimeout(saveTimer); window.removeEventListener('beforeunload', unload);
    manager?.dispose(); screen.dispose(); subscription.dispose(); api.dispose(); sound.dispose(); audio.dispose(); } };
}
