// SPDX-License-Identifier: Apache-2.0
// Own one Dockview panel layout and save only normal, bounded geometry.
import { createDockview, FloatingGroupModule, registerModules, themeLight } from './dockview.js';
import { button, confirmation, el, notice } from './components.js';
import { request } from './api.js';
import { renderModule } from './ui-renderer.js';
import { requiredCapabilities, selectTargets, workspaceCapability } from './module-targets.js';

registerModules([FloatingGroupModule]);
export const identity = () => crypto.randomUUID().replaceAll('-', '');

export function workspaceLayout({ workspace, viewId = identity(), modules, audio, changed, error, drafts = new Map() }) {
  let value = workspace, revision = 0, ready = false, disposed = false, timer, saving = Promise.resolve(), zoom;
  const element = el('div', { class: 'workspace-dock' }), components = new Map(), subscriptions = [];
  let pending = 0;
  function moduleFor(item) { return modules.find(candidate => candidate.digest === item.digest); }
  function queue(change, panelId) {
    pending++;
    saving = saving.catch(() => {}).then(async () => {
      const next = structuredClone(value); change(next);
      const path = panelId ? `/workspaces/${value.id}/instances/${panelId}/state` : `/workspaces/${value.id}`;
      const body = panelId ? { revision: value.revision, state: next.instances.find(row => row.id === panelId).state } :
        { revision: value.revision, name: next.name, instances: next.instances };
      const saved = await request(path, { method: 'PUT', body });
      value = saved; changed(saved); return saved;
    }).finally(() => { pending--; });
    return saving;
  }
  function restoreZoom() {
    if (!zoom) return;
    const previous = zoom; zoom = null; api.exitMaximizedGroup();
    const control = components.get(previous.id)?.expandControl;
    if (control) { control.textContent = 'Expand'; control.setAttribute('aria-pressed', 'false'); }
    const panel = api.getPanel(previous.id);
    if (panel && previous.position) api.addFloatingGroup(panel.group, { position: previous.position,
      width: previous.position.width, height: previous.position.height });
    saveSoon();
  }
  function maximize(id) {
    if (zoom) { restoreZoom(); return; }
    const panel = api.getPanel(id); if (!panel) return;
    const position = api.toJSON().floatingGroups?.find(group => group.data?.id === panel.group.id)?.position;
    zoom = { id, position }; clearTimeout(timer);
    const control = components.get(id)?.expandControl;
    if (control) { control.textContent = 'Restore panel'; control.setAttribute('aria-pressed', 'true'); }
    if (position) panel.group.api.moveTo({ position: 'right' });
    panel.api.maximize();
  }
  function float(id) {
    restoreZoom(); const panel = api.getPanel(id); if (!panel) return;
    api.addFloatingGroup(panel, { position: { left: 16, top: 16 }, width: Math.min(480, api.width), height: Math.min(400, api.height) });
    saveSoon();
  }
  function dock(id) {
    restoreZoom(); const panel = api.getPanel(id); if (!panel) return;
    panel.api.moveTo({ group: api.addGroup({ direction: 'right' }) }); saveSoon();
  }
  const api = createDockview(element, { theme: themeLight, floatingGroupBounds: 'boundedWithinViewport',
    createComponent() {
      const frame = el('div', { class: 'module-frame' }); let component, panelId;
      return { element: frame, init(options) {
        panelId = options.params.instanceId;
        const item = value.instances.find(candidate => candidate.id === panelId), module = item && moduleFor(item);
        if (!item || !module?.enabled || requiredCapabilities(module.manifest).some(capability =>
          !(workspaceCapability(capability) ? [value.id] : item.targets || []).length ||
          !module.grants.some(grant => grant.capability === capability &&
            (workspaceCapability(capability) ? [value.id] : item.targets || []).every(id => grant.target_ids.includes(id))))) {
          frame.append(notice('This module is missing, disabled or not granted to this workspace. Its saved data is retained.')); return;
        }
        if (!drafts.has(panelId)) drafts.set(panelId, {});
        component = renderModule(item, module, { audio, workspaceId: value.id, drafts: drafts.get(panelId),
          saveState: state => queue(next => { Object.assign(next.instances.find(row => row.id === panelId).state, state); }, panelId),
          invoke: (action, parameters) => request('/module-invocations', { method: 'POST',
            body: { workspace_id: value.id, instance_id: panelId, action, parameters, targets: item.targets?.length ? item.targets : [value.id] } }),
        });
        component.expandControl = button('Expand', () => maximize(panelId), { 'aria-pressed': 'false' });
        const tools = el('div', { class: 'module-tools', role: 'toolbar', 'aria-label': `${item.title} window controls` },
          button('Float', () => float(panelId)), button('Dock', () => dock(panelId)), component.expandControl,
          ...(module.manifest.capabilities.some(capability => !workspaceCapability(capability)) ? [button('Select targets', async () => {
            try {
              if (Object.keys(drafts.get(panelId) || {}).length) throw Error('Save or discard unsaved text before changing targets.');
              const targets = await selectTargets(module, item.targets || []); if (targets === null) return;
              await component.flush();
              await queue(next => { next.instances.find(row => row.id === panelId).targets = targets; });
              const saved = layout(); ready = false; api.clear(); api.fromJSON(saved); ready = true; saveSoon();
            } catch (failure) { error(failure); }
          })] : []),
          button('Hide', () => options.api.close()), button('Remove panel', () => confirmation('Remove module panel?',
            'This panel and its saved data are deleted. Other saved layouts containing it will reset. Managed systems are unchanged.',
            'Remove panel', async () => {
              await saving.catch(() => {}); clearTimeout(timer); timer = null; ready = false;
              try {
                await queue(next => { next.instances = next.instances.filter(row => row.id !== panelId); });
                drafts.delete(panelId); options.api.close();
                revision = (await request(`/workspaces/${value.id}/views/${viewId}`)).revision;
              } finally { ready = true; saveSoon(); }
            })));
        frame.append(tools, component.element); components.set(panelId, component);
      }, onShow() { component?.setVisible(true); }, onHide() { component?.setVisible(false); },
      dispose() { component?.dispose(); components.delete(panelId); } };
    },
  });
  function add(item, floating = false) {
    if (api.getPanel(item.id)) { api.getPanel(item.id).api.setActive(); return; }
    api.addPanel({ id: item.id, title: item.title, component: 'module', params: { instanceId: item.id },
      minimumWidth: 220, minimumHeight: 150, ...(floating ? { floating: { x: 16, y: 16, width: 450, height: 350 } } : {}) });
  }
  function layout() {
    const state = api.toJSON();
    for (const group of state.floatingGroups || []) {
      const p = group.position, width = Math.max(1, api.width), height = Math.max(1, api.height);
      p.width = Math.min(Math.max(100, p.width), width); p.height = Math.min(Math.max(80, p.height), height);
      p.left = Math.max(0, Math.min(Number(p.left ?? width - p.right - p.width) || 0, width - p.width));
      p.top = Math.max(0, Math.min(Number(p.top ?? height - p.bottom - p.height) || 0, height - p.height));
      delete p.right; delete p.bottom;
    }
    return state;
  }
  function saveSoon() {
    if (!ready || disposed || zoom) return;
    clearTimeout(timer); timer = setTimeout(saveLayout, 250);
  }
  function saveLayout() {
      clearTimeout(timer); timer = null;
      if (!ready || disposed || zoom) return saving;
      const state = layout();
      pending++;
      saving = saving.catch(() => {}).then(async () => {
        const result = await request(`/workspaces/${value.id}/views/${viewId}`, { method: 'PUT', body: { revision, layout: state } });
        revision = result.revision;
      }).finally(() => { pending--; });
      void saving.catch(error); return saving;
  }
  subscriptions.push(api.onDidLayoutChange(saveSoon));
  subscriptions.push(api.onDidMaximizedGroupChange(() => { if (zoom && !api.hasMaximizedGroup()) queueMicrotask(restoreZoom); }));
  const observer = new ResizeObserver(() => {
    for (const group of api.groups) if (group.api.location.type === 'floating') {
      group.api.setSize({ width: Math.min(group.width, api.width), height: Math.min(group.height, api.height) });
    }
  }); observer.observe(element);
  void request(`/workspaces/${value.id}/views/${viewId}`).then(saved => {
    if (disposed) return;
    revision = saved.revision;
    if (saved.layout?.grid) {
      try { api.fromJSON(saved.layout); } catch { api.clear(); for (const item of value.instances) add(item); }
    } else for (const item of value.instances) add(item);
    ready = true;
  }).catch(error);
  return { element, get workspace() { return value; }, get viewId() { return viewId; },
    get dirty() { return [...drafts.values()].some(value => Object.keys(value).length); },
    get pending() { return Boolean(pending || timer); },
    async flush() { await Promise.all([...components.values()].map(component => component.flush())); await saveLayout(); },
    refreshPackages() { const saved = layout(); ready = false; api.clear(); api.fromJSON(saved); ready = true; },
    discard() { for (const draft of drafts.values()) for (const key of Object.keys(draft)) delete draft[key]; this.refreshPackages(); },
    async reload() {
      if (this.dirty) throw Error('Save or discard unsaved text before reloading.');
      const [workspace, view] = await Promise.all([request(`/workspaces/${value.id}`), request(`/workspaces/${value.id}/views/${viewId}`)]);
      ready = false; clearTimeout(timer); await saving.catch(() => {}); value = workspace; revision = view.revision;
      api.clear(); if (view.layout?.grid) api.fromJSON(view.layout); else for (const item of value.instances) add(item);
      ready = true; changed(value);
    },
    async addModule(module) {
      const targets = await selectTargets(module); if (targets === null) return;
      const item = { id: identity(), digest: module.digest, title: module.manifest.display_name || module.manifest.id, state: {}, targets };
      await queue(next => { next.instances.push(item); }); add(item, true); saveSoon();
    },
    showAll() { for (const item of value.instances) add(item); saveSoon(); },
    recover() { restoreZoom(); for (const item of value.instances) { add(item); dock(item.id); } saveSoon(); },
    rename(name) { return queue(next => { next.name = name; }); },
    dispose() { if (disposed) return saving; const completion = saveLayout(); void completion?.catch(error);
      disposed = true; clearTimeout(timer); observer.disconnect();
      for (const subscription of subscriptions) subscription.dispose(); api.dispose(); return completion; },
  };
}
