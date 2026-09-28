// SPDX-License-Identifier: Apache-2.0
// Inspect package sources and show exact workspace grants before activation.
import { request } from './api.js';
import { button, confirmation, el, notice, table } from './components.js';
import { requiredCapabilities } from './module-targets.js';
import { adapterProfiles } from './adapter-profiles.js';

export function moduleManager(workspaces, changed) {
  const dialog = el('dialog', { class: 'module-manager', 'aria-label': 'Module manager' });
  const feedback = el('div', { role: 'status' }), installed = el('div'), inspection = el('div');
  const file = el('input', { type: 'file', accept: '.ficc-module,.zip', 'aria-label': 'Module package' });
  const supplied = el('select', { 'aria-label': 'Supplied module' });
  const url = el('input', { type: 'url', placeholder: 'https://packages.example/module.ficc-module', 'aria-label': 'Package URL' });
  const digest = el('input', { type: 'text', maxlength: '64', 'aria-label': 'Expected SHA-256', placeholder: 'Optional for HTTPS' });
  const privateNetwork = el('input', { type: 'checkbox' }), insecure = el('input', { type: 'checkbox' });
  let disposed = false, previewId = null, inspecting = false, adapterManager, catalogue = { capabilities: {}, targets: {} };
  async function releasePreview() {
    const id = previewId; previewId = null;
    if (id) await request(`/module-install-previews/${id}`, { method: 'DELETE' }).catch(() => {});
  }
  const fail = error => { if (!disposed) feedback.replaceChildren(notice(error.message, 'error')); };
  async function inspect(source) {
    if (inspecting || disposed) return;
    inspecting = true;
    await releasePreview();
    feedback.replaceChildren(notice('Inspecting package. No package code is running.'));
    inspection.replaceChildren();
    try {
      let result;
      if (source === 'file') {
        const selected = file.files[0];
        if (!selected || selected.size > 16 * 1024 * 1024) throw Error('Select a package of at most 16 MiB.');
        result = await request('/module-install-previews', { method: 'POST', bytes: await selected.arrayBuffer() });
      } else if (source === 'supplied') result = await request('/supplied-module-previews', {
        method: 'POST', body: { package_id: supplied.value },
      });
      else result = await request('/module-fetch-previews', { method: 'POST', body: {
        url: url.value, expected_digest: digest.value || null, allow_private_network: privateNetwork.checked, allow_http: insecure.checked,
      } });
      previewId = result.preview_id;
      if (disposed) { await releasePreview(); return; }
      const manifest = result.manifest, accept = el('input', { type: 'checkbox' });
      inspection.append(el('h3', {}, 'Package inspection'), table(['Field', 'Value'], [
        ['Package', manifest.id], ['Version', manifest.version], ['Category', manifest.category],
        ['Source', result.source], ['Publisher', 'Unverified'], ['SHA-256', result.digest],
        ['Runtime', `${manifest.runtime.kind} / ${manifest.runtime.language}`],
        ['Role', manifest.role === 'provider-adapter' ? 'Provider account adapter' : 'Workspace module'],
        ['Required permissions', requiredCapabilities(manifest).join(', ') || 'None'],
        ['Optional permissions', (manifest.optional_capabilities || []).join(', ') || 'None'],
        ['Expanded size', `${result.expanded_bytes} bytes`],
      ].map(([name, value]) => el('tr', {}, el('th', { scope: 'row' }, name), el('td', {}, value))), 'Inspected module package'),
      el('p', {}, 'A checksum identifies bytes. It does not establish publisher trust. Install packages only from sources you trust.'),
      manifest.role === 'provider-adapter' ? notice('Provider adapters require a separate account grant. That grant can permit changes to all VMs accessible to the provider account.') : null,
      el('label', {}, accept, ' I accept this unverified package source.'),
      button('Install disabled', async event => {
        const control = event.currentTarget; control.disabled = true;
        try {
          if (!accept.checked) throw Error('Confirm the unverified package source first.');
          await request('/modules', { method: 'POST', body: { preview_id: result.preview_id, digest: result.digest, accept_unverified: true } });
          previewId = null;
          inspection.replaceChildren(); feedback.replaceChildren(notice('Package installed. Review grants before enabling it.')); await refresh();
        } catch (error) { fail(error); }
        finally { control.disabled = false; }
      }));
      feedback.replaceChildren();
    } catch (error) { fail(error); }
    finally { inspecting = false; }
  }
  function grant(module) {
    void releasePreview();
    const panel = el('section', { class: 'module-grants' }), choices = [];
    panel.append(el('h3', {}, `Enable ${module.manifest.display_name || module.manifest.id}`),
      el('p', {}, 'Select exact targets for required permissions. Optional permissions can stay ungranted; actions that use them will remain unavailable. These grants apply to this package digest only.'));
    for (const capability of module.manifest.capabilities) {
      const spec = catalogue.capabilities[capability];
      const targets = (spec?.kind === 'workspace' ? workspaces : catalogue.targets[spec?.kind] || [])
        .filter(target => !target.capabilities || target.capabilities.includes(capability));
      const optional = (module.manifest.optional_capabilities || []).includes(capability);
      const group = el('fieldset', {}, el('legend', {}, `${capability}${spec ? `: ${spec.label}` : ' (unavailable)'}${optional ? ' (optional)' : ''}`));
      for (const workspace of targets) {
        const input = el('input', { type: 'checkbox' });
        input.checked = module.grants.some(grant => grant.capability === capability && grant.target_ids.includes(workspace.id));
        choices.push({ capability, workspace: workspace.id, input });
        group.append(el('label', {}, input, ` ${workspace.name}`));
      }
      if (!targets.length) group.append(el('p', {}, 'No targets are available for this permission. Create a workspace, enroll a system or register a folder first.'));
      panel.append(group);
    }
    panel.append(button('Enable with selected grants', async event => {
      const control = event.currentTarget; control.disabled = true;
      try {
        const grants = module.manifest.capabilities.map(capability => ({ capability,
          target_ids: choices.filter(item => item.capability === capability && item.input.checked).map(item => item.workspace),
        })).filter(item => item.target_ids.length);
        await request(`/modules/${module.digest}/activation`, { method: 'POST', body: { enabled: true, grants } });
        inspection.replaceChildren(); await refresh();
      } catch (error) { fail(error); }
      finally { control.disabled = false; }
    }), button('Cancel', () => inspection.replaceChildren()));
    inspection.replaceChildren(panel);
  }
  async function refresh() {
    try {
      const [result, targets, defaults] = await Promise.all([request('/modules'), request('/module-targets'), request('/supplied-modules')]); if (disposed) return;
      catalogue = targets;
      supplied.replaceChildren(...defaults.modules.map(item => el('option', { value: item.id }, `${item.display_name} ${item.version}`)));
      if (!defaults.modules.length) supplied.append(el('option', { value: '' }, 'No supplied archives in this installation'));
      const rows = result.modules.map(module => {
        const adapter = module.manifest.role === 'provider-adapter';
        const profiles = () => { adapterManager?.dispose(); adapterManager = adapterProfiles(() => { void refresh(); }); };
        const toggle = module.enabled ? button('Disable', async () => {
          try { await request(`/modules/${module.digest}/activation`, { method: 'POST', body: { enabled: false, grants: [] } }); await refresh(); }
          catch (error) { fail(error); }
        }) : adapter ? button('Provider profiles', profiles) : button('Enable', () => grant(module));
        const remove = button('Remove', () => confirmation('Remove module?',
          'The package is removed. Saved workspace data stays available.', 'Remove', async () => {
            await request(`/modules/${module.digest}`, { method: 'DELETE' }); await refresh();
          }));
        return el('tr', {}, el('td', {}, module.manifest.display_name || module.manifest.id),
          el('td', {}, module.manifest.version), el('td', {}, module.manifest.category),
          el('td', {}, module.enabled ? 'Enabled' : 'Disabled'), el('td', {}, toggle,
            ...(module.enabled ? [adapter ? button('Provider profiles', profiles) : button('Edit grants', () => grant(module))] : []), remove));
      });
      installed.replaceChildren(table(['Package', 'Version', 'Category', 'State', 'Actions'], rows, 'Installed modules'));
      if (!result.modules.length) installed.append(notice('No modules installed. Select a local package or enter its URL.'));
      changed(result.modules);
    } catch (error) { fail(error); }
  }
  dialog.append(el('div', { class: 'page-heading' }, el('h2', {}, 'Module manager'), button('Close', () => dialog.close())),
    el('p', {}, 'Install modules at runtime. Each package has its own identity and permissions.'),
    el('section', { class: 'module-sources' }, el('h3', {}, 'Supplied modules'), supplied, button('Inspect supplied module', () => inspect('supplied')),
      el('h3', {}, 'Install from file'), file, button('Inspect file', () => inspect('file')),
      el('h3', {}, 'Install from address'), el('label', {}, 'Package URL', url), el('label', {}, 'Expected SHA-256', digest),
      el('label', {}, privateNetwork, ' Allow this private network source'),
      el('label', {}, insecure, ' Allow HTTP with an expected digest'), button('Inspect address', () => inspect('url'))),
    feedback, inspection, el('h3', {}, 'Installed modules'), installed);
  dialog.addEventListener('close', () => { disposed = true; adapterManager?.dispose(); void releasePreview(); dialog.remove(); });
  document.body.append(dialog); dialog.showModal(); void refresh();
  return { dispose() { dialog.close(); } };
}
