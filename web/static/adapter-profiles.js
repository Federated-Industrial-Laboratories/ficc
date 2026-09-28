// SPDX-License-Identifier: Apache-2.0
// Bind installed adapter packages to explicit provider accounts and resource grants.
import { request } from './api.js';
import { button, el, notice, table } from './components.js';
import { checkedBeforeDispatch, consistencyName } from './provider-contracts.js';
import { windowsEndpoints } from './windows-endpoints.js';

export function adapterProfiles(changed = () => {}) {
  let disposed = false, child, modules = [], endpoints = [];
  const dialog = el('dialog', { class: 'module-manager', 'aria-label': 'Provider adapter profiles' });
  const body = el('div'), status = el('div', { role: 'status' });
  const packages = el('select', { 'aria-label': 'Provider adapter package' });
  const systems = el('select', { 'aria-label': 'Adapter endpoint' });
  const bindings = el('select', { 'aria-label': 'Provider resource binding' });
  const socket = el('input', { 'aria-label': 'Provider socket path', maxlength: 240, placeholder: '/run/user/1000/provider/socket' });
  const bindingStatus = el('div', { role: 'status' });
  const fail = error => { if (!disposed) status.replaceChildren(notice(error.message, 'error')); };
  const selected = () => endpoints.find(endpoint => endpoint.id === systems.value);
  async function readBindings() {
    const endpoint = selected();
    bindings.replaceChildren(); bindingStatus.replaceChildren();
    registerSocket.disabled = !endpoint || endpoint.kind !== 'linux-ssh';
    socket.disabled = registerSocket.disabled;
    if (!endpoint) return;
    try {
      const value = await request(`/adapter-bindings?endpoint_kind=${endpoint.kind}&endpoint_id=${endpoint.id}`);
      if (disposed || selected() !== endpoint) return;
      bindings.replaceChildren(...value.bindings.map(binding => el('option', { value: binding.id, disabled: !binding.available },
        `${binding.label || binding.resource_kind} / ${binding.id}${binding.available ? '' : ' (unavailable)'}`)));
      if (!value.bindings.length) bindingStatus.replaceChildren(notice('No provider resources are registered for this endpoint.'));
    } catch (error) { if (!disposed && selected() === endpoint) bindingStatus.replaceChildren(notice(error.message, 'error')); }
  }
  function selectPackage() {
    const current = modules.find(module => module.digest === packages.value);
    const kind = current?.manifest.adapter.execution === 'enrolled-node' ? 'linux-ssh' : 'windows';
    const previous = systems.value;
    systems.replaceChildren(...endpoints.filter(endpoint => endpoint.kind === kind).map(endpoint =>
      el('option', { value: endpoint.id }, endpoint.name)));
    if ([...systems.options].some(option => option.value === previous)) systems.value = previous;
    void readBindings();
  }
  const registerSocket = button('Register provider socket', async event => {
    const control = event.currentTarget, endpoint = selected();
    if (!endpoint || endpoint.kind !== 'linux-ssh') return;
    control.disabled = true;
    try {
      await request('/adapter-bindings', { method: 'POST', body: {
        endpoint_kind: endpoint.kind, endpoint_id: endpoint.id, socket_path: socket.value,
      } });
      socket.value = ''; await readBindings();
    } catch (error) { fail(error); }
    finally { control.disabled = selected()?.kind !== 'linux-ssh'; }
  });
  packages.addEventListener('change', selectPackage);
  systems.addEventListener('change', () => { void readBindings(); });
  function grant(profile) {
    const confirm = el('input', { type: 'checkbox' });
    const endpoint = endpoints.find(value => value.id === profile.endpoint_id);
    status.replaceChildren(el('h3', {}, 'Grant provider account access'),
      el('p', {}, `Package: ${profile.display_name}. SHA-256: ${profile.digest}.`),
      el('p', {}, `Endpoint: ${endpoint?.name || profile.endpoint_id}. Profile: ${profile.id}.`),
      notice('This adapter can administer the complete registered provider account, including all VMs accessible to that account.'),
      el('p', {}, 'A trusted adapter can change the provider during an inventory call. Host confirmation controls the normal module workflow.'),
      el('p', {}, 'Use a dedicated provider account. Ordinary module VM permissions do not restrict the adapter account itself.'),
      el('p', {}, `Declared consistency: ${consistencyName(profile.consistency)}.`),
      profile.consistency === 'checked-before-dispatch' ? notice(checkedBeforeDispatch) : null,
      el('label', {}, confirm, ' I trust this exact package and grant access to this provider account.'),
      button('Grant account access and probe', async event => {
        if (!confirm.checked) return;
        const control = event.currentTarget; control.disabled = true;
        try {
          await request(`/adapter-profiles/${profile.id}/grant`, { method: 'POST', body: {
            expected_revision: profile.revision, confirm: true,
          } });
          status.replaceChildren(notice('Provider access granted. Grant VM permissions to a workspace module separately.'));
          await load(); changed();
        } catch (error) { fail(error); }
        finally { control.disabled = false; }
      }), button('Cancel grant', () => status.replaceChildren()));
  }
  async function load() {
    try {
      const [installed, linux, windows, saved] = await Promise.all([
        request('/modules'), request('/nodes'), request('/windows-endpoints'), request('/adapter-profiles'),
      ]);
      if (disposed) return;
      modules = installed.modules.filter(module => module.manifest.role === 'provider-adapter');
      endpoints = [...linux.nodes.map(node => ({ ...node, kind: 'linux-ssh' })),
        ...windows.endpoints.map(endpoint => ({ ...endpoint, kind: 'windows' }))];
      const previous = packages.value;
      packages.replaceChildren(...modules.map(module => el('option', { value: module.digest },
        `${module.manifest.display_name || module.manifest.id} ${module.manifest.version}`)));
      if (modules.some(module => module.digest === previous)) packages.value = previous;
      selectPackage();
      body.replaceChildren(table(['Adapter / profile', 'Endpoint', 'Declared consistency', 'State', 'Actions'], saved.profiles.map(profile => {
        const revoke = button('Revoke account access', async event => {
          const control = event.currentTarget; control.disabled = true;
          try {
            await request(`/adapter-profiles/${profile.id}/revoke`, { method: 'POST' });
            status.replaceChildren(notice('Provider access revoked. Accepted provider tasks retain their receipts.')); await load(); changed();
          } catch (error) { fail(error); }
          finally { control.disabled = false; }
        });
        const remove = button('Remove profile', () => {
          const confirm = el('input', { type: 'checkbox' });
          status.replaceChildren(el('label', {}, confirm, ` Remove profile ${profile.id}. Clear its operation receipts first.`),
            button('Confirm adapter profile removal', async event => {
              if (!confirm.checked) return;
              const control = event.currentTarget; control.disabled = true;
              try {
                await request(`/adapter-profiles/${profile.id}`, { method: 'DELETE', body: { confirm: true } });
                status.replaceChildren(notice('Adapter profile removed. The provider resources are unchanged.')); await load(); changed();
              } catch (error) { fail(error); }
              finally { control.disabled = false; }
            }));
        });
        return el('tr', {}, el('td', {}, profile.display_name, el('p', {}, profile.id)),
          el('td', {}, endpoints.find(endpoint => endpoint.id === profile.endpoint_id)?.name || profile.endpoint_id),
          el('td', {}, consistencyName(profile.consistency)),
          el('td', {}, el('span', { class: 'module-nowrap' }, profile.ready ? 'Ready' : 'Unavailable'),
            el('p', {}, profile.diagnostic?.message || (profile.enabled && profile.admin_granted ? 'Access granted.' : 'Access disabled.'))),
          el('td', {}, button('Review account grant', () => grant(profile)), revoke, remove));
      }), 'Installed provider adapter profiles'));
      if (!saved.profiles.length) body.append(notice('No provider adapter profiles are registered.'));
    } catch (error) { fail(error); }
  }
  const create = button('Create disabled adapter profile', async () => {
    const endpoint = selected();
    if (!packages.value || !endpoint || !bindings.value) { fail(Error('Select an installed adapter, endpoint and available resource binding.')); return; }
    create.disabled = true;
    try {
      await request('/adapter-profiles', { method: 'POST', body: { digest: packages.value,
        endpoint_kind: endpoint.kind, endpoint_id: endpoint.id, transport_binding_id: bindings.value,
      } });
      status.replaceChildren(notice('Adapter profile created without account access. Review its exact grant before enabling it.')); await load();
    } catch (error) { fail(error); }
    finally { create.disabled = false; }
  });
  dialog.append(el('h2', {}, 'Provider adapter profiles'),
    el('p', {}, 'Install an adapter package with Manage modules, register its endpoint, then grant access to its provider account.'),
    body, el('h3', {}, 'New adapter profile'),
    el('div', { class: 'module-sources' }, el('label', {}, 'Installed adapter', packages), el('label', {}, 'Registered endpoint', systems),
      el('label', {}, 'Provider resource', bindings), bindingStatus,
      el('label', {}, 'Owner-selected provider socket', socket), registerSocket,
      el('p', {}, 'Socket registration checks its owner and provider process. Packages cannot select another host path.'), create),
    status, button('Windows endpoints', () => { child?.dispose(); child = windowsEndpoints(); }),
    button('Refresh', load), button('Close', () => dialog.close()));
  dialog.addEventListener('close', () => { disposed = true; child?.dispose(); dialog.remove(); }, { once: true });
  document.body.append(dialog); dialog.showModal(); void load();
  return { dispose() { dialog.close(); } };
}
