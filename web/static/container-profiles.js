// SPDX-License-Identifier: Apache-2.0
// Register fixed container connections on enrolled systems without browser credentials.
import { request } from './api.js';
import { button, el, notice } from './components.js';

export function containerProfiles() {
  let disposed = false, nodes = [];
  const dialog = el('dialog', { class: 'module-manager', 'aria-label': 'Container provider profiles' });
  const body = el('div'), status = el('div', { role: 'status' }), editor = el('form');
  const system = el('select', { 'aria-label': 'Container system', required: true });
  const provider = el('select', { 'aria-label': 'Container provider' },
    ...['docker', 'podman', 'kubernetes'].map(value => el('option', { value }, value)));
  const connection = el('select', { 'aria-label': 'Container connection' });
  const context = el('input', { 'aria-label': 'Kubernetes context', maxlength: '128' });
  const namespace = el('input', { 'aria-label': 'Kubernetes namespace', maxlength: '63' });
  const fields = el('div', {}, el('label', {}, 'Context', context), el('label', {}, 'Namespace', namespace));
  const probe = button('Probe and add profile', () => {}, { type: 'submit' });
  function connections() {
    const options = { docker: ['rootless', 'rootful'], podman: ['rootless'], kubernetes: ['context'] }[provider.value];
    connection.replaceChildren(...options.map(value => el('option', { value }, value)));
    fields.hidden = provider.value !== 'kubernetes';
    context.required = namespace.required = !fields.hidden;
  }
  provider.addEventListener('change', connections); connections();
  async function change(value, enabled) {
    await request('/container-profiles', { method: 'PUT', body: {
      node_id: value.node_id, provider: value.provider, connection: value.connection, context: value.context,
      namespace: value.namespace, profile_id: value.id, enabled,
    } });
  }
  async function load() {
    try {
      const [inventory, saved] = await Promise.all([request('/nodes'), request('/container-profiles')]);
      if (disposed) return;
      nodes = inventory.nodes;
      const selected = system.value;
      system.replaceChildren(...nodes.map(node => el('option', { value: node.id }, node.name)));
      if (nodes.some(node => node.id === selected)) system.value = selected;
      probe.disabled = !nodes.length;
      const rows = el('tbody');
      for (const value of saved.profiles) {
        const state = el('span', {}, value.enabled ? 'Enabled' : 'Disabled');
        const toggle = button(value.enabled ? 'Disable profile' : 'Probe and enable', async () => {
          toggle.disabled = true;
          try { await change(value, !value.enabled); await load(); }
          catch (error) { status.replaceChildren(notice(error.message, 'error')); }
          finally { toggle.disabled = false; }
        });
        const remove = button('Remove profile', () => {
          const confirmed = el('input', { type: 'checkbox' });
          const apply = button('Confirm profile removal', async () => {
            if (!confirmed.checked) return;
            apply.disabled = true;
            try {
              await request(`/container-profiles/${encodeURIComponent(value.id)}`, { method: 'DELETE' });
              status.replaceChildren(notice('Profile removed. The workloads are unchanged.')); await load();
            } catch (error) { status.replaceChildren(notice(error.message, 'error')); }
          });
          status.replaceChildren(el('label', {}, confirmed, ` Remove ${value.provider} profile ${value.id}. Clear its action receipts first.`), apply);
        });
        rows.append(el('tr', {}, ...[nodes.find(node => node.id === value.node_id)?.name || value.node_id, value.provider,
          value.connection, value.context || '', value.namespace || '', value.version].map(text => el('td', {}, text)),
          el('td', {}, state), el('td', {}, toggle, remove)));
      }
      body.replaceChildren(saved.profiles.length ? el('div', { class: 'table-scroll' }, el('table', {},
        el('thead', {}, el('tr', {}, ...['System', 'Provider', 'Connection', 'Context', 'Namespace', 'Version', 'State', 'Actions'].map(name => el('th', {}, name)))), rows)) : notice('No container profiles.'));
    } catch (error) { if (!disposed) status.replaceChildren(notice(error.message, 'error')); }
  }
  editor.append(el('label', {}, 'System', system), el('label', {}, 'Provider', provider),
    el('label', {}, 'Connection', connection), fields, probe);
  editor.addEventListener('submit', async event => {
    event.preventDefault(); probe.disabled = true;
    try {
      await request('/container-profiles', { method: 'PUT', body: { node_id: system.value, provider: provider.value,
        connection: connection.value, context: fields.hidden ? '' : context.value, namespace: fields.hidden ? '' : namespace.value } });
      status.replaceChildren(notice('Container profile verified and saved. Grant the module access to this system before use.')); await load();
    } catch (error) { status.replaceChildren(notice(error.message, 'error')); }
    finally { probe.disabled = !nodes.length; }
  });
  dialog.append(el('h2', {}, 'Container provider profiles'),
    notice('Docker and Podman use fixed local sockets through the enrolled SSH account. Socket access can grant broad system authority.'),
    el('p', {}, 'Kubernetes uses the account configuration with an explicit context and namespace. Credential commands and external credential files are refused.'),
    body, el('h3', {}, 'Add a connection'), editor, status, button('Refresh', load), button('Close', () => dialog.close()));
  dialog.addEventListener('close', () => { disposed = true; dialog.remove(); }, { once: true });
  document.body.append(dialog); dialog.showModal(); void load();
  return { dispose() { disposed = true; dialog.close(); } };
}
