// SPDX-License-Identifier: Apache-2.0
// Register systemd managers through the enrolled account's existing authority.
import { request } from './api.js';
import { button, el, notice } from './components.js';

export function adminProfiles() {
  let disposed = false, nodes = [];
  const dialog = el('dialog', { class: 'module-manager', 'aria-label': 'Administration profiles' });
  const body = el('div'), status = el('div', { role: 'status' }), editor = el('form');
  const system = el('select', { 'aria-label': 'Administration system', required: true });
  const manager = el('select', { 'aria-label': 'Service manager' },
    el('option', { value: 'user' }, 'User services'), el('option', { value: 'system' }, 'System services and power'));
  const probe = button('Probe and add profile', () => {}, { type: 'submit' });
  async function change(value, enabled) {
    await request('/admin-profiles', { method: 'PUT', body: {
      node_id: value.node_id, manager: value.manager, profile_id: value.id, enabled,
    } });
  }
  async function load() {
    try {
      const [inventory, saved] = await Promise.all([request('/nodes'), request('/admin-profiles')]);
      if (disposed) return;
      nodes = inventory.nodes;
      const selected = system.value;
      system.replaceChildren(...nodes.map(node => el('option', { value: node.id }, node.name)));
      if (nodes.some(node => node.id === selected)) system.value = selected;
      probe.disabled = !nodes.length;
      const rows = el('tbody');
      for (const value of saved.profiles) {
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
              await request(`/admin-profiles/${encodeURIComponent(value.id)}`, { method: 'DELETE' });
              status.replaceChildren(notice('Profile removed. Services and power state are unchanged.')); await load();
            } catch (error) { status.replaceChildren(notice(error.message, 'error')); }
          });
          status.replaceChildren(el('label', {}, confirmed, ` Remove ${value.manager} profile ${value.id}. Clear its action receipts first.`), apply);
        });
        rows.append(el('tr', {}, ...[nodes.find(node => node.id === value.node_id)?.name || value.node_id,
          value.manager, value.account_uid, value.version, value.enabled ? 'Enabled' : 'Disabled'].map(text => el('td', {}, String(text))),
          el('td', {}, toggle, remove)));
      }
      body.replaceChildren(saved.profiles.length ? el('div', { class: 'table-scroll' }, el('table', {},
        el('thead', {}, el('tr', {}, ...['System', 'Manager', 'Account UID', 'Version', 'State', 'Actions'].map(name => el('th', {}, name)))), rows)) : notice('No administration profiles.'));
    } catch (error) { if (!disposed) status.replaceChildren(notice(error.message, 'error')); }
  }
  editor.append(el('label', {}, 'System', system), el('label', {}, 'Manager', manager), probe);
  editor.addEventListener('submit', async event => {
    event.preventDefault(); probe.disabled = true;
    try {
      await request('/admin-profiles', { method: 'PUT', body: { node_id: system.value, manager: manager.value } });
      status.replaceChildren(notice('Administration profile verified and saved. Grant the module access to this system before use.')); await load();
    } catch (error) { status.replaceChildren(notice(error.message, 'error')); }
    finally { probe.disabled = !nodes.length; }
  });
  dialog.append(el('h2', {}, 'Administration profiles'),
    notice('Linux systemd managers use the enrolled SSH account. FICC does not collect passwords, invoke sudo or change system authorization.'),
    el('p', {}, 'User managers control that account\'s services. System managers require existing permission for each service or power action.'),
    body, el('h3', {}, 'Add a connection'), editor, status, button('Refresh', load), button('Close', () => dialog.close()));
  dialog.addEventListener('close', () => { disposed = true; dialog.remove(); }, { once: true });
  document.body.append(dialog); dialog.showModal(); void load();
  return { dispose() { disposed = true; dialog.close(); } };
}
