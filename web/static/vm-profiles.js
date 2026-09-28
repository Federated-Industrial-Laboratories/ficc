// SPDX-License-Identifier: Apache-2.0
// Configure fixed VM provider connections for enrolled systems.
import { request } from './api.js';
import { button, el, notice } from './components.js';

export function vmProfiles() {
  let disposed = false;
  const dialog = el('dialog', { class: 'module-manager', 'aria-label': 'VM provider profiles' });
  const body = el('div'), status = el('div', { role: 'status' });
  async function load() {
    try {
      const [inventory, saved, proxmox] = await Promise.all([request('/nodes'), request('/vm-profiles'), request('/proxmox-profiles')]);
      if (disposed) return;
      const table = el('table', {}, el('thead', {}, el('tr', {},
        ['System', 'Provider', 'Connection', 'Enabled', 'Action'].map(name => el('th', {}, name)))));
      const rows = el('tbody');
      for (const node of inventory.nodes) {
        const prior = saved.profiles.find(item => item.node_id === node.id);
        const select = el('select', { 'aria-label': `${node.name} libvirt connection` },
          el('option', { value: 'system' }, 'System'), el('option', { value: 'session' }, 'User session'));
        select.value = prior?.connection || 'system';
        const enabled = el('input', { type: 'checkbox', 'aria-label': `${node.name} VM profile enabled` });
        enabled.checked = Boolean(prior?.enabled);
        const save = button('Save profile', async () => {
          save.disabled = true;
          try {
            await request(`/nodes/${encodeURIComponent(node.id)}/vm-profile`, { method: 'PUT',
              body: { connection: select.value, enabled: enabled.checked } });
            status.replaceChildren(notice('VM profile saved. New requests use this profile revision.')); await load();
          } catch (error) { status.replaceChildren(notice(error.message, 'error')); }
          finally { save.disabled = false; }
        });
        const remove = prior && button('Remove profile', () => {
          const confirmed = el('input', { type: 'checkbox' });
          const apply = button('Confirm profile removal', async () => {
            if (!confirmed.checked) return;
            apply.disabled = true;
            try {
              await request(`/nodes/${encodeURIComponent(node.id)}/vm-profile`, { method: 'DELETE' });
              status.replaceChildren(notice('VM profile removed. The VMs are unchanged.')); await load();
            } catch (error) { status.replaceChildren(notice(error.message, 'error')); }
          });
          status.replaceChildren(el('label', {}, confirmed, ` Remove the VM profile for ${node.name}. Clear its action receipts first.`), apply);
        });
        rows.append(el('tr', {}, el('td', {}, node.name), el('td', {}, 'KVM / libvirt'),
          el('td', {}, select), el('td', {}, enabled), el('td', {}, save, remove)));
        const pve = proxmox.profiles.find(item => item.node_id === node.id);
        const activate = button(pve?.enabled ? 'Disable Proxmox' : 'Probe and enable Proxmox', async () => {
          activate.disabled = true;
          try {
            await request(`/nodes/${encodeURIComponent(node.id)}/proxmox-profile`, { method: 'PUT', body: { enabled: !pve?.enabled } });
            status.replaceChildren(notice('Proxmox profile saved. Module grants remain separate.')); await load();
          } catch (error) { status.replaceChildren(notice(error.message, 'error')); }
          finally { activate.disabled = false; }
        });
        const removePve = pve && button('Remove Proxmox profile', () => {
          const confirmed = el('input', { type: 'checkbox' });
          const apply = button('Confirm Proxmox profile removal', async () => {
            if (!confirmed.checked) return;
            apply.disabled = true;
            try {
              await request(`/nodes/${encodeURIComponent(node.id)}/proxmox-profile`, { method: 'DELETE' });
              status.replaceChildren(notice('Proxmox profile removed. The VMs are unchanged.')); await load();
            } catch (error) { status.replaceChildren(notice(error.message, 'error')); }
          });
          status.replaceChildren(el('label', {}, confirmed, ` Remove the Proxmox profile for ${node.name}. Clear its action receipts first.`), apply);
        });
        rows.append(el('tr', {}, el('td', {}, node.name), el('td', {}, 'Proxmox VE'),
          el('td', {}, pve ? `${pve.provider.node} / ${pve.provider.version}` : 'Fixed local provider'),
          el('td', {}, pve?.enabled ? 'Enabled' : 'Disabled'), el('td', {}, activate, removePve)));
      }
      table.append(rows);
      body.replaceChildren(inventory.nodes.length ? el('div', { class: 'table-scroll' }, table) : notice('Enroll a system before configuring a VM provider.'));
    } catch (error) { if (!disposed) status.replaceChildren(notice(error.message, 'error')); }
  }
  dialog.append(el('h2', {}, 'VM provider profiles'),
    notice('Libvirt requires python3-libvirt and connection access for the enrolled SSH account. Read/write libvirt access can grant broad system authority.'),
    el('p', {}, 'System and user-session connections have separate VM inventories. Module grants and caller permissions still control every FICC action.'),
    el('p', {}, 'Proxmox requires an enrolled root SSH account on its node. FICC checks exact provider compatibility before power or console access.'),
    body, status, button('Refresh', load), button('Close', () => dialog.close()));
  dialog.addEventListener('close', () => { disposed = true; dialog.remove(); }, { once: true });
  document.body.append(dialog); dialog.showModal(); void load();
  return { dispose() { disposed = true; dialog.close(); } };
}
