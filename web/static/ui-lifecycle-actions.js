// SPDX-License-Identifier: Apache-2.0
// Keep provider confirmation and durable action history in host-owned dialogs.
import { request } from './api.js';
import { button, el, notice } from './components.js';
import { checkedBeforeDispatch, consistencyName } from './provider-contracts.js';

const identity = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
const terminal = new Set(['observed', 'refused', 'resolved', 'failed']);

export function lifecycleActions(context, kind) {
  const vm = kind === 'vms', admin = kind === 'admin';
  const label = vm ? 'VM' : admin ? 'administration' : 'container', targetKey = vm ? 'vm_id' : 'resource_id';
  const collection = vm ? 'vms' : admin ? 'resources' : 'workloads';
  let disposed = false;
  const dialogs = new Set();
  const post = (path, body = {}, idempotencyKey) => request(`/module-${kind}/${path}`, { method: 'POST', body: { ...context, ...body }, idempotencyKey });
  function dialog(title) {
    const element = el('dialog', { class: 'module-manager module-lifecycle', 'aria-label': title });
    const content = el('div');
    element.append(el('h2', {}, title), content, button('Close', () => element.close()));
    element.addEventListener('close', () => { dialogs.delete(element); element.remove(); }, { once: true });
    dialogs.add(element); document.body.append(element); element.showModal();
    return { element, content };
  }
  function rows(headers, values) {
    return el('div', { class: 'table-scroll' }, el('table', {},
      el('thead', {}, el('tr', {}, headers.map(name => el('th', {}, name)))),
      el('tbody', {}, values.map(row => el('tr', {}, row.map(value => el('td', {}, value instanceof Node ? value : el('span', { class: String(value ?? '').length <= 24 ? 'module-nowrap' : '' }, String(value ?? '')))))))));
  }
  function alive(view) { return !disposed && view.element.isConnected; }
  function operation(view, value) {
    if (!alive(view)) return;
    const status = el('div', { role: 'status' });
    const unknown = value.targets.filter(item => ['unknown', 'accepted'].includes(item.state)).map(item => item[targetKey]);
    const refresh = button('Refresh operation', async () => {
      refresh.disabled = true;
      try { operation(view, await post('operation', { operation_id: value.id })); }
      catch (error) { status.replaceChildren(notice(error.message, 'error')); }
      finally { refresh.disabled = false; }
    });
    const observed = item => vm ? item.observed_state : item.observed &&
      `${item.observed.state}${item.observed.replicas == null ? '' : `; replicas ${item.observed.replicas}, ready ${item.observed.ready ?? 'unknown'}`}`;
    view.content.replaceChildren(el('p', {}, `Operation ${value.id}`),
      notice(admin && ['reboot', 'poweroff'].includes(value.action) ?
        'Accepted means queued. Inspect the system externally before closing the outcome. A lost SSH connection does not prove shutdown.' :
        'Accepted means the provider acknowledged the request. Observed records the current state. Unknown requires inspection.'),
      rows(['System', 'Resource identity', 'Outcome', 'Observed state', 'Details'], value.targets.map(item =>
        [item.node_id, item[targetKey], item.state, observed(item), item.error?.message])), refresh, status);
    if (vm && value.targets.some(item => item.consistency)) {
      view.content.append(rows(['Resource identity', 'Profile', 'Declared consistency'], value.targets.map(item =>
        [item.vm_id, item.profile_id || '', consistencyName(item.consistency)])));
      if (value.targets.some(item => item.consistency === 'checked-before-dispatch')) view.content.append(notice(checkedBeforeDispatch));
    }
    if (unknown.length) {
      const confirmed = el('input', { type: 'checkbox' });
      const resolve = button('Close pending outcomes', async () => {
        if (!confirmed.checked) return;
        resolve.disabled = true;
        try { operation(view, await post('resolve', { operation_id: value.id, [vm ? 'vm_ids' : 'resource_ids']: unknown, confirm: true })); }
        catch (error) { status.replaceChildren(notice(error.message, 'error')); }
        finally { resolve.disabled = false; }
      });
      view.content.append(el('label', {}, confirmed,
        ' I inspected each pending resource above. Close these outcomes without claiming success or repeating the action.'), resolve);
    }
    if (value.targets.every(item => terminal.has(item.state))) {
      const confirmed = el('input', { type: 'checkbox' });
      const orphanConfirmed = el('input', { type: 'checkbox' });
      let orphanRequired = false;
      const remove = button(value.cleanup ? 'Retry receipt removal' : 'Remove operation receipt', async () => {
        if (!confirmed.checked || (orphanRequired && !orphanConfirmed.checked)) return;
        remove.disabled = true;
        try {
          await post('forget', { operation_id: value.id, confirm: true,
            ...(orphanRequired ? { acknowledge_orphans: true } : {}) });
          if (alive(view)) view.content.replaceChildren(notice('Operation receipt removed. The managed resources are unchanged.'));
        } catch (error) {
          status.replaceChildren(notice(error.message, 'error'));
          if (vm && error.code === 'adapter_orphan_ack_required' && alive(view)) {
            orphanRequired = true; orphanConfirmed.checked = false;
            status.append(notice('The registered system identity changed or is absent. Remote receipt cleanup cannot be verified.'),
              el('label', {}, orphanConfirmed,
                ' Remove the local receipt only. Remote systems can retain a receipt that cannot execute or repeat the action.'));
            remove.textContent = 'Remove local receipt only';
          }
        }
        finally { remove.disabled = false; }
      });
      if (value.cleanup) view.content.append(notice(`Receipt removal acknowledged by ${value.cleanup.acknowledged} of ${value.cleanup.total} profiles.`));
      view.content.append(el('label', {}, confirmed, ' Remove this completed receipt from FICC and its systems. This does not delete managed resources.'), remove);
    }
  }
  async function preview(previewId) {
    const view = dialog(`FICC ${label} action confirmation`);
    view.content.append(notice('Checking the current action and permissions.'));
    try {
      const value = await post('preview', { preview_id: previewId });
      if (!alive(view)) return;
      const key = crypto.randomUUID(), status = el('div', { role: 'status' });
      const title = vm ? (value.action === 'start' ? 'Start these VMs' : 'Shut down these VMs') :
        admin ? ({ start: 'Start these services', stop: 'Stop these services', restart: 'Restart these services',
          reboot: 'Restart these systems', poweroff: 'Shut down these systems' })[value.action] :
        ({ start: 'Start these containers', stop: 'Stop these containers', scale: 'Set these replica counts' })[value.action];
      const confirm = button(title, async () => {
        confirm.disabled = true;
        try { operation(view, await post('commit', { preview_id: previewId, confirm: true }, key)); }
        catch (error) {
          status.replaceChildren(notice(`${error.message} Retry uses the same operation key. Open action history to inspect a saved request.`, 'error'));
          confirm.disabled = false;
        }
      });
      view.content.replaceChildren(el('p', {}, `Action: ${value.action}. Expires ${new Date(value.expires_at * 1000).toLocaleTimeString()}.`),
        vm ? rows(['VM', 'System', 'State', 'Identity'], value.vms.map(item => [item.name, item.node_id, item.state, item.vm_id])) :
          admin ? rows(['Resource', 'Kind', 'Provider', 'System', 'State', 'Identity'], value.resources.map(item =>
            [item.name, item.kind, item.provider, item.node_id, item.state, item.resource_id])) :
          rows(['Workload', 'Provider', 'System', 'Namespace', 'State', 'Replicas', 'Identity'], value.workloads.map(item =>
            [item.name, item.provider, item.node_id, item.namespace, item.state, item.replicas, item.resource_id])),
        vm && value.vms.some(item => item.consistency) ? rows(['VM', 'Profile', 'Declared consistency'],
          value.vms.map(item => [item.name, item.profile_id || '', consistencyName(item.consistency)])) : null,
        notice(vm ? (value.vms.some(item => item.consistency === 'checked-before-dispatch') ?
          'Each VM has its own outcome. Shutdown does not force power off.' :
          'Each VM has its own outcome. A changed VM state refuses the action. Shutdown does not force power off.') : value.effect),
        vm && value.vms.some(item => item.consistency === 'checked-before-dispatch') ? notice(checkedBeforeDispatch) : null,
        confirm, status);
    } catch (error) { if (alive(view)) view.content.replaceChildren(notice(error.message, 'error')); }
  }
  async function history() {
    const view = dialog(`FICC ${label} action history`);
    let page = 0;
    async function load() {
      try {
        const value = await post('history');
        if (!alive(view)) return;
        page = Math.min(page, Math.max(0, Math.ceil(value.operations.length / 50) - 1));
        const open = item => button('Inspect operation', async () => {
          try { operation(view, await post('operation', { operation_id: item.id })); }
          catch (error) { status.replaceChildren(notice(error.message, 'error')); }
        });
        const status = el('div', { role: 'status' });
        view.content.replaceChildren(notice('History persists across reloads. Inspect pending outcomes before another action. Remove completed receipts before removing this panel.'),
          value.operations.length ? rows(['Created', 'Action', 'Outcomes', 'Operation', 'Details'], value.operations.slice(page * 50, (page + 1) * 50).map(item =>
            [new Date(item.created_at * 1000).toLocaleString(), item.action,
              Object.entries(item.outcomes).map(([state, count]) => `${state}: ${count}`).join(', '), item.id, open(item)])) : notice('No permitted operation receipts.'),
          el('div', { class: 'actions' }, button('Previous', () => { page--; void load(); }, { disabled: page === 0 }),
            el('span', {}, `Page ${page + 1} of ${Math.max(1, Math.ceil(value.operations.length / 50))}`),
            button('Next', () => { page++; void load(); }, { disabled: (page + 1) * 50 >= value.operations.length }), button('Refresh history', load)), status);
      } catch (error) { if (alive(view)) view.content.replaceChildren(notice(error.message, 'error')); }
    }
    await load();
  }
  return {
    historyControl() { return button(`${vm ? 'VM' : admin ? 'Administration' : 'Container'} action history`, history); },
    controls(result) {
      const refs = [...new Set((Array.isArray(result?.results) ? result.results : [])
        .filter(item => Array.isArray(item?.data?.[collection]))
        .map(item => item.data.preview_id).filter(identity))].slice(0, 16);
      return refs.map(ref => button(`Review ${label} action in FICC`, () => preview(ref)));
    },
    dispose() { disposed = true; for (const element of dialogs) element.close(); dialogs.clear(); },
  };
}
