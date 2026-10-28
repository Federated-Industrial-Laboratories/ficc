// SPDX-License-Identifier: Apache-2.0
// Review exact resources and finite limits before granting another cluster access.
import { button, el, notice, time } from './components.js';

export const scopes = ['discover', 'inference:invoke', 'inference:manage', 'models:read', 'models:transfer', 'models:manage', 'resources:read'];
export const field = (label, input) => el('label', { class: 'field' }, el('span', {}, label), input);

export function grantForm(title, resources, submit, suggested = ['discover', 'inference:invoke']) {
  const dialog = el('dialog', { class: 'workload-dialog' }), status = el('div');
  function selection(label, items) {
    const node = el('fieldset', {}, el('legend', {}, label), items.map(([id, text, checked]) => el('label', { class: 'check-label' }, el('input', { type: 'checkbox', value: id, checked }), text)));
    return { node, values: () => [...node.querySelectorAll('input:checked')].map(input => input.value) };
  }
  const rights = selection('Allowed operations', scopes.map(scope => [scope, scope, suggested.includes(scope)]));
  const services = selection('Published inference services', resources.services.map(item => [item.id, item.spec.alias, false]));
  const models = selection('Published model revisions', resources.models.map(item => [item.id, `${item.manifest.name} / ${item.manifest.revision}`, false]));
  const nodes = selection('Machines available to remote deployments', resources.offers.map(item => [item.snapshot.node_id, item.snapshot.node_id, false]));
  const hours = el('input', { type: 'number', min: 1, max: 720, value: 24 });
  const concurrent = el('input', { type: 'number', min: 1, max: 16, value: 2 });
  const requests = el('input', { type: 'number', min: 1, max: 1000000, value: 1000 });
  const transfer = el('input', { type: 'number', min: 0, max: 16384, value: 0 });
  const stop = el('input', { type: 'checkbox' });
  const accept = button('Approve selected access', async () => {
    accept.disabled = true;
    try {
      await submit({ scopes: rights.values(), services: services.values(), models: models.values(), nodes: nodes.values(),
        lifetime: Number(hours.value) * 3600, concurrent: Number(concurrent.value), requests: Number(requests.value),
        transfer_bytes: Number(transfer.value) * 1024 ** 3, stop_on_revoke: stop.checked });
      dialog.close();
    } catch (error) { status.replaceChildren(notice(error.message, 'error')); accept.disabled = false; }
  }, { class: 'primary' });
  dialog.append(el('h2', {}, title), el('p', {}, 'Only the selected resources are shared. Remote deployments still require local capacity, policy and approved runtime images.'),
    rights.node, services.node, models.node, nodes.node, field('Lifetime in hours', hours), field('Concurrent requests', concurrent),
    field('Total request allowance', requests), field('Total model transfer allowance in GiB, including retries', transfer),
    el('label', { class: 'check-label' }, stop, ' Stop services created by this grant when it is revoked'),
    el('p', {}, 'Requests are limited to 512 KiB and inference responses to 64 MiB. Grant expiry does not stop an already delegated deployment.'), status, accept, button('Cancel', () => dialog.close()));
  dialog.addEventListener('close', () => dialog.remove()); document.body.append(dialog); dialog.showModal();
  return dialog;
}

export function grantSummary(grant) {
  return `${grant.spec.scopes.join(', ')}; ${grant.spec.services.length} services, ${grant.spec.models.length} models, ${grant.spec.nodes.length} machines; expires ${time(grant.expires)}`;
}
