// SPDX-License-Identifier: Apache-2.0
// Show saved offers and current availability without changing local consent.
import { button, bytes, details, el, panel, state, table, time } from './components.js';
import { limitFields, nodeLabel, schedule, words } from './workloads-model.js';

export function offerDetail(value) {
  const { snapshot, observed_at } = value, { offer, capacity } = snapshot;
  return el('div', { class: 'workload-offer-detail' },
    details([['Node', snapshot.node_id], ['Installation', snapshot.installation_id],
      ['Last observed', time(observed_at)], ['Offer revision', offer.revision],
      ['Local control', words(offer.control)], ['Schedule', schedule(offer.schedule_utc)],
      ['Sensitive data', offer.mode === 'managed' && offer.accept_sensitive ? 'Accepted under policy' : 'Not accepted']]),
    table(['Resource', 'Local ceiling', 'Observed available'], [
      ...limitFields.map(([key, label]) => el('tr', {}, el('td', {}, label),
        el('td', { class: 'numeric' }, offer.limits[key]), el('td', { class: 'numeric' }, capacity.available[key]))),
      el('tr', {}, el('td', {}, 'GPU devices'), el('td', {}, offer.limits.gpu_devices.join(', ') || 'None'),
        el('td', {}, capacity.available.gpu_devices.join(', ') || 'None')),
    ], 'Offered resource limits'),
    el('h3', {}, 'Approved runtimes'),
    offer.runtimes.length ? table(['Provider', 'Package digest', 'Image digest', 'Isolation / network'],
      offer.runtimes.map(runtime => el('tr', {}, el('td', {}, runtime.provider),
        el('td', {}, el('code', {}, runtime.package_digest)), el('td', {}, el('code', {}, runtime.image_digest)),
        el('td', {}, `${runtime.isolation} / ${runtime.network}`))), 'Approved contributor runtimes') : el('p', {}, 'No runtime is approved.'),
    el('h3', {}, 'Provider availability'),
    table(['Provider', 'Package digest', 'Status'], capacity.providers.map(provider => el('tr', {},
      el('td', {}, provider.id), el('td', {}, el('code', {}, provider.package_digest)),
      el('td', {}, provider.available ? 'Available' : words(provider.reason || 'unavailable')))), 'Observed executor providers'),
    el('h3', {}, 'Storage slots'),
    table(['Slot', 'Generation', 'Storage / inodes', 'Status'], capacity.slots.map(slot => el('tr', {},
      el('td', {}, slot.id), el('td', {}, slot.generation), el('td', {}, `${bytes(slot.storage_bytes)} / ${slot.storage_inodes}`),
      el('td', {}, slot.available ? 'Available' : words(slot.reason || 'reserved')))), 'Observed storage slots'));
}

export function offerView() {
  let selected = null;
  const list = el('div'), detail = el('div');
  const element = panel('Contributor offers', [
    el('p', { class: 'muted' }, 'Offers are saved observations, not reservations. The executor checks current local consent, policy and capacity at dispatch. Pause, drain and stop are controlled on the contributor machine.'), list, detail]);
  function update(offers) {
    if (selected && !offers.some(value => value.snapshot.node_id === selected)) selected = null;
    function choose(value) { selected = value.snapshot.node_id; update(offers); }
    list.replaceChildren(offers.length ? table(['Contributor', 'Control', 'Availability', 'CPU / memory ceiling', 'Runtimes', 'Observed'],
      offers.map(value => {
        const { offer, node_id } = value.snapshot;
        return el('tr', { 'aria-selected': node_id === selected ? 'true' : 'false' },
          el('td', {}, button(nodeLabel(value), () => choose(value), { 'aria-expanded': node_id === selected ? 'true' : 'false' }),
            el('small', { class: 'cell-note' }, node_id)),
          el('td', {}, `${words(offer.mode)} / ${words(offer.control)}`),
          el('td', {}, value.available ? 'Connected' : words(value.reason || 'unavailable')),
          el('td', {}, `${offer.limits.cpu_millis} mCPU / ${bytes(offer.limits.memory_bytes)}`),
          el('td', {}, offer.runtimes.length), el('td', {}, time(value.observed_at)));
      }), 'Contributor workload offers') : state('No contributor offers', 'A connected executor must report an offer approved for this project.'));
    detail.replaceChildren(...(selected ? [offerDetail(offers.find(value => value.snapshot.node_id === selected))] : []));
  }
  return { element, update };
}
