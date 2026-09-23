// SPDX-License-Identifier: Apache-2.0
// Present observed node resources and preserve selection across refreshes.
import { allowed, getSession, request } from './api.js';
import { age, announce, badge, button, bytes, confirmation, details, el, errorPanel,
  heading, isStale, metric, notice, panel, percent, state, table, time } from './components.js';
import { enroll } from './enroll.js';
import { upgradeHelper } from './helper-upgrade.js';

export function overview() {
  let nodes = [], selected = null, active = true, timer, loading = false;
  const demo = getSession().mode === 'demo';
  const status = el('div');
  const summary = el('div', { class: 'summary-grid', 'aria-label': 'Cluster summary' });
  const inventory = el('div', { class: 'inventory' });
  const detail = el('div', { class: 'node-detail' });
  const update = button('Refresh samples', () => refresh(true), { 'data-focus': 'refresh' });
  const actions = [update];
  if (allowed('nodes:write') && !demo) actions.push(button('Enroll node', () => enroll(() => refresh()), { class: 'primary' }));
  const element = el('div', {}, heading('CLUSTER / OVERVIEW', 'Cluster overview',
    'Connection health and observed resources across enrolled machines.', actions), status, summary,
  el('div', { class: 'overview-grid' }, inventory, detail));
  inventory.append(state('Loading machines', 'Waiting for the local inventory.'));

  function draw(disconnected = false) {
    const focus = element.contains(document.activeElement) ? document.activeElement?.dataset.focus : null;
    const current = nodes.find(node => node.id === selected);
    const fresh = nodes.filter(node => node.resources && !isStale(node)).length;
    const attention = nodes.filter(node => !node.resources || isStale(node) || node.state !== 'ready').length;
    summary.replaceChildren(...[
      ['Enrolled machines', nodes.length, 'Current inventory'],
      ['Fresh samples', disconnected ? 0 : fresh, 'Updated within 15 seconds'],
      ['Need attention', disconnected ? nodes.length : attention, 'Stale, missing or unavailable'],
    ].map(([label, value, note]) => el('div', { class: 'summary-card' },
      el('span', {}, label), el('strong', {}, value), el('small', {}, note))));
    if (!nodes.length) {
      inventory.replaceChildren(state('No machines enrolled',
        allowed('nodes:write') ? 'Add an approved SSH profile to begin observing your cluster.' : 'No machines are available within this account scope.'));
      detail.replaceChildren(panel('Selection', state('No machine selected', 'Machine details appear here after enrollment.')));
      return;
    }
    const rows = nodes.map(node => {
      const memory = node.resources;
      const label = button(node.name, () => { selected = node.id; draw(); announce(`${node.name} selected`); },
        { class: 'node-select', 'aria-pressed': node.id === selected ? 'true' : 'false', 'data-focus': `node-${node.id}` });
      return el('tr', { class: node.id === selected ? 'selected' : '' },
        el('td', {}, label, el('small', { class: 'cell-note' }, `${node.account}@${node.host}`)),
        el('td', {}, badge(disconnected ? { ...node, stale: true } : node)),
        el('td', { class: 'numeric' }, percent(memory?.cpu_percent)),
        el('td', { class: 'numeric' }, memory ? bytes(memory.memory_total_bytes - memory.memory_available_bytes) : 'Unknown'),
        el('td', { class: 'numeric' }, age(node)));
    });
    inventory.replaceChildren(panel('Machines', table(['Machine / account', 'Connection', 'CPU', 'RAM used', 'Sample age'], rows, 'Enrolled machines')));
    detail.replaceChildren(nodeDetail(current ?? nodes[0], disconnected, refresh));
    if (focus) [...element.querySelectorAll('[data-focus]')].find(node => node.dataset.focus === focus)?.focus({ preventScroll: true });
  }

  async function refresh(probe = false) {
    if (loading || !active) return;
    loading = true;
    update.disabled = true;
    clearTimeout(timer);
    try {
      if (probe && !demo && nodes.length && allowed('nodes:write')) {
        status.replaceChildren(notice('Requesting fresh samples. Unreachable machines can take longer to respond.'));
        await request('/nodes/refresh', { method: 'POST', body: { node_ids: nodes.map(node => node.id) } });
      }
      const result = await request('/nodes');
      if (!active) return;
      nodes = result.nodes;
      if (!nodes.some(node => node.id === selected)) selected = nodes[0]?.id ?? null;
      status.replaceChildren();
      draw();
      document.querySelector('#connection').textContent = demo ? 'Simulation service connected' : 'Local service connected';
      if (probe) announce('Machine samples updated');
    } catch (error) {
      if (!active) return;
      status.replaceChildren(errorPanel(error, () => refresh()));
      if (error.status === 0 && nodes.length) {
        status.append(notice('Cached samples are shown below. Their current state is unknown.', 'warning'));
        draw(true);
      } else if (error.status === 403) { nodes = []; inventory.replaceChildren(); detail.replaceChildren(); summary.replaceChildren(); }
      document.querySelector('#connection').textContent = error.status === 0 ? 'Local service disconnected' : 'Request unavailable';
    } finally {
      loading = false;
      update.disabled = false;
      if (active) timer = setTimeout(() => refresh(), 5000);
    }
  }
  refresh();
  return { element, dispose() { active = false; clearTimeout(timer); } };
}

function nodeDetail(node, disconnected, refresh) {
  const body = el('div', {}, el('div', { class: 'detail-heading' }, el('h3', {}, node.name), badge(node)));
  if (isStale(node) || disconnected) body.append(notice('Stale sample. These values are the last observation, not current resource availability.', 'warning'));
  if (node.error) body.append(notice(`${node.error.message} (${node.error.code})`, 'error'));
  body.append(details([['SSH account', `${node.account}@${node.host}`], ['Profile', node.profile], ['Last sample', time(node.last_seen)]]));
  const resources = node.resources;
  if (!resources) body.append(state('Resources unknown', 'No resource sample is available. A missing sample does not mean zero use.'));
  else {
    const used = resources.memory_total_bytes - resources.memory_available_bytes;
    const memoryPercent = resources.memory_total_bytes > 0 ? used / resources.memory_total_bytes * 100 : null;
    body.append(el('div', { class: 'resource-grid' },
      metric('CPU use', percent(resources.cpu_percent), resources.cpu_percent, `${resources.cpu_count} logical CPUs`),
      metric('RAM used', bytes(used), memoryPercent, `${bytes(resources.memory_total_bytes)} total`)));
    body.append(el('h3', { class: 'section-label' }, 'Storage'),
      ...(resources.storage.length ? resources.storage.map(disk => metric(disk.mount, bytes(disk.available_bytes),
        disk.total_bytes > 0 ? (disk.total_bytes - disk.available_bytes) / disk.total_bytes * 100 : null,
        `Available of ${bytes(disk.total_bytes)} total`)) : [el('p', { class: 'muted' }, 'Storage information unavailable.')]));
    body.append(el('h3', { class: 'section-label' }, 'GPU observation'));
    if (resources.gpu_status !== 'available' || !resources.gpus.length) {
      body.append(el('p', { class: 'muted' }, `GPU metrics ${resources.gpu_status}. No capacity is inferred.`));
    } else {
      for (const gpu of resources.gpus) body.append(el('div', { class: 'gpu-card' }, el('strong', {}, gpu.name),
        metric('GPU use', percent(gpu.utilization_percent), gpu.utilization_percent,
          `${bytes(gpu.memory_used_bytes)} / ${bytes(gpu.memory_total_bytes)} memory`),
        el('small', {}, gpu.temperature_c == null ? 'Temperature unknown' : `${gpu.temperature_c} °C`)));
    }
    body.append(el('h3', { class: 'section-label' }, 'System'), details([
      ['Load averages', resources.load.map(value => value.toFixed(2)).join(' / ') || 'Unknown'],
      ['Uptime', `${Math.floor(resources.uptime_seconds / 3600)}h ${Math.floor(resources.uptime_seconds / 60) % 60}m`],
      ...resources.network.map(net => [`Network / ${net.name}`, `${bytes(net.rx_bytes)} received / ${bytes(net.tx_bytes)} sent`]),
    ]));
  }
  const trust = el('details', { class: 'trust-detail' }, el('summary', {}, 'Host identity and capabilities'),
    el('p', { class: 'muted' }, 'Pinned SSH host fingerprint'), el('code', { class: 'fingerprint' }, node.fingerprint),
    details(Object.entries(node.capabilities).map(([key, value]) => [key.replaceAll('_', ' '), String(value)])));
  body.append(trust);
  if (allowed('nodes:write') && getSession().principal.node_ids == null && getSession().mode !== 'demo') {
    body.append(button('Upgrade helper', () => upgradeHelper(node, refresh), { class: 'quiet' }));
  }
  if (allowed('nodes:write') && getSession().mode !== 'demo') body.append(button('Forget node', () => confirmation('Forget this node?',
    `Remove ${node.name} from this inventory. The remote account and helper remain installed.`, 'Forget node', async () => {
      await request(`/nodes/${encodeURIComponent(node.id)}`, { method: 'DELETE' });
      await refresh();
      announce('Node removed from inventory');
    }), { class: 'quiet danger-text' }));
  return panel('Machine detail', body);
}
