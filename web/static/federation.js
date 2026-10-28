// SPDX-License-Identifier: Apache-2.0
// Pair HyperNet-connected clusters and operate explicitly shared resources.
import { allowed, getSession, request } from './api.js';
import { button, bytes, confirmation, el, heading, notice, panel, table, time } from './components.js';
import { field, grantForm, grantSummary, scopes } from './federation-grant.js';
import { inferenceForm } from './inference-form.js';

export function federation() {
  const session = getSession(), abort = new AbortController(), dialogs = new Set();
  let active = true, timer, overview, actionError;
  const status = el('div'), content = el('div'), receipts = el('div');
  const valid = () => active && getSession() === session;
  const send = (path, options = {}) => valid() ? request(path, { ...options, signal: abort.signal }) : Promise.reject(new Error('The project changed. Reopen Federation.'));
  const manage = () => allowed('federation:manage');
  const showStatus = backendError => status.replaceChildren(...[actionError, backendError].filter(Boolean).map(message => notice(message, 'error')));
  async function run(action) {
    actionError = null; showStatus();
    try { await action(); if (valid()) await load(); }
    catch (error) { if (valid()) { actionError = error.message; showStatus(); } }
  }
  function dialog(title, ...children) {
    const node = el('dialog', { class: 'workload-dialog' }, el('h2', {}, title), children);
    node.append(button('Close', () => node.close())); dialogs.add(node);
    node.addEventListener('close', () => { dialogs.delete(node); node.remove(); }); document.body.append(node); node.showModal(); return node;
  }
  async function remote(peer, operation, body = {}, mutate = false) {
    const id = mutate ? crypto.randomUUID().replaceAll('-', '') : undefined;
    const receipt = mutate ? el('p', {}, `${peer.cluster.label}: ${operation}. Operation ID: `, el('code', {}, id)) : null;
    if (receipt) receipts.prepend(receipt);
    try {
      const result = await send(`/federation/peers/${peer.id}/request`, { method: 'POST', body: { operation, body, ...(id ? { id } : {}) } });
      if (receipt) receipt.append(' / complete');
      return result;
    } catch (error) {
      if (receipt) receipt.append(' / inspect the retained outcome before retrying with a new ID');
      throw error;
    }
  }
  async function grant(peer, offer = null) {
    const [services, models, offers] = await Promise.all([
      allowed('inference:read') ? send('/inference') : { services: [] },
      allowed('models:read') ? send('/models') : { models: [] },
      allowed('contributors:read') ? send('/workload-offers') : { offers: [] },
    ]);
    dialogs.add(grantForm(`Share with ${peer.label}`, { services: services.services, models: models.models, offers: offers.offers }, async spec => {
      await send(offer ? `/federation/offers/${offer.id}/approve` : `/federation/peers/${peer.id}/grants`, {
        method: 'POST', body: offer ? { revision: offer.revision, grant: spec } : spec }); await load();
    }, offer?.offer.payload.requested));
  }
  function configure() {
    const label = el('input', { value: overview.cluster?.label || 'My cluster' });
    const path = el('input', { value: overview.agent_directory || '', placeholder: '/private/hypernet/ficc' });
    const errors = el('div');
    const node = dialog('Connect the HyperNet companion', el('p', {}, 'Choose the private directory of a running companion registered for ficc.federation/1. The FICC controller must run as its application account.'),
      el('a', { href: '/static/federation-help.html', target: '_blank', rel: 'noopener' }, 'HyperNet setup checklist'), field('Cluster label', label), field('Companion directory', path), errors,
      button('Verify and connect', async () => { try { await send('/federation/configuration', { method: 'PUT', body: { label: label.value, agent_directory: path.value } }); node.close(); await load(); } catch (error) { errors.replaceChildren(notice(error.message, 'error')); } }));
  }
  function pair() {
    const targets = (overview.transport?.targets || []).filter(item => item.protocol === 'ficc.federation/1');
    const target = el('select', {}, targets.map(item => el('option', { value: item.service }, item.service)));
    const rights = el('fieldset', {}, el('legend', {}, 'Request access'), scopes.map(scope => el('label', { class: 'check-label' }, el('input', { type: 'checkbox', value: scope, checked: ['discover', 'inference:invoke'].includes(scope) }), scope)));
    const errors = el('div');
    const node = dialog('Request cluster pairing', el('p', {}, 'Targets come from the approved HyperNet companion configuration. The receiving operator reviews each resource grant.'), field('Approved remote service', target), rights, errors,
      button('Send pairing request', async () => { try { await send('/federation/offers', { method: 'POST', body: { service: target.value, requested: [...rights.querySelectorAll('input:checked')].map(input => input.value) } }); node.close(); await load(); } catch (error) { errors.replaceChildren(notice(error.message, 'error')); } }, { disabled: !targets.length }));
  }
  async function refresh(peer) {
    const result = await send(`/federation/peers/${peer.id}/refresh`, { method: 'POST', body: {} });
    const node = dialog('Select a remote grant', result.grants.length ? result.grants.map(item => panel(item.id, [el('p', {}, grantSummary(item)),
      button('Use this grant', () => run(async () => { await send(`/federation/peers/${peer.id}/refresh`, { method: 'POST', body: { grant: item.id } }); node.close(); }))])) : notice('No current grant is published by this peer. Ask its operator to share access.'));
  }
  async function create(peer, existing = null) {
    const data = await remote(peer, 'inference.prepare');
    if (existing) existing = await remote(peer, 'inference.get', { service: existing.id });
    if (existing?.spec.engine === 'attached') throw new Error('The receiving operator manages attachment profiles locally. Remote start, stop and drain remain available.');
    const mapped = async (path, options) => {
      if (path === '/inference/preview') return remote(peer, 'inference.preview', { spec: options.body });
      return remote(peer, existing ? 'inference.replace' : 'inference.create', existing ? { service: existing.id, ...options.body } : { spec: options.body }, true);
    };
    dialogs.add(inferenceForm(data.models, data.offers, mapped, load, existing));
  }
  function prompt(peer, service) {
    const input = el('textarea', { 'aria-label': 'Remote test prompt' }, 'Explain what this model can help with.'), output = el('pre', { class: 'job-request', 'aria-live': 'polite' });
    let controller;
    const node = dialog(`${peer.cluster.label} / ${service.alias}`, input, button('Send prompt', async () => {
      controller?.abort(); controller = new AbortController(); output.textContent = '';
      try {
        const response = await fetch(`/api/v1/federation/peers/${peer.id}/v1/chat/completions`, { method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf, 'X-FICC-Project': session.principal.project_id, 'X-FICC-Session': session.principal.id },
          body: JSON.stringify({ model: service.id, messages: [{ role: 'user', content: input.value }], stream: true, max_tokens: 256 }) });
        if (!response.ok) throw new Error((await response.json()).error?.message || 'Remote inference failed.');
        const reader = response.body.getReader(), decoder = new TextDecoder(); let pending = '';
        while (valid()) { const { done, value } = await reader.read(); if (done) break; pending += decoder.decode(value, { stream: true }); let boundary;
          while ((boundary = pending.indexOf('\n')) >= 0) { const line = pending.slice(0, boundary).trim(); pending = pending.slice(boundary + 1);
            if (line.startsWith('data:') && line !== 'data: [DONE]') output.textContent += JSON.parse(line.slice(5)).choices?.[0]?.delta?.content || ''; }
        }
      } catch (error) { if (error.name !== 'AbortError' && valid()) output.textContent += `\n${error.message}`; }
    }), button('Cancel request', () => controller?.abort()), output);
    node.addEventListener('close', () => controller?.abort());
  }
  async function model(peer, id) {
    const item = await remote(peer, 'models.manifest', { model: id }), manifest = item.manifest;
    const node = dialog(manifest.name, el('p', {}, `Revision ${manifest.revision}; licence ${manifest.licence}; ${bytes(manifest.files.reduce((sum, file) => sum + file.bytes, 0))}`),
      el('pre', { class: 'job-request' }, JSON.stringify(manifest, null, 2)), button('Acquire or resume verified copy', () => run(async () => {
        await send(`/federation/peers/${peer.id}/models`, { method: 'POST', body: { model: id } }); node.close();
      }), { disabled: !peer.remote_grant.spec.scopes.includes('models:transfer') || !allowed('models:manage') }));
  }
  async function control(peer, item, operation, parent) {
    const current = operation === 'start' ? await remote(peer, 'inference.get', { service: item.id }) : item;
    const acknowledge = operation === 'start' && current.replicas.some(replica => replica.state === 'unknown');
    const explanation = acknowledge
      ? 'An earlier replica stopped without a confirmed result. Its resources must be released before new attempts start. Previous inference requests will not be replayed.'
      : `${peer.cluster.label}: ${item.alias}`;
    confirmation(acknowledge ? 'Start after an unknown outcome' : `${operation} remote service`, explanation,
      acknowledge ? 'Acknowledge and start new attempts' : operation, async () => {
        await remote(peer, 'inference.control', { service: item.id, operation, revision: current.revision,
          ...(acknowledge ? { acknowledge_unknown: true } : {}) }, true);
        parent.close(); await browse(peer);
      });
  }
  async function browse(peer) {
    const data = await remote(peer, 'discover'), canManage = data.scopes.includes('inference:manage');
    const node = dialog(peer.cluster.label,
      el('p', {}, `Verified now. Remote grant expires ${time(data.expires)}.`),
      el('p', {}, 'Compatible client base URL: ', el('code', { class: 'wrap' }, `${location.origin}/api/v1/federation/peers/${peer.id}/v1`), '. Use a federation:invoke project token and a published service ID as model.'),
      table(['Service', 'State', 'Actions'], data.services.map(item => el('tr', {}, el('td', {}, item.alias, el('small', { class: 'cell-note' }, item.id)), el('td', {}, item.state),
        el('td', {}, button('Try prompt', () => prompt(peer, item), { disabled: !data.scopes.includes('inference:invoke') }),
          button('Configure', () => run(() => create(peer, item)), { disabled: !canManage || item.state !== 'stopped' }),
          ['start', 'drain', 'stop', 'remove'].map(operation => button(operation, () => run(() => control(peer, item, operation, node)),
            { disabled: !canManage }))))), 'Published remote services'),
      button('New remote service', () => run(() => create(peer)), { disabled: !canManage }),
      panel('Published model revisions', data.models.map(id => button(id, () => run(() => model(peer, id)), { disabled: !data.scopes.includes('models:read') }))));
  }
  function inspect(peer) {
    const id = el('input', { pattern: '[a-f0-9]{32}', 'aria-label': 'Operation ID' }), result = el('pre');
    dialog('Inspect a retained operation', field('Operation ID', id), button('Inspect outcome', async () => {
      try { result.textContent = JSON.stringify(await remote(peer, 'operation.status', { id: id.value }), null, 2); } catch (error) { result.textContent = error.message; }
    }), result);
  }
  async function load() {
    clearTimeout(timer);
    try {
      overview = await send('/federation'); if (!valid()) return;
      showStatus(overview.error ? `${overview.error.code}: ${overview.error.message}` : null);
      content.replaceChildren(panel('HyperNet connection', [el('p', {}, overview.configured ? `${overview.cluster.label}: ${overview.transport ? 'companion connected' : 'companion unavailable'}` : 'Connect a dedicated HyperNet companion to begin.'),
        overview.cluster && el('details', {}, el('summary', {}, 'Verified cluster identity'), el('pre', {}, JSON.stringify(overview.cluster, null, 2))),
        button('Configure connection', configure, { disabled: !manage() || !session.principal.local_owner }), button('Pair a cluster', pair, { disabled: !manage() || !overview.transport }),
        el('a', { href: '/static/federation-help.html', target: '_blank', rel: 'noopener' }, 'Setup and recovery guide')]),
        panel('Pairing requests', overview.offers.filter(item => item.state !== 'paired').map(item => {
          const other = item.offer.payload[item.direction === 'incoming' ? 'source' : 'destination'];
          return panel(other.label, [el('p', {}, `${item.direction}: ${item.state}; request expires ${time(item.offer.payload.expires)}`), el('code', {}, other.key),
            item.direction === 'incoming' ? button('Review access', () => run(() => grant(other, item)), { disabled: !manage() || item.state !== 'pending' }) :
              button('Complete pairing', () => run(() => send(`/federation/offers/${item.id}/finish`, { method: 'POST' })), { disabled: !manage() }),
            button('Discard request', () => run(() => send(`/federation/offers/${item.id}`, { method: 'DELETE' })), { disabled: !manage() || !['pending', 'suspended'].includes(item.state) })]);
        })),
        panel('Paired clusters', overview.peers.map(peer => panel(peer.cluster.label, [el('p', {}, `${peer.state}; last verified ${time(peer.last_verified)}`),
          peer.remote_grant && el('p', {}, grantSummary(peer.remote_grant)),
          button('Browse shared resources', () => run(() => browse(peer)), { disabled: !allowed('federation:invoke') || peer.state !== 'paired' }),
          button('Refresh remote access', () => run(() => refresh(peer)), { disabled: !manage() || peer.state !== 'paired' }),
          button('Share local resources', () => run(() => grant({ ...peer.cluster, id: peer.id })), { disabled: !manage() || peer.state !== 'paired' }),
          button('Inspect operation', () => inspect(peer), { disabled: !allowed('federation:invoke') || peer.state !== 'paired' }),
          button('Forget receipts', () => confirmation('Forget removed peer', 'Delete its pairing, revoked grants and retained operation outcomes. Export any needed evidence first. Fresh pairing will be required.', 'Forget receipts', () => run(() => send(`/federation/peers/${peer.id}/forget`, { method: 'POST' }))), { disabled: !manage() || !['removed', 'suspended'].includes(peer.state) }),
          button('Remove peer', () => confirmation('Remove peer', 'Revoke its local grants and close active requests. Models remain stored locally.', 'Remove peer', () => run(() => send(`/federation/peers/${peer.id}`, { method: 'DELETE' }))), { disabled: !manage() || peer.state === 'removed' })]))),
        panel('Local access grants', overview.grants.map(item => el('div', {}, el('p', {}, `${item.id}: ${item.state}. ${grantSummary(item)}`),
          el('p', {}, `${item.used_requests}/${item.spec.requests} requests; ${bytes(item.used_bytes)}/${bytes(item.spec.transfer_bytes)} model bytes`),
          button('Retire receipts', () => confirmation('Retire revoked grant', 'Delete the revoked grant and its retained mutation outcomes. Export any needed evidence first. The old grant remains unusable.', 'Retire receipts', () => run(() => send(`/federation/grants/${item.id}/retire`, { method: 'POST' }))), { disabled: !manage() || !['revoked', 'suspended'].includes(item.state) }),
          button('Revoke', () => confirmation('Revoke peer access', 'Active requests are cancelled. Services created by this grant stop only when its stop-on-revoke option is selected.', 'Revoke', () => run(() => send(`/federation/grants/${item.id}`, { method: 'DELETE' }))), { disabled: !manage() || item.state === 'revoked' })))),
        panel('Model transfers', overview.transfers.map(item => el('div', {}, el('p', {}, `${item.model}: ${item.state}; ${bytes(item.offset || 0)} received. ${item.retry ? `Reconnect ${item.retry}/${item.retry_limit}. ` : ''}${item.error?.message || ''}`),
          button('Pause', () => run(() => send(`/federation/transfers/${item.id}/pause`, { method: 'POST' })), { disabled: !['connecting', 'transferring', 'reconnecting'].includes(item.state) }))))) ;
    } catch (error) { if (valid()) showStatus(error.message); }
    if (valid()) timer = setTimeout(load, 5000);
  }
  const element = el('div', {}, heading('CLUSTER / FEDERATION', 'Federation', 'Share selected services and models through authenticated HyperNet streams.', [button('Refresh', () => { actionError = null; void load(); })]), status, content,
    panel('Operations started in this view', [el('p', {}, 'Retain operation IDs to inspect an interrupted mutation before issuing a new action.'), receipts]));
  void load();
  return { element, dispose() { active = false; clearTimeout(timer); abort.abort(); for (const node of dialogs) node.close(); } };
}
