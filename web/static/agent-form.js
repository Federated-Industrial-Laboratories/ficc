// SPDX-License-Identifier: Apache-2.0
// Preview a registered command and retain one launch identity across lost replies.
import { allowed, request } from './api.js';
import { button, details, el, errorPanel, notice, state, time } from './components.js';

function machineName(node) {
  return `${node.name} / ${node.account}${node.host ? ` @ ${node.host}` : ''}`;
}

function profileOptions(profiles) {
  // Repeated registrations of the same command do not create more launch choices.
  const unique = new Map();
  for (const item of profiles) {
    const key = JSON.stringify([item.name, item.adapter, item.argv, item.workspace, item.version, item.delivery_method]);
    if (!unique.has(key) || item.verified_at > unique.get(key).verified_at) unique.set(key, item);
  }
  const items = [...unique.values()].sort((a, b) => a.name.localeCompare(b.name) || a.workspace.localeCompare(b.workspace));
  return items.map(item => {
    const sameName = items.filter(other => other.name === item.name);
    let label = item.name;
    if (sameName.length > 1) label += ` / ${item.workspace}`;
    if (sameName.filter(other => other.workspace === item.workspace).length > 1) {
      label += ` / ${item.argv.join(' ')} / ${item.adapter} / ${item.version} / ${item.delivery_method}`;
    }
    return el('option', { value: item.id }, label);
  });
}

export function newAgent(received) {
  const trigger = document.activeElement;
  let active = true, busy = false, frozen, inventoryTimer;
  const content = el('div'), close = button('Close', () => dialog.close());
  const dialog = el('dialog', { class: 'agent-dialog', 'aria-labelledby': 'agent-title' },
    el('div', { class: 'dialog-heading' }, el('h2', { id: 'agent-title' }, 'Launch agent'), close), content);
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { active = false; clearTimeout(inventoryTimer); dialog.remove(); trigger?.focus(); });
  document.body.append(dialog); dialog.showModal();
  async function load() {
    content.replaceChildren(state('Finding installed agents', 'Polling enrolled machines and reading open runs.'));
    try {
      const [{ profiles, discovery = [] }, { runs }, { nodes }] = await Promise.all([
        request('/agent-profiles/refresh', { method: 'POST', body: {} }), request('/bus/runs'), allowed('nodes:read') ? request('/nodes') : { nodes: [] },
      ]);
      if (!active) return;
      const machines = new Map(nodes.map(node => [node.id, node]));
      for (const scan of discovery) {
        if (!machines.has(scan.node_id)) machines.set(scan.node_id, scan.node);
      }
      for (const profile of profiles) {
        if (!machines.has(profile.node_id) && profile.node) machines.set(profile.node_id, profile.node);
      }
      const open = runs.filter(run => run.state === 'open');
      if (!machines.size || !open.length) {
        content.replaceChildren(state('Agent setup required', !machines.size ?
          'No enrolled machines are available. Add a machine in Overview to discover its installed agents.' : 'Create an open run on the Bus page first.')); return;
      }
      compose([...machines.values()].sort((a, b) => a.name.localeCompare(b.name)),
        profiles.filter(item => item.availability !== 'unavailable'), open, discovery);
    } catch (error) { if (active) content.replaceChildren(errorPanel(error, load)); }
  }
  function compose(nodes, profiles, runs, discovery) {
    const machine = el('select', { id: 'agent-machine' }, nodes.map(node => el('option', { value: node.id }, machineName(node))));
    const profile = el('select', { id: 'agent-profile', required: true });
    const run = el('select', { id: 'agent-run' }, runs.map(item => el('option', { value: item.id }, item.name)));
    const label = el('input', { id: 'agent-label', required: true, maxlength: 80, value: 'Coding agent', autocomplete: 'off' });
    const errors = el('div'), registration = el('div', { class: 'agent-registration', 'aria-live': 'polite' });
    const submit = el('button', { type: 'submit', class: 'primary' }, 'Preview agent');
    function describe() {
      const item = profiles.find(item => item.id === profile.value && item.node_id === machine.value);
      const node = nodes.find(node => node.id === machine.value);
      const scan = discovery.find(item => item.node_id === machine.value);
      const scanNotice = scan && (scan.state !== 'ready' || scan.errors?.length) && notice(
        scan.message || scan.errors?.map(error => `${error.command}: ${error.message}`).join(' ') || 'Agent discovery is pending.', 'warning');
      profile.disabled = !item; submit.disabled = !item;
      if (!item) {
        registration.replaceChildren(state('No registered agents on this machine',
          `No launchable agents were found on ${node.name}. Install an agent for ${node.account}, then use Refresh agents. Custom commands can also be registered with ficc agent-profile-add.`));
        if (scanNotice) registration.append(scanNotice);
        return;
      }
      registration.replaceChildren(details([
        ['Working directory', item.workspace], ['Registered command', el('code', { class: 'agent-command' }, JSON.stringify(item.argv))],
        ['Adapter / version', `${item.adapter} / ${item.version === 'unversioned' ? 'Version not checked' : item.version ?? 'Unknown'}`],
        ['Last verified', time(item.verified_at)],
        ['Registration', item.source === 'discovered' ? 'Automatically discovered on this machine' : 'Manually registered command'],
      ]), el('p', { class: 'muted' }, 'Preview checks this command again. Provider sign-in is completed in the agent terminal.'));
      if (scanNotice) registration.append(scanNotice);
    }
    function selectMachine() {
      errors.replaceChildren();
      profile.replaceChildren(...profileOptions(profiles.filter(item => item.node_id === machine.value)));
      if (!profile.options.length) profile.append(el('option', { value: '' }, 'No registered agents'));
      describe();
    }
    machine.addEventListener('change', selectMachine);
    profile.addEventListener('change', describe);
    selectMachine();
    const form = el('form', { onsubmit: async event => {
      event.preventDefault(); if (busy) return;
      if (!profiles.some(item => item.id === profile.value && item.node_id === machine.value)) return;
      busy = true; submit.disabled = true;
      for (const field of [machine, profile, run, label]) field.disabled = true;
      const body = { profile_id: profile.value, label: label.value.trim(), run_id: run.value, cols: 100, rows: 30 };
      const runName = runs.find(item => item.id === run.value).name;
      errors.replaceChildren();
      try {
        const preview = await request('/agent-previews', { method: 'POST', body });
        if (active) confirm(preview, body, runName, () => {
          frozen = undefined;
          content.replaceChildren(form); machine.focus();
        });
      } catch (error) { if (active) errors.replaceChildren(errorPanel(error)); }
      finally {
        busy = false; submit.disabled = false;
        for (const field of [machine, profile, run, label]) field.disabled = false;
      }
    } }, el('label', { for: machine.id }, 'Machine'), machine,
    el('label', { for: profile.id }, 'Registered agent profile'), profile, registration,
    el('label', { for: run.id }, 'Agent bus run'), run, el('label', { for: label.id }, 'Agent label'), label, errors,
    el('div', { class: 'actions' }, submit));
    content.replaceChildren(form); machine.focus();
    async function updateDiscovery() {
      if (!active) return;
      if (busy) { inventoryTimer = setTimeout(updateDiscovery, 1000); return; }
      try {
        const result = await request('/agent-profiles');
        if (!active) return;
        if (busy) { inventoryTimer = setTimeout(updateDiscovery, 1000); return; }
        profiles = result.profiles.filter(item => item.availability !== 'unavailable');
        discovery = result.discovery ?? [];
        const chosen = profile.value;
        selectMachine();
        if ([...profile.options].some(option => option.value === chosen)) profile.value = chosen;
        describe();
        if (discovery.some(scan => ['pending', 'scanning'].includes(scan.state))) inventoryTimer = setTimeout(updateDiscovery, 1000);
      } catch (error) { if (active) errors.replaceChildren(errorPanel(error, updateDiscovery)); }
    }
    if (discovery.some(scan => ['pending', 'scanning'].includes(scan.state))) inventoryTimer = setTimeout(updateDiscovery, 1000);
  }
  function confirm(preview, requested, runName, edit) {
    const profile = preview.profile, consent = el('input', { id: 'agent-consent', type: 'checkbox', required: true });
    const errors = el('div'), submit = el('button', { type: 'submit', class: 'primary' }, 'Confirm and launch agent');
    const back = button('Back', () => { if (!busy && !frozen) edit(); });
    const form = el('form', { onsubmit: async event => {
      event.preventDefault(); if (busy) return;
      frozen ??= { preview_id: preview.preview_id, idempotency_key: crypto.randomUUID(), confirm_execution: true };
      busy = true; close.disabled = true; submit.disabled = true; consent.disabled = true; back.disabled = true;
      try {
        const agent = await request('/agents', { method: 'POST', body: frozen });
        if (active) { dialog.close(); received(agent); }
      } catch (error) {
        if (active) {
          errors.replaceChildren(errorPanel(error), notice('Check the agent list before starting another agent. Retry keeps this exact launch identity.', 'warning'));
          submit.textContent = 'Retry same agent';
        }
      } finally { busy = false; close.disabled = false; submit.disabled = false; }
    } }, details([['Machine / account', machineName(preview.node)], ['Registered agent profile', profile.name],
      ['Adapter / version', `${profile.adapter} / ${profile.version ?? 'Unverified'}`], ['Working directory', profile.workspace],
      ['Command arguments', el('code', { class: 'agent-command' }, JSON.stringify(profile.argv))], ['Delivery', preview.delivery_method],
      ['Agent bus run', runName], ['Agent label', requested.label]]),
    notice(`The agent will run as ${preview.node.account} on ${preview.node.name}, with that account's file and command access. Its own approval and sign-in settings still apply.`, 'warning'),
    el('label', { for: consent.id, class: 'check-label' }, consent, 'Launch this exact command on this machine and enroll it in this run.'),
    errors, el('div', { class: 'actions' }, back, submit));
    content.replaceChildren(form); consent.focus();
  }
  load();
}

export function rebindAgent(agent, received) {
  const trigger = document.activeElement;
  let active = true, busy = false;
  const session = el('input', { id: 'agent-rebind-session', required: true, maxlength: 100, autocomplete: 'off' });
  const consent = el('input', { id: 'agent-rebind-consent', type: 'checkbox', required: true });
  const errors = el('div'), close = button('Cancel', () => dialog.close());
  const submit = el('button', { type: 'submit', class: 'primary' }, 'Bind exact session');
  const dialog = el('dialog', { class: 'agent-dialog', 'aria-labelledby': 'rebind-title' },
    el('h2', { id: 'rebind-title' }, 'Bind agent runtime session'),
    el('form', { onsubmit: async event => {
      event.preventDefault(); if (busy) return;
      busy = true; close.disabled = true; submit.disabled = true; session.disabled = true; consent.disabled = true;
      try {
        const result = await request(`/agents/${encodeURIComponent(agent.id)}/rebind`, { method: 'POST',
          body: { runtime_session_id: session.value.trim(), confirm_rebind: true } });
        if (active) { dialog.close(); received(result); }
      } catch (error) { if (active) errors.replaceChildren(errorPanel(error)); }
      finally { busy = false; close.disabled = false; submit.disabled = false; session.disabled = false; consent.disabled = false; }
    } }, notice(`Direct delivery to ${agent.label} follows the exact bound runtime session. Confirm the new session identity in its terminal before rebinding.`, 'warning'),
    el('label', { for: session.id }, 'Exact runtime session ID'), session,
    el('label', { for: consent.id, class: 'check-label' }, consent, 'Permit direct delivery to this exact runtime session.'), errors,
    el('div', { class: 'actions' }, close, submit)));
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { active = false; dialog.remove(); trigger?.focus(); });
  document.body.append(dialog); dialog.showModal(); session.focus();
}
