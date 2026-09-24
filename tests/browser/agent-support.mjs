// SPDX-License-Identifier: Apache-2.0
// Supply distinct process, run and delivery identities for browser regressions.
import { expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { node, origin } from './support.mjs';

export const agentScopes = ['nodes:read', 'resources:read', 'agents:read', 'agents:execute', 'agents:stop',
  'bus:read', 'bus:send', 'terminals:read', 'terminals:execute'];
export function agent(index = 1, extra = {}) {
  return { id: `agent-${index}`, node_id: `sample-${index}`, node_name: `Machine ${index}`, profile_id: `profile-${index}`,
    label: `Agent ${index}`, adapter: 'generic', workspace: `/work/project-${index}`, version: '1.0', delivery_method: 'inbox',
    state: 'running', terminal_id: `terminal-${index}`, run_id: 'run-1', runtime_session_id: `session-${index}`,
    created_at: 1000, updated_at: 1001, last_contact: 1001, error: null, ...extra };
}
export async function setupAgents(page, options = {}) {
  const agents = options.agents ?? [agent()];
  const runs = options.runs ?? [{ id: 'run-1', name: 'Sample run', state: 'open', agent_ids: agents.filter(a => a.run_id === 'run-1').map(a => a.id), message_count: 0, created_at: 1000 }];
  const profiles = agents.map(a => ({ id: a.profile_id, name: `Profile ${a.id}`, node_id: a.node_id, adapter: a.adapter,
    argv: ['/usr/bin/agent', '--workspace', a.workspace], workspace: a.workspace, version: a.version, delivery_method: a.delivery_method, verified_at: 1000 }));
  const state = { agents, runs, profiles, previews: [], launches: [], controls: [], messages: options.messages ?? [],
    sends: [], creations: [], closes: [], denied: false, lists: [], deliveries: options.deliveries ?? [] };
  const denied = route => route.fulfill({ status: 403, json: { error: { code: 'denied', message: 'Permission revoked.' } } });
  await page.route('**/api/v1/session', route => route.fulfill({ json: { csrf: 'test-csrf', mode: options.mode ?? 'live', version: 'fixture',
    principal: { id: 'operator', label: 'Test operator', scopes: options.scopes ?? agentScopes, node_ids: null, root_ids: null } } }));
  await page.route('**/api/v1/nodes', route => route.fulfill({ json: { nodes: [node()] } }));
  await page.route('**/api/v1/agent-profiles', route => route.fulfill({ json: { profiles: options.noProfiles ? [] : state.profiles } }));
  await page.route('**/api/v1/agent-previews', route => {
    const body = route.request().postDataJSON(); state.previews.push(body);
    const profile = state.profiles.find(p => p.id === body.profile_id);
    return route.fulfill({ json: { preview_id: 'frozen-preview', expires_at: Date.now() / 1000 + 120,
      profile, node: { name: profile.node_id, account: 'operator' }, request: body, delivery_method: profile.delivery_method } });
  });
  await page.route('**/api/v1/agents', route => {
    if (state.denied) return denied(route);
    if (route.request().method() === 'POST') {
      state.launches.push(route.request().postDataJSON());
      if (options.dropLaunch && state.launches.length === 1) return route.abort('connectionfailed');
      return route.fulfill({ json: agents.find(a => a.profile_id === state.previews.at(-1).profile_id) });
    }
    return route.fulfill({ json: { agents: state.agents } });
  });
  await page.route('**/api/v1/agents/*/*', route => {
    state.controls.push({ path: new URL(route.request().url()).pathname, body: route.request().postDataJSON() });
    return route.fulfill({ json: state.agents[0] });
  });
  await page.route('**/api/v1/bus/runs', route => {
    if (state.denied) return denied(route);
    if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON(); state.creations.push(body);
      if (options.dropRun && state.creations.length === 1) return route.abort('connectionfailed');
      const run = { id: 'run-new', name: body.name, state: 'open', agent_ids: [], message_count: 0, created_at: 1000 };
      state.runs = [...state.runs.filter(r => r.id !== run.id), run]; return route.fulfill({ json: run });
    }
    return route.fulfill({ json: { runs: state.runs } });
  });
  await page.route('**/api/v1/bus/runs/*/messages**', route => {
    if (state.denied) return denied(route);
    if (route.request().method() === 'POST') {
      state.sends.push({ path: new URL(route.request().url()).pathname, body: route.request().postDataJSON() });
      if (options.dropMessage && state.sends.length === 1) return route.abort('connectionfailed');
      return route.fulfill({ json: { message: { id: 'sent-message' }, deliveries: [] } });
    }
    const url = new URL(route.request().url()); state.lists.push(url.pathname + url.search);
    return route.fulfill({ json: { messages: url.searchParams.get('after') === '100' ? [] : state.messages, next_after: options.paged && url.searchParams.get('after') === '0' ? 100 : null } });
  });
  await page.route('**/api/v1/bus/deliveries?*', route => route.fulfill({ json: { deliveries: state.deliveries } }));
  await page.route('**/api/v1/bus/runs/*/close', route => { state.closes.push({ path: new URL(route.request().url()).pathname, body: route.request().postDataJSON() }); return route.fulfill({ json: state.runs[0] }); });
  await page.route('**/api/v1/terminals', route => route.fulfill({ json: { terminals: [] } }));
  await page.goto(origin); await page.locator(`[data-view=${options.view ?? 'agents'}]`).click();
  await expect(page.getByRole('heading', { name: options.view === 'bus' ? 'Agent bus' : 'Coding agents', exact: true })).toBeVisible();
  return state;
}
