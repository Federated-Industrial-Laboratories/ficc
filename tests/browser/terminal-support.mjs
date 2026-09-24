// SPDX-License-Identifier: Apache-2.0
// Drive real terminal assets with authenticated HTTP and byte-stream fixtures.
import { expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { node, origin } from './support.mjs';

export const terminalScopes = ['nodes:read', 'resources:read', 'terminals:read', 'terminals:execute', 'terminals:stop'];
export function terminalRecord(index = 1, extra = {}) {
  return { id: String(index).padStart(32, '0'), node_id: `sample-${index}`, node_name: `Sample machine ${index}`,
    account: 'operator', label: `Shell ${index}`, mode: 'tmux', state: 'detached',
    created_at: Date.now() / 1000, updated_at: Date.now() / 1000, error: null, ...extra };
}
export async function setupTerminals(page, options = {}) {
  const state = { terminals: options.terminals ?? [terminalRecord()], creations: [], tickets: [], stops: [], reconciliations: [], sockets: [], frames: [], denied: false };
  await page.route('**/api/v1/session', route => route.fulfill({ json: { csrf: 'test-csrf', mode: options.mode ?? 'live', version: 'fixture',
    principal: { id: 'test', label: 'Test operator', scopes: options.scopes ?? terminalScopes, node_ids: null, root_ids: null } } }));
  await page.route('**/api/v1/nodes', route => route.fulfill({ json: { nodes: options.nodes ?? [node(1, { capabilities: { terminals_ephemeral: true, terminals_tmux: true } })] } }));
  await page.route('**/api/v1/terminals', route => {
    if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON(); state.creations.push(body);
      if (options.dropFirstCreate && state.creations.length === 1) return route.abort('connectionfailed');
      const record = terminalRecord(2, { ...body, state: 'new' }); state.terminals.push(record);
      return route.fulfill({ status: 201, json: record });
    }
    return state.denied ? route.fulfill({ status: 403, json: { error: { code: 'denied', message: 'Terminal permission revoked.' } } }) : route.fulfill({ json: { terminals: state.terminals } });
  });
  await page.route('**/api/v1/terminals/*/tickets', route => {
    state.tickets.push(route.request().headers());
    const id = new URL(route.request().url()).pathname.split('/').at(-2);
    return route.fulfill({ json: { ticket: 'one-use-fixture-ticket', expires_at: Date.now() / 1000 + 15, websocket_path: `/api/v1/terminals/${id}/stream` } });
  });
  await page.route('**/api/v1/terminals/*/stop', route => {
    state.stops.push(route.request().postDataJSON()); state.terminals[0].state = 'stopped';
    return route.fulfill({ json: state.terminals[0] });
  });
  await page.route('**/api/v1/terminals/*/reconcile', route => {
    state.reconciliations.push({ url: route.request().url(), body: route.request().postDataJSON(), headers: route.request().headers() });
    state.terminals[0].state = 'detached'; return route.fulfill({ json: state.terminals[0] });
  });
  await page.routeWebSocket('**/api/v1/terminals/*/stream', socket => {
    state.sockets.push(socket);
    socket.onMessage(message => {
      state.frames.push(message);
      if (typeof message === 'string' && JSON.parse(message).type === 'auth' && !options.deferAttach) socket.send(JSON.stringify({ type: 'status', state: 'attached' }));
      if (Buffer.isBuffer(message) && options.echo !== false) socket.send(message);
    });
  });
  await page.goto(origin); await page.locator('[data-view=terminals]').click();
  await expect(page.getByRole('heading', { name: 'Terminals', exact: true })).toBeVisible();
  return state;
}
export async function attachTerminal(page, state) {
  await page.getByRole('button', { name: 'Reattach', exact: true }).first().click();
  await expect.poll(() => state.sockets.length).toBe(1);
  await expect(page.getByText('Attached. Input goes only', { exact: false })).toBeVisible();
}
