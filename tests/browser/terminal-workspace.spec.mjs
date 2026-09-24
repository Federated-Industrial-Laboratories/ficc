// SPDX-License-Identifier: Apache-2.0
// Exercise independent tile geometry, focus, transport identity and disposal.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { setupTerminals, terminalRecord } from './terminal-support.mjs';
import { capture, node } from './support.mjs';

const tile = (page, record) => page.locator(`[data-terminal-id="${record.id}"]`);
const inputs = connection => Buffer.concat(connection.frames.filter(Buffer.isBuffer)).toString();
const controls = (connection, type) => connection.frames.filter(frame => typeof frame === 'string').map(JSON.parse).filter(frame => frame.type === type);
async function attach(page, state, record) {
  await page.locator(`[data-focus="attach-${record.id}"]`).click();
  await expect.poll(() => state.connections.some(item => item.id === record.id)).toBe(true);
  await expect(tile(page, record).getByRole('button', { name: 'Focus terminal' })).toBeEnabled();
}
async function split(page, axis) {
  await page.getByRole('button', { name: `Split ${axis}`, exact: true }).click();
  await page.getByLabel('Open a shell with full authority', { exact: false }).check();
  await page.getByRole('button', { name: 'Confirm and open terminal' }).click();
}

test('independent right and down splits resize, zoom and collapse without new tickets', async ({ page }) => {
  const first = terminalRecord(), state = await setupTerminals(page, { terminals: [first] });
  await attach(page, state, first); await split(page, 'right');
  await expect(page.locator('.terminal-tile')).toHaveCount(2);
  await expect(page.locator('.terminal-divider.right')).toHaveCount(1);
  await split(page, 'down'); await expect(page.locator('.terminal-tile')).toHaveCount(3);
  await expect(page.locator('.terminal-divider.down')).toHaveCount(1);
  expect(state.creations.map(record => record.node_id)).toEqual(['sample-1', 'sample-1']);
  const side = page.getByRole('separator', { name: 'Resize side by side terminals' });
  const before = Number(await side.getAttribute('aria-valuenow'));
  await side.focus(); await page.keyboard.press('ArrowRight');
  await expect.poll(async () => Number(await side.getAttribute('aria-valuenow'))).toBeGreaterThan(before);
  const rect = await side.boundingBox();
  await page.mouse.move(rect.x + rect.width / 2, rect.y + rect.height / 2); await page.mouse.down();
  await page.mouse.move(rect.x - 55, rect.y + rect.height / 2); await page.mouse.up();
  await expect.poll(async () => Number(await side.getAttribute('aria-valuenow'))).toBeLessThan(before + 5);
  const last = state.terminals.at(-1);
  await tile(page, last).getByRole('button', { name: 'Zoom tile' }).click();
  await expect(page.locator('.terminal-tile:visible')).toHaveCount(1);
  await expect(page.locator('.terminal-divider:visible')).toHaveCount(0);
  await tile(page, last).getByRole('button', { name: 'Restore tiles' }).click();
  await expect(page.locator('.terminal-tile:visible')).toHaveCount(3);
  await tile(page, last).getByRole('button', { name: 'Close pane' }).click();
  await expect(page.locator('.terminal-tile')).toHaveCount(2);
  await expect(page.locator('.terminal-divider')).toHaveCount(1);
  expect(state.tickets).toHaveLength(3);
  expect(state.stops).toHaveLength(0);
  await expect.poll(() => state.connections.at(-1).closed).toBe(true);
  expect(state.connections.slice(0, 2).every(item => !item.closed)).toBe(true);
  await capture(page, 'terminal-split-collapse');
});

test('four panes keep independent byte targets and the fifth attachment is refused locally', async ({ page }) => {
  const records = Array.from({ length: 5 }, (_, i) => terminalRecord(i + 1, { node_id: 'sample-1', node_name: 'Shared machine' }));
  const state = await setupTerminals(page, { terminals: records });
  for (const record of records.slice(0, 4)) {
    await attach(page, state, record); await page.keyboard.type(`input-${record.id}-`);
  }
  for (const [index, connection] of state.connections.entries()) expect(inputs(connection)).toBe(`input-${records[index].id}-`);
  await expect(page.getByRole('button', { name: 'Split right' })).toBeDisabled();
  await page.locator(`[data-focus="attach-${records[4].id}"]`).click();
  await expect(page.getByText('Workspace limit reached:', { exact: false })).toBeVisible();
  expect(state.tickets).toHaveLength(4); await expect(page.locator('.terminal-tile')).toHaveCount(4);
  await tile(page, records[0]).getByRole('button', { name: 'Focus terminal' }).click(); await page.keyboard.type('first-again');
  expect(inputs(state.connections[0])).toBe(`input-${records[0].id}-first-again`);
  for (const [index, connection] of state.connections.slice(1).entries()) expect(inputs(connection)).toBe(`input-${records[index + 1].id}-`);
  await capture(page, 'terminal-four-panes');
});

test('machine tabs preserve hidden output ACKs and prohibit hidden input and resize', async ({ page }) => {
  const records = [terminalRecord(1), terminalRecord(2)], state = await setupTerminals(page, { terminals: records });
  for (const record of records) await attach(page, state, record);
  const first = tile(page, records[0]), second = tile(page, records[1]);
  await expect(first).toBeHidden(); await expect(second).toBeVisible();
  const resizeCount = controls(state.connections[0], 'resize').length;
  state.sockets[0].send(Buffer.from('hidden π'));
  await expect.poll(() => controls(state.connections[0], 'ack').at(-1)?.bytes).toBe(9);
  await first.locator('.xterm-helper-textarea').evaluate(element => {
    element.focus(); const data = new DataTransfer(); data.setData('text/plain', 'wrong-target');
    element.dispatchEvent(new ClipboardEvent('paste', { clipboardData: data, bubbles: true, cancelable: true }));
  });
  expect(inputs(state.connections[0])).toBe('');
  await page.setViewportSize({ width: 900, height: 850 });
  await second.getByRole('button', { name: 'Focus terminal' }).click(); await page.keyboard.type('visible');
  await expect(second.locator('.xterm-rows')).toContainText('visible');
  expect(controls(state.connections[0], 'resize')).toHaveLength(resizeCount);
  await page.getByRole('tab', { name: 'Sample machine 1', exact: true }).click();
  await expect(first.locator('.xterm-rows')).toContainText('hidden π');
  await first.getByRole('button', { name: 'Focus terminal' }).click(); await page.keyboard.type('revealed');
  await expect.poll(() => controls(state.connections[0], 'resize').length).toBeGreaterThan(resizeCount);
  expect(inputs(state.connections[0])).toBe('revealed'); expect(inputs(state.connections[1])).toBe('visible');
  expect(state.tickets).toHaveLength(2);
});

test('late attached and output events cannot steal the visible target or revive a finished stream', async ({ page }) => {
  const records = [terminalRecord(1), terminalRecord(2)], state = await setupTerminals(page, { terminals: records, deferAttach: true });
  for (const record of records) {
    await page.locator(`[data-focus="attach-${record.id}"]`).click();
    await expect.poll(() => state.connections.some(item => item.id === record.id)).toBe(true);
  }
  state.sockets[1].send(JSON.stringify({ type: 'status', state: 'attached' }));
  await tile(page, records[1]).getByRole('button', { name: 'Focus terminal' }).click();
  state.sockets[0].send(JSON.stringify({ type: 'status', state: 'attached' }));
  await page.keyboard.type('only-second');
  expect(inputs(state.connections[0])).toBe('');
  await expect.poll(() => inputs(state.connections[1])).toBe('only-second');
  // Inject sequential statuses in one task before the queued socket close completes.
  await page.evaluate(async id => {
    const original = WebSocket.prototype.close;
    WebSocket.prototype.close = function() {};
    window.restoreTerminalClose = () => { WebSocket.prototype.close = original; };
  }, records[1].id);
  state.sockets[1].send(JSON.stringify({ type: 'status', state: 'denied', message: 'Permission removed.' }));
  state.sockets[1].send(JSON.stringify({ type: 'status', state: 'attached' }));
  state.sockets[1].send(Buffer.from('late private output'));
  await expect(tile(page, records[1]).getByRole('button', { name: 'Focus terminal' })).toBeDisabled();
  await expect(tile(page, records[1])).not.toContainText('late private output');
  await page.evaluate(() => window.restoreTerminalClose());
});

test('a delayed attachment cannot move focus away from a machine tab or toolbar', async ({ page }) => {
  const record = terminalRecord(), state = await setupTerminals(page, { deferAttach: true });
  await page.locator(`[data-focus="attach-${record.id}"]`).click(); await expect.poll(() => state.sockets.length).toBe(1);
  await page.getByRole('button', { name: 'Expand workspace', exact: true }).focus();
  state.sockets[0].send(JSON.stringify({ type: 'status', state: 'attached' }));
  await expect(tile(page, record).getByRole('button', { name: 'Focus terminal' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Expand workspace', exact: true })).toBeFocused();
});

test('pending tickets are discarded after pane closure and after navigation', async ({ page }) => {
  const record = terminalRecord(), state = await setupTerminals(page, { deferTicket: true });
  await page.locator(`[data-focus="attach-${record.id}"]`).click();
  await expect.poll(() => state.ticketRequests.length).toBe(1);
  await tile(page, record).getByRole('button', { name: 'Close pane' }).click();
  await state.ticketRequests[0].route.fulfill({ json: { ticket: 'late', websocket_path: `/api/v1/terminals/${record.id}/stream` } });
  await page.locator(`[data-focus="attach-${record.id}"]`).click(); await expect.poll(() => state.ticketRequests.length).toBe(2);
  await page.locator('[data-view=overview]').click();
  await state.ticketRequests[1].route.fulfill({ json: { ticket: 'late', websocket_path: `/api/v1/terminals/${record.id}/stream` } });
  await expect(page.locator('.terminal-tile')).toHaveCount(0);
  expect(state.sockets).toHaveLength(0);
});

test('refresh and same-page navigation preserve attachments while leaving disposes all', async ({ page }) => {
  const records = [terminalRecord(1), terminalRecord(2)], state = await setupTerminals(page, { terminals: records });
  for (const record of records) await attach(page, state, record);
  await page.getByRole('button', { name: 'Refresh terminals' }).click();
  await page.locator('[data-view=terminals]').click();
  await expect(page.locator('.terminal-tile')).toHaveCount(2);
  expect(state.tickets).toHaveLength(2); expect(state.connections.every(item => !item.closed)).toBe(true);
  await page.locator('[data-view=overview]').click();
  await expect.poll(() => state.connections.every(item => item.closed)).toBe(true);
});

test('page lifecycle detaches all panes and allows explicit attachment after returning', async ({ page }) => {
  const record = terminalRecord(), state = await setupTerminals(page); await attach(page, state, record);
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
  await expect.poll(() => state.connections[0].closed).toBe(true); await expect(page.locator('.terminal-tile')).toHaveCount(0);
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
  await page.locator(`[data-focus="attach-${record.id}"]`).click();
  await expect.poll(() => state.tickets.length).toBe(2);
  await tile(page, record).getByRole('button', { name: 'Focus terminal' }).click(); await page.keyboard.type('returned');
  expect(inputs(state.connections[1])).toBe('returned');
});

test('read revocation clears every visible and hidden pane', async ({ page }) => {
  const records = [terminalRecord(1), terminalRecord(2)], state = await setupTerminals(page, { terminals: records });
  for (const record of records) await attach(page, state, record);
  await page.getByRole('button', { name: 'Expand workspace', exact: true }).click();
  state.denied = true;
  await expect(page.getByText('Terminal permission revoked.', { exact: true })).toBeVisible();
  await expect(page.locator('.xterm')).toHaveCount(0); await expect.poll(() => state.connections.every(item => item.closed)).toBe(true);
});

for (const action of ['sign out', 'expire']) test(`${action} disposes visible and hidden attachments`, async ({ page }) => {
  const records = [terminalRecord(1), terminalRecord(2)], state = await setupTerminals(page, { terminals: records });
  for (const record of records) await attach(page, state, record);
  if (action === 'sign out') await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  else {
    await page.route('**/api/v1/terminals', route => route.fulfill({ status: 401, json: { error: { message: 'Expired' } } }));
    await page.getByRole('button', { name: 'Refresh terminals' }).click();
  }
  await expect(page.getByRole('heading', { name: 'Console locked', exact: true })).toBeVisible();
  await expect(page.locator('.xterm')).toHaveCount(0); await expect.poll(() => state.connections.every(item => item.closed)).toBe(true);
});

test('sixteen global panes are bounded across distinct machines', async ({ page }) => {
  test.setTimeout(60000);
  const records = Array.from({ length: 17 }, (_, i) => terminalRecord(i + 1,
    { node_id: `group-${Math.floor(i / 4)}`, node_name: `Group ${Math.floor(i / 4)}` }));
  const state = await setupTerminals(page, { terminals: records });
  for (const record of records.slice(0, 16)) await attach(page, state, record);
  await page.locator(`[data-focus="attach-${records[16].id}"]`).click();
  await expect(page.getByText('Workspace limit reached:', { exact: false })).toBeVisible();
  expect(state.tickets).toHaveLength(16); await expect(page.locator('.terminal-tile')).toHaveCount(16);
  await expect(page.getByRole('button', { name: 'Split down' })).toBeDisabled();
  await page.locator('[data-view=overview]').click();
  await expect.poll(() => state.connections.every(item => item.closed)).toBe(true);
});

test('open by exact record identity focuses an existing tile without duplicate tickets', async ({ page }) => {
  const records = [terminalRecord(1), terminalRecord(2)], state = await setupTerminals(page, { terminals: records });
  await attach(page, state, records[0]);
  await page.evaluate(id => window.dispatchEvent(new CustomEvent('ficc-open-terminal', { detail: { terminalId: id } })), records[1].id);
  await expect(tile(page, records[1]).getByRole('button', { name: 'Focus terminal' })).toBeEnabled();
  await page.evaluate(id => window.dispatchEvent(new CustomEvent('ficc-open-terminal', { detail: { terminalId: id } })), records[0].id);
  await expect(tile(page, records[0])).toBeVisible(); await page.keyboard.type('exact-first');
  expect(inputs(state.connections[0])).toBe('exact-first'); expect(inputs(state.connections[1])).toBe('');
  expect(state.tickets).toHaveLength(2);
});

test('fullscreen entry, exit and denial keep tile identity and connections', async ({ page }) => {
  const record = terminalRecord(), state = await setupTerminals(page); await attach(page, state, record);
  await page.getByRole('button', { name: 'Enter fullscreen', exact: true }).click();
  await expect.poll(() => page.evaluate(() => Boolean(document.fullscreenElement))).toBe(true);
  await expect(tile(page, record).locator('.terminal-identity')).toContainText('Sample machine 1 / operator');
  await page.getByRole('button', { name: 'Open terminal', exact: true }).click();
  await expect(page.getByRole('dialog', { name: 'Open terminal', exact: true })).toBeVisible();
  await expect(page.getByLabel('Terminal machine and account')).toBeDisabled();
  await page.getByRole('dialog').getByRole('button', { name: 'Close', exact: true }).click();
  await page.getByRole('button', { name: 'Exit fullscreen', exact: true }).click();
  await expect.poll(() => page.evaluate(() => Boolean(document.fullscreenElement))).toBe(false);
  await page.getByRole('button', { name: 'Restore workspace', exact: true }).click();
  await page.evaluate(() => { Element.prototype.requestFullscreen = async () => { throw new Error('Unavailable'); }; });
  await page.getByRole('button', { name: 'Enter fullscreen', exact: true }).click();
  await expect(page.getByText('Browser fullscreen is unavailable.', { exact: false })).toBeVisible();
  await tile(page, record).getByRole('button', { name: 'Focus terminal' }).click(); await page.keyboard.type('still-connected');
  expect(inputs(state.connections[0])).toBe('still-connected'); expect(state.tickets).toHaveLength(1);
});

for (const width of [390, 768, 1280, 1920]) test(`split workspace stays usable at ${width}px and double zoom`, async ({ page }) => {
  await page.setViewportSize({ width, height: 1000 }); await page.emulateMedia({ reducedMotion: 'reduce' });
  const records = [terminalRecord(1), terminalRecord(2, { node_id: 'sample-1', node_name: 'Sample machine 1' })];
  const state = await setupTerminals(page, { terminals: records });
  for (const record of records) await attach(page, state, record);
  await page.getByRole('button', { name: 'Expand workspace', exact: true }).click();
  await page.evaluate(() => { document.documentElement.style.zoom = '2'; });
  await tile(page, records[1]).getByRole('button', { name: 'Zoom tile' }).click();
  await tile(page, records[1]).getByRole('button', { name: 'Focus terminal' }).click(); await page.keyboard.type('zoomed');
  await expect(tile(page, records[1]).locator('.xterm-rows')).toContainText('zoomed');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await tile(page, records[1]).getByRole('button', { name: 'Restore tiles' }).click();
  expect(state.tickets).toHaveLength(2); await capture(page, `terminal-split-zoom-${width}`);
});

test('machine tabs support arrow, Home and End without sending terminal input', async ({ page }) => {
  const records = [terminalRecord(1), terminalRecord(2), terminalRecord(3)], state = await setupTerminals(page, { terminals: records });
  for (const record of records) await attach(page, state, record);
  await page.getByRole('tab', { name: 'Sample machine 3', exact: true }).focus();
  await page.keyboard.press('Home'); await expect(page.getByRole('tab', { name: 'Sample machine 1', exact: true })).toBeFocused();
  await page.keyboard.press('ArrowRight'); await expect(tile(page, records[1])).toBeVisible();
  await page.keyboard.press('End'); await expect(page.getByRole('tab', { name: 'Sample machine 3', exact: true })).toBeFocused();
  expect(state.connections.every(item => inputs(item) === '')).toBe(true);
});

for (const count of [1, 64]) test(`distinct terminal routing across ${count} machines within one attached pane`, async ({ page }) => {
  test.setTimeout(120000);
  const records = Array.from({ length: count }, (_, index) => terminalRecord(index + 1));
  const state = await setupTerminals(page, { terminals: records, nodes: records.map((_, index) => node(index + 1)) });
  for (const [index, record] of records.entries()) {
    await attach(page, state, record); await page.keyboard.type(`route-${index + 1}`);
    await expect(tile(page, record).locator('.xterm-rows')).toContainText(`route-${index + 1}`);
    expect(inputs(state.connections[index])).toBe(`route-${index + 1}`);
    await tile(page, record).getByRole('button', { name: 'Close pane' }).click();
    await expect.poll(() => state.connections[index].closed).toBe(true);
    expect(state.connections.filter(item => !item.closed)).toHaveLength(0);
  }
  expect(new Set(state.connections.map(item => item.id)).size).toBe(count);
  expect(state.tickets).toHaveLength(count);
});
