// SPDX-License-Identifier: Apache-2.0
// Verify terminal consent, lifecycle, byte accounting and hostile output boundaries.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { attachTerminal, setupTerminals, terminalRecord, terminalScopes } from './terminal-support.mjs';
import { capture, node } from './support.mjs';

test('creation requires consent and keeps its key after a lost reply', async ({ page }) => {
  const state = await setupTerminals(page, { terminals: [], dropFirstCreate: true });
  await page.getByRole('button', { name: 'New terminal', exact: true }).click();
  await page.getByRole('button', { name: 'Confirm and open terminal' }).click();
  expect(state.creations).toHaveLength(0);
  await page.getByLabel('Open a shell with full authority', { exact: false }).check();
  await page.getByRole('button', { name: 'Confirm and open terminal' }).click();
  await expect(page.getByRole('button', { name: 'Retry same terminal' })).toBeVisible();
  await page.getByRole('button', { name: 'Retry same terminal' }).click();
  await expect(page.getByText('Attached. Input goes only', { exact: false })).toBeVisible();
  expect(state.creations).toHaveLength(2); expect(state.creations[0]).toEqual(state.creations[1]);
  expect(state.creations[0].confirm_execution).toBe(true);
});

test('ticket stays in the first frame and real UTF-8 input echoes to one target', async ({ page }) => {
  const faults = []; page.on('console', message => { if (message.type() === 'error') faults.push(message.text()); });
  const state = await setupTerminals(page); await attachTerminal(page, state);
  expect(new URL(state.sockets[0].url()).search).toBe('');
  expect(JSON.parse(state.frames[0])).toEqual({ type: 'auth', ticket: 'one-use-fixture-ticket' });
  expect(state.tickets[0]['x-csrf-token']).toBe('test-csrf');
  await page.keyboard.type('hello');
  await expect(page.locator('.xterm-rows')).toContainText('hello');
  expect(Buffer.concat(state.frames.filter(Buffer.isBuffer)).toString()).toBe('hello');
  await page.keyboard.press('Control+Shift+Escape');
  await expect(page.getByRole('button', { name: 'Focus terminal' })).toBeFocused();
  await page.keyboard.type('outside');
  expect(Buffer.concat(state.frames.filter(Buffer.isBuffer)).toString()).toBe('hello');
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  expect(faults.filter(message => /Content Security Policy|inline style/.test(message))).toEqual([]);
});

test('output ACK waits for the real parser callback and counts bytes', async ({ page }) => {
  const state = await setupTerminals(page);
  await page.evaluate(async () => {
    const { Terminal } = await import('/static/vendor/xterm/xterm.mjs');
    const original = Terminal.prototype.write;
    Terminal.prototype.write = function(data, callback) { original.call(this, data, () => setTimeout(callback, 600)); };
  });
  await attachTerminal(page, state);
  state.sockets[0].send(Buffer.from('π🙂'));
  await expect(page.locator('.xterm-rows')).toContainText('π🙂');
  expect(state.frames.filter(frame => typeof frame === 'string' && JSON.parse(frame).type === 'ack')).toHaveLength(0);
  await expect.poll(() => state.frames.filter(frame => typeof frame === 'string' && JSON.parse(frame).type === 'ack').map(JSON.parse)).toEqual([{ type: 'ack', bytes: 6 }]);
});

test('RGB output and contrast adjustment render without content-policy errors', async ({ page }) => {
  const faults = [];
  page.on('console', message => { if (message.type() === 'error') faults.push(message.text()); });
  const state = await setupTerminals(page); await attachTerminal(page, state);
  state.sockets[0].send(Buffer.from('\x1b[38;2;255;180;80mRGB FOREGROUND\x1b[0m\r\n\x1b[48;2;35;50;70mRGB BACKGROUND\x1b[0m\r\n\x1b[30mCONTRAST ADJUSTMENT\x1b[0m'));
  await expect(page.locator('.xterm-rows')).toContainText('CONTRAST ADJUSTMENT');
  await expect.poll(() => page.locator('.xterm-rows span[style]').evaluateAll(elements => {
    const spans = elements.map(element => ({ text: element.textContent, style: getComputedStyle(element) }));
    return {
      foreground: spans.filter(value => value.style.color === 'rgb(255, 180, 80)').map(value => value.text).join(''),
      background: spans.filter(value => value.style.backgroundColor === 'rgb(35, 50, 70)').map(value => value.text).join(''),
      contrast: spans.filter(value => value.style.color === 'rgb(146, 150, 150)').map(value => value.text).join(''),
    };
  })).toEqual({ foreground: 'RGB FOREGROUND', background: 'RGB BACKGROUND', contrast: 'CONTRAST ADJUSTMENT' });
  expect(faults.filter(message => /Content Security Policy|inline style/.test(message))).toEqual([]);
});

test('hostile output cannot change title, execute markup, open links or copy clipboard', async ({ page }) => {
  const state = await setupTerminals(page); await attachTerminal(page, state);
  await page.evaluate(() => { window.opened = 0; window.copied = 0; window.open = () => { window.opened++; }; navigator.clipboard.writeText = async () => { window.copied++; }; });
  state.sockets[0].send(Buffer.from('\x1b]0;ATTACK\x07\x1b]52;c;c2VjcmV0\x07\x1b]8;;javascript:alert(1)\x07LINK\x1b]8;;\x07<img src=x onerror=alert(1)>'));
  await expect(page.locator('.xterm-rows')).toContainText('<img');
  await expect(page).toHaveTitle('FICC | Cluster console');
  expect(await page.evaluate(() => [window.opened, window.copied])).toEqual([0, 0]);
  expect(await page.locator('.terminal-well img').count()).toBe(0);
});

test('disconnect disables input and reattach uses a new ticket without replay', async ({ page }) => {
  const state = await setupTerminals(page); await attachTerminal(page, state);
  await page.keyboard.type('before'); state.sockets[0].close();
  await expect(page.getByText('Connection closed.', { exact: false })).toBeVisible();
  const input = state.frames.filter(Buffer.isBuffer).length;
  await page.keyboard.type('after');
  expect(state.frames.filter(Buffer.isBuffer)).toHaveLength(input);
  await page.getByRole('button', { name: 'Reattach', exact: true }).click();
  await expect.poll(() => state.tickets.length).toBe(2);
  expect(state.frames.filter(Buffer.isBuffer)).toHaveLength(input);
});

test('tmux detach is separate from explicitly confirmed stop', async ({ page }) => {
  const state = await setupTerminals(page); await attachTerminal(page, state);
  await page.getByRole('button', { name: 'Detach', exact: true }).click();
  await expect(page.getByText('Detached. The remote tmux', { exact: false })).toBeVisible();
  expect(state.stops).toHaveLength(0);
  await page.getByRole('button', { name: 'Stop session' }).click();
  expect(state.stops).toHaveLength(0);
  await page.getByRole('button', { name: 'Confirm stop' }).click();
  await expect.poll(() => state.stops.length).toBe(1);
  expect(state.stops[0]).toEqual({ confirm_stop: true });
});

test('server denial clears terminal output and disables keyboard', async ({ page }) => {
  const state = await setupTerminals(page); await attachTerminal(page, state);
  state.sockets[0].send(Buffer.from('private sample')); await expect(page.locator('.xterm-rows')).toContainText('private sample');
  state.sockets[0].send(JSON.stringify({ type: 'status', state: 'denied', message: 'Permission revoked.' }));
  await expect(page.getByText('Permission revoked.', { exact: true })).toBeVisible();
  await expect(page.locator('.terminal-well')).not.toContainText('private sample');
  await expect(page.getByRole('button', { name: 'Focus terminal' })).toBeDisabled();
});

test('an oversized output frame produces an explicit gap and closes input', async ({ page }) => {
  const state = await setupTerminals(page); await attachTerminal(page, state);
  state.sockets[0].send(Buffer.alloc(32769, 65));
  await expect(page.getByText('Output exceeded the bounded', { exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Focus terminal' })).toBeDisabled();
  expect(state.frames.filter(frame => typeof frame === 'string' && JSON.parse(frame).type === 'ack')).toHaveLength(0);
});

test('large paste is refused as one action without partial input', async ({ page }) => {
  const state = await setupTerminals(page); await attachTerminal(page, state);
  await page.locator('.xterm-helper-textarea').evaluate(element => {
    const transfer = new DataTransfer(); transfer.setData('text/plain', 'a'.repeat(17000));
    element.dispatchEvent(new ClipboardEvent('paste', { clipboardData: transfer, bubbles: true, cancelable: true }));
  });
  await expect(page.getByText('Input was refused:', { exact: false })).toBeVisible();
  expect(state.frames.filter(Buffer.isBuffer)).toHaveLength(0);
});

test('simulation and missing execution grant do not expose live controls', async ({ page }) => {
  await setupTerminals(page, { mode: 'demo' });
  await expect(page.getByRole('button', { name: 'New terminal' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Reattach', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Stop session' })).toHaveCount(0);
});

test('terminals without read permission show an explicit denial', async ({ page }) => {
  await setupTerminals(page, { scopes: terminalScopes.filter(scope => scope !== 'terminals:read') });
  await expect(page.getByRole('heading', { name: 'Terminal access denied' })).toBeVisible();
});

test('detached ephemeral sessions cannot be recreated by reattach', async ({ page }) => {
  await setupTerminals(page, { terminals: [terminalRecord(1, { mode: 'ephemeral' })] });
  await expect(page.getByRole('button', { name: 'Reattach', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Attach', exact: true })).toHaveCount(0);
});

test('unknown tmux checks its saved session without creating or attaching a shell', async ({ page }) => {
  const record = terminalRecord(1, { state: 'unknown' });
  const state = await setupTerminals(page, { terminals: [record] });
  await expect(page.getByRole('button', { name: 'Reattach', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Check recorded session', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Reattach', exact: true })).toBeVisible();
  expect(state.reconciliations).toHaveLength(1);
  expect(new URL(state.reconciliations[0].url).pathname).toBe(`/api/v1/terminals/${record.id}/reconcile`);
  expect(state.reconciliations[0].body).toEqual({});
  expect(state.reconciliations[0].headers['x-csrf-token']).toBe('test-csrf');
  expect(state.creations).toHaveLength(0); expect(state.tickets).toHaveLength(0); expect(state.sockets).toHaveLength(0);
});

test('saved-session checks require execute authority and apply only to tmux', async ({ page }) => {
  await setupTerminals(page, { scopes: terminalScopes.filter(scope => scope !== 'terminals:execute'), terminals: [terminalRecord(1, { state: 'unknown' })] });
  await expect(page.getByRole('table', { name: 'Terminal sessions', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Check recorded session', exact: true })).toHaveCount(0);
});

test('unknown ephemeral sessions have no saved-session creation shortcut', async ({ page }) => {
  await setupTerminals(page, { terminals: [terminalRecord(1, { mode: 'ephemeral', state: 'unknown' })] });
  await expect(page.getByRole('table', { name: 'Terminal sessions', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Check recorded session', exact: true })).toHaveCount(0);
});

test('switching sessions closes the old keyboard target', async ({ page }) => {
  const state = await setupTerminals(page, { terminals: [terminalRecord(1), terminalRecord(2)] });
  await attachTerminal(page, state); await page.keyboard.type('first');
  await page.getByRole('button', { name: 'Reattach', exact: true }).click();
  await expect.poll(() => state.sockets.length).toBe(2);
  await expect(page.locator('.terminal-identity')).toContainText('Sample machine 2 / operator');
  await expect(page.locator('.xterm-helper-textarea')).toHaveCount(1);
});

test('pending output is bounded even when parser acknowledgements stall', async ({ page }) => {
  const state = await setupTerminals(page);
  await page.evaluate(async () => {
    const { Terminal } = await import('/static/vendor/xterm/xterm.mjs');
    const original = Terminal.prototype.write;
    Terminal.prototype.write = function(data) { original.call(this, data); };
  });
  await attachTerminal(page, state);
  for (let i = 0; i < 9; i++) state.sockets[0].send(Buffer.alloc(32768, 65));
  await expect(page.getByText('Output exceeded the bounded', { exact: false })).toBeVisible();
  expect(state.frames.filter(frame => typeof frame === 'string' && JSON.parse(frame).type === 'ack')).toHaveLength(0);
});

test('two hundred percent terminal layout keeps input and identity accessible', async ({ page }) => {
  const state = await setupTerminals(page); await page.evaluate(() => { document.documentElement.style.zoom = '2'; });
  await attachTerminal(page, state); await page.keyboard.type('zoom');
  await expect(page.locator('.xterm-rows')).toContainText('zoom');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

for (const count of [1, 64]) test(`terminal selection remains singular with ${count} machines`, async ({ page }) => {
  const state = await setupTerminals(page, { nodes: Array.from({ length: count }, (_, i) => node(i + 1, { capabilities: { terminals_ephemeral: true } })), terminals: [] });
  await page.getByRole('button', { name: 'New terminal', exact: true }).click();
  await page.getByLabel('Terminal machine and account').selectOption(`sample-${count}`);
  await expect(page.getByLabel('Terminal lifetime').locator('option')).toHaveCount(1);
  await page.getByLabel('Open a shell with full authority', { exact: false }).check();
  await page.getByRole('button', { name: 'Confirm and open terminal' }).click();
  await expect.poll(() => state.creations.length).toBe(1); expect(state.creations[0].node_id).toBe(`sample-${count}`);
});

for (const width of [390, 768, 1280, 1920]) test(`terminal resizes and preserves identity at ${width}px`, async ({ page }) => {
  await page.setViewportSize({ width, height: 1080 }); await page.emulateMedia({ reducedMotion: 'reduce' });
  const state = await setupTerminals(page, { terminals: [terminalRecord(1)] }); await attachTerminal(page, state);
  await expect(page.locator('.terminal-identity')).toContainText('Sample machine 1 / operator');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await expect.poll(() => state.frames.filter(frame => typeof frame === 'string' && JSON.parse(frame).type === 'resize').length).toBeGreaterThan(0);
  for (const frame of state.frames.filter(frame => typeof frame === 'string').map(JSON.parse).filter(item => item.type === 'resize')) {
    expect(frame.cols).toBeGreaterThanOrEqual(2); expect(frame.cols).toBeLessThanOrEqual(300);
    expect(frame.rows).toBeGreaterThanOrEqual(2); expect(frame.rows).toBeLessThanOrEqual(120);
  }
  await capture(page, `terminal-${width}`);
});
