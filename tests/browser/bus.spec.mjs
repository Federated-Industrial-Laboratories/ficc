// SPDX-License-Identifier: Apache-2.0
// Check recipient routing, uncertain retries and literal bus display.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { agent, setupAgents } from './agent-support.mjs';
import { capture } from './support.mjs';

for (const count of [1, 64]) test(`bus routes only selected run recipients at N=${count}`, async ({ page }) => {
  const records = Array.from({ length: count }, (_, i) => agent(i + 1));
  records.push(agent(100, { run_id: 'another-run' }));
  const state = await setupAgents(page, { view: 'bus', agents: records });
  await page.getByRole('button', { name: 'Send message', exact: true }).click();
  await expect(page.getByRole('checkbox', { name: 'Agent 100 / Machine 100', exact: true })).toHaveCount(0);
  for (let i = 1; i <= count; i++) await page.getByRole('checkbox', { name: `Agent ${i} / Machine ${i}`, exact: true }).check();
  await page.getByLabel('Message body', { exact: true }).fill('Inspect the selected workspace.');
  await page.getByLabel('Send this exact text', { exact: false }).check();
  await page.getByRole('button', { name: 'Send exact message' }).click();
  await expect.poll(() => state.sends.length).toBe(1);
  expect(state.sends[0].body.recipient_ids).toEqual(records.slice(0, count).map(a => a.id));
  expect(state.sends[0].path).toBe('/api/v1/bus/runs/run-1/messages');
  expect(state.sends[0].body.delivery).toBe('inbox');
});

test('direct message retry preserves exact body, recipients and identity', async ({ page }) => {
  const state = await setupAgents(page, { view: 'bus', dropMessage: true });
  await page.getByRole('button', { name: 'Send message', exact: true }).click();
  await page.getByRole('checkbox', { name: 'Agent 1 / Machine 1', exact: true }).check();
  await page.getByLabel('Delivery method', { exact: true }).selectOption('direct');
  await page.getByLabel('Message body', { exact: true }).fill('Literal $(false) <script>text</script>');
  await page.getByLabel('Send this exact text', { exact: false }).check();
  await page.getByRole('button', { name: 'Send exact message' }).click();
  await expect(page.getByLabel('Message body', { exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Retry same message' }).click();
  await expect.poll(() => state.sends.length).toBe(2);
  expect(state.sends[0]).toEqual(state.sends[1]); expect(state.sends[0].body.idempotency_key).toBeTruthy();
  expect(state.sends[0].body.confirm_delivery).toBe(true); expect(state.sends[0].body.delivery).toBe('direct');
});

test('message requires recipients and limits UTF-8 bytes before submission', async ({ page }) => {
  const state = await setupAgents(page, { view: 'bus' });
  await page.getByRole('button', { name: 'Send message', exact: true }).click();
  await page.getByLabel('Message body', { exact: true }).fill('test');
  await page.getByLabel('Send this exact text', { exact: false }).check();
  await page.getByRole('button', { name: 'Send exact message' }).click();
  await expect(page.getByText('Select at least one exact recipient.')).toBeVisible();
  await page.getByRole('checkbox', { name: 'Agent 1 / Machine 1', exact: true }).check();
  await page.getByLabel('Message body', { exact: true }).fill('界'.repeat(2800));
  await page.getByRole('button', { name: 'Send exact message' }).click();
  await expect(page.getByText('The message body exceeds 8192 UTF-8 bytes.')).toBeVisible(); expect(state.sends).toHaveLength(0);
});

test('bus renders literal message text and separates uncertain delivery from completion', async ({ page }) => {
  const hostile = '<img src=x onerror="window.busExecuted=true">';
  await setupAgents(page, { view: 'bus', messages: [{ id: 'message-1', ordinal: 1, type: 'note', body: { text: hostile },
    sender_id: 'agent-1', sequence: 1, recipient_ids: ['agent-2'], created_at: 1000, reply_to: null }],
    deliveries: [{ id: 'delivery-1', message_id: 'message-1', agent_id: 'agent-2', state: 'uncertain', method: 'direct', detail: 'Submission receipt lost.', updated_at: 1000 }] });
  await expect(page.locator('.bus-message-body')).toHaveText(hostile);
  expect(await page.evaluate(() => window.busExecuted)).toBeUndefined();
  await expect(page.getByText('Outcome is unknown. Do not blindly resend.')).toBeVisible();
  await expect(page.getByText('A receipt confirms a delivery stage.', { exact: false })).toBeVisible();
  await capture(page, 'bus-receipts');
});

test('run creation retries with the same idempotency key', async ({ page }) => {
  const state = await setupAgents(page, { view: 'bus', dropRun: true });
  await page.getByRole('button', { name: 'Create run', exact: true }).click();
  await page.getByLabel('Run name', { exact: true }).fill('review-run');
  await page.getByRole('button', { name: 'Create run', exact: true }).last().click();
  await page.getByRole('button', { name: 'Retry same run' }).click();
  await expect.poll(() => state.creations.length).toBe(2); expect(state.creations[0]).toEqual(state.creations[1]);
  await expect(page.getByRole('heading', { name: 'Run: review-run', exact: true })).toBeVisible();
});

for (const [stage, explanation] of [
  ['host-stored', 'Recorded by the controller.'], ['node-stored', 'Stored in the node inbox.'],
  ['adapter-submitted', 'Accepted by the adapter; inclusion is not confirmed.'],
  ['session-included', 'Observed in the bound runtime session.'], ['tool-read', 'Read through the inbox tool.'],
]) test(`receipt describes the ${stage} boundary`, async ({ page }) => {
  await setupAgents(page, { view: 'bus', deliveries: [{ id: 'delivery-1', message_id: 'message-1', agent_id: 'agent-1',
    state: stage, method: 'inbox', detail: null, updated_at: 1000 }] });
  await expect(page.getByText(explanation, { exact: true })).toBeVisible();
});

test('message pagination and run changes use separate opaque run IDs', async ({ page }) => {
  const runs = [1, 2].map(i => ({ id: `run-${i}`, name: `Run ${i}`, state: 'open', agent_ids: [], message_count: 200, created_at: 1000 }));
  const state = await setupAgents(page, { view: 'bus', runs, paged: true });
  await page.getByRole('button', { name: 'Next messages' }).click();
  await expect.poll(() => state.lists.at(-1)).toBe('/api/v1/bus/runs/run-1/messages?after=100&limit=100');
  await page.getByRole('button', { name: 'Run 2', exact: true }).click();
  await expect.poll(() => state.lists.at(-1)).toBe('/api/v1/bus/runs/run-2/messages?after=0&limit=100');
  await expect(page.getByRole('button', { name: 'Previous messages' })).toBeDisabled();
});

test('read-only bus exposes no send or close controls and revoked data clears', async ({ page }) => {
  const state = await setupAgents(page, { view: 'bus', scopes: ['bus:read'] });
  await expect(page.getByRole('button', { name: 'Send message', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Close run', exact: true })).toHaveCount(0);
  state.denied = true; await page.getByRole('button', { name: 'Refresh bus' }).click();
  await expect(page.getByRole('button', { name: 'Sample run', exact: true })).toHaveCount(0);
});

test('closing a run requires explicit confirmation and addresses that run alone', async ({ page }) => {
  const state = await setupAgents(page, { view: 'bus' });
  await page.getByRole('button', { name: 'Close run', exact: true }).click(); expect(state.closes).toHaveLength(0);
  await page.getByRole('button', { name: 'Close exact run' }).click(); await expect.poll(() => state.closes.length).toBe(1);
  expect(state.closes[0]).toEqual({ path: '/api/v1/bus/runs/run-1/close', body: { confirm_close: true } });
});
