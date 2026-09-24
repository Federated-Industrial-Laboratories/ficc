// SPDX-License-Identifier: Apache-2.0
// Check exact agent launch previews, authority controls and terminal selection.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { agent, agentScopes, setupAgents } from './agent-support.mjs';
import { capture } from './support.mjs';

for (const count of [1, 64]) test(`agent controls retain exact identity at N=${count}`, async ({ page }) => {
  const records = Array.from({ length: count }, (_, i) => agent(i + 1));
  const state = await setupAgents(page, { agents: records });
  await page.getByRole('button', { name: `Agent ${count}`, exact: true }).click();
  await expect(page.getByText(`session-${count}`, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Reconcile agent' }).click();
  await expect.poll(() => state.controls.length).toBe(1);
  expect(state.controls[0]).toEqual({ path: `/api/v1/agents/agent-${count}/reconcile`, body: {} });
  await page.getByRole('button', { name: 'Stop agent', exact: true }).click();
  expect(state.controls).toHaveLength(1);
  await page.getByRole('button', { name: 'Stop exact agent' }).click();
  await expect.poll(() => state.controls.length).toBe(2);
  expect(state.controls[1]).toEqual({ path: `/api/v1/agents/agent-${count}/stop`, body: { confirm_stop: true } });
});

test('launch uses exact preview and same creation key after a lost response', async ({ page }) => {
  const state = await setupAgents(page, { agents: [agent(1), agent(2)], dropLaunch: true });
  await page.getByRole('button', { name: 'Launch agent', exact: true }).click();
  await page.getByLabel('Registered agent profile').selectOption('profile-2');
  await page.getByLabel('Agent label', { exact: true }).fill('Review workspace');
  await page.getByRole('button', { name: 'Preview agent' }).click();
  await expect(page.getByText('/work/project-2', { exact: true }).last()).toBeVisible();
  expect(state.launches).toHaveLength(0);
  expect(state.previews[0]).toEqual({ profile_id: 'profile-2', label: 'Review workspace', run_id: 'run-1', cols: 100, rows: 30 });
  await page.getByLabel('Launch this exact command', { exact: false }).check();
  await page.getByRole('button', { name: 'Confirm and launch agent' }).click();
  await page.getByRole('button', { name: 'Retry same agent' }).click();
  await expect.poll(() => state.launches.length).toBe(2);
  expect(state.launches[0]).toEqual(state.launches[1]);
  expect(state.launches[0].idempotency_key).toBeTruthy();
  expect(state.launches[0].preview_id).toBe('frozen-preview');
});

test('opening an agent terminal is explicit and selects its exact identity', async ({ page }) => {
  await setupAgents(page, { agents: [agent(1), agent(2)] });
  await page.evaluate(() => { window.opened = []; window.addEventListener('ficc-open-terminal', e => window.opened.push(e.detail.terminalId)); });
  await page.getByRole('button', { name: 'Agent 2', exact: true }).click();
  expect(await page.evaluate(() => window.opened)).toEqual([]);
  await page.getByRole('button', { name: 'Open terminal', exact: true }).click();
  expect(await page.evaluate(() => window.opened)).toEqual(['terminal-2']);
  await expect(page.locator('[data-view=terminals]')).toHaveAttribute('aria-current', 'page');
});

test('read-only and demo sessions cannot launch or stop agents', async ({ page }) => {
  await setupAgents(page, { scopes: ['agents:read'] });
  await expect(page.getByRole('button', { name: 'Launch agent', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Stop agent', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Open terminal', exact: true })).toHaveCount(0);
  await setupAgents(page, { mode: 'demo' });
  await expect(page.getByRole('button', { name: 'Launch agent', exact: true })).toHaveCount(0);
});

test('agent permission loss clears retained workspace and runtime identities', async ({ page }) => {
  const state = await setupAgents(page);
  await expect(page.getByText('session-1', { exact: true })).toBeVisible();
  state.denied = true; await page.getByRole('button', { name: 'Refresh agents' }).click();
  await expect(page.getByText('session-1', { exact: true })).toHaveCount(0);
  await expect(page.getByText('/work/project-1', { exact: true })).toHaveCount(0);
});

test('missing agent read scope makes no agent inventory request', async ({ page }) => {
  let reads = 0; page.on('request', req => { if (new URL(req.url()).pathname === '/api/v1/agents') reads++; });
  await setupAgents(page, { scopes: agentScopes.filter(scope => scope !== 'agents:read') });
  await expect(page.getByRole('heading', { name: 'Agent access denied' })).toBeVisible(); expect(reads).toBe(0);
});

test('launch control requires bus send authority for run enrollment', async ({ page }) => {
  await setupAgents(page, { scopes: agentScopes.filter(scope => scope !== 'bus:send') });
  await expect(page.getByRole('button', { name: 'Launch agent', exact: true })).toHaveCount(0);
});

for (const adapter of ['omp', 'codex']) test(`${adapter} rebind requires exact runtime identity and confirmation`, async ({ page }) => {
  const state = await setupAgents(page, { agents: [agent(1, { adapter, state: 'suspended' })] });
  await page.getByRole('button', { name: 'Bind runtime session' }).click();
  await page.getByLabel('Exact runtime session ID').fill('session-distinct');
  await page.getByLabel('Permit direct delivery', { exact: false }).check();
  await page.getByRole('button', { name: 'Bind exact session' }).click();
  await expect.poll(() => state.controls.length).toBe(1);
  expect(state.controls[0]).toEqual({ path: '/api/v1/agents/agent-1/rebind', body: { runtime_session_id: 'session-distinct', confirm_rebind: true } });
});

test('unregistered profiles give an actionable setup state without launch', async ({ page }) => {
  const state = await setupAgents(page, { noProfiles: true });
  await page.getByRole('button', { name: 'Launch agent', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Agent setup required' })).toBeVisible();
  expect(state.previews).toHaveLength(0); expect(state.launches).toHaveLength(0);
});

test('agent page retains controls at narrow width and double zoom', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 }); await setupAgents(page);
  await page.evaluate(() => { document.documentElement.style.zoom = '2'; });
  await page.getByRole('button', { name: 'Agent 1', exact: true }).click();
  await page.getByRole('button', { name: 'Reconcile agent' }).focus();
  await expect(page.getByRole('button', { name: 'Reconcile agent' })).toBeFocused();
  await capture(page, 'agents-390-zoom');
});

for (const count of [1, 64]) test(`rejected replies retain exact agent identity and literal refusal at N=${count}`, async ({ page }) => {
  const records = Array.from({ length: count }, (_, index) => agent(index + 1, {
    outbox_rejections: [{ id: `refused-${index + 1}`, code: 'invalid_message',
      detail: `<img src=x onerror=alert(1)> Invalid reply ${index + 1}`, rejected_at: 1800000000 + index }],
  }));
  await setupAgents(page, { agents: records });
  await page.getByRole('button', { name: `Agent ${count}`, exact: true }).click();
  const refusals = page.getByRole('table', { name: 'Rejected replies', exact: true });
  await expect(refusals.getByRole('row')).toHaveCount(2);
  await expect(refusals.getByText(`refused-${count}`, { exact: true })).toBeVisible();
  await expect(refusals.getByText(`<img src=x onerror=alert(1)> Invalid reply ${count}`, { exact: true })).toBeVisible();
  await expect(refusals.locator('img')).toHaveCount(0);
  await expect(page.getByText('These replies were refused by the controller.', { exact: false })).toBeVisible();
  if (count > 1) await expect(refusals.getByText('refused-1', { exact: true })).toHaveCount(0);
});
