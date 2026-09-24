// SPDX-License-Identifier: Apache-2.0
// Obtain local credentials privately and supply synthetic UI boundary data.
import { execFileSync } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { expect } from '../../web/node_modules/@playwright/test/index.mjs';

export const origin = process.env.FICC_URL || 'http://127.0.0.1:8171';
export const stateDir = process.env.FICC_STATE_DIR;
export function cli(args) {
  if (!stateDir) throw new Error('Set FICC_STATE_DIR to the isolated service state directory.');
  try {
    return execFileSync(process.env.FICC_CLI || 'ficc', [...args, '--state-dir', stateDir],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000 }).trim();
  } catch { throw new Error('The local credential command failed.'); }
}
export async function login(page) {
  const url = new URL(cli(['open', '--print-url']));
  if (url.origin !== origin) throw new Error('The isolated service URL does not match FICC_URL.');
  await page.goto(origin);
  await page.evaluate(fragment => {
    history.replaceState(null, '', `/${fragment}`);
    location.reload();
  }, url.hash);
  await expect(page.getByRole('heading', { name: 'Cluster overview', exact: true })).toBeVisible();
  await expect(page).toHaveURL(`${origin}/`);
}
export async function capture(page, name) {
  if (!process.env.FICC_CAPTURE_DIR) return;
  const folder = resolve(process.env.FICC_CAPTURE_DIR);
  const repository = resolve(new URL('../../', import.meta.url).pathname);
  if (folder === repository || folder.startsWith(`${repository}/`)) throw new Error('Captures must be outside the source repository.');
  await mkdir(folder, { recursive: true });
  await page.screenshot({ path: join(folder, `${name}.png`), fullPage: true });
}
export function node(index = 1, extra = {}) {
  return {
    id: `sample-${index}`, name: `Sample machine ${index}`, profile: `sample-${index}`,
    host: `node-${index}.example`, account: 'operator', fingerprint: 'SHA256:SyntheticFingerprint1234567890',
    state: 'ready', last_seen: Date.now() / 1000, sample_age_seconds: 0, stale: false,
    capabilities: { resources: true, gpu: false }, error: null,
    resources: {
      cpu_percent: 24.5, cpu_count: 8, load: [1.25, 1.0, 0.75],
      memory_total_bytes: 17179869184, memory_available_bytes: 12884901888, uptime_seconds: 7200,
      storage: [{ mount: '/', total_bytes: 1099511627776, available_bytes: 549755813888 }],
      network: [{ name: 'eth0', rx_bytes: 12345678, tx_bytes: 23456789 }], gpus: [], gpu_status: 'unsupported',
    }, ...extra,
  };
}
export async function mockNodes(page, nodes) {
  await page.route('**/api/v1/nodes', route => route.fulfill({ json: { nodes } }));
}
export async function mockLiveSession(page) {
  await page.route('**/api/v1/session', async route => {
    const response = await route.fetch();
    const value = await response.json();
    await route.fulfill({ response, json: { ...value, mode: 'live' } });
  });
}
