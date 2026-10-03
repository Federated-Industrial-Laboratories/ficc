// SPDX-License-Identifier: Apache-2.0
// Start a private actual-API fixture with explicitly synthetic executor receipts.
import { spawn } from 'node:child_process';
import { chmod, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:net';
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';

export async function fixture(page, count = 1) {
  const python = process.env.FICC_WORKLOAD_PYTHON;
  test.skip(!python || !process.env.FICC_TEST_OPA,
    'Requires an explicit FICC_WORKLOAD_PYTHON and qualified FICC_TEST_OPA evaluator.');
  const root = resolve(new URL('../../', import.meta.url).pathname);
  const directory = await mkdtemp(join(tmpdir(), 'ficc-workload-browser-'));
  const reservation = createServer();
  await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const child = spawn(python, [join(root, 'tests/integration/workload_browser.py'), '--directory', directory, '--count', String(count), '--port', String(port)],
    { env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', data => { output += data; }); child.stderr.on('data', data => { output += data; });
  async function close() {
    if (child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise(resolve => {
        const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
        child.once('exit', () => { clearTimeout(timer); resolve(); });
      });
    }
    // Installed module directories are read-only until their private fixture is removed.
    async function writable(path) {
      await chmod(path, 0o700);
      for (const entry of await readdir(path, { withFileTypes: true })) {
        if (entry.isDirectory()) await writable(join(path, entry.name));
      }
    }
    await writable(directory);
    await rm(directory, { recursive: true, force: true });
  }
  try {
    let metadata;
    await expect.poll(async () => {
      if (child.exitCode !== null) throw new Error(`The synthetic executor fixture stopped: ${output}`);
      try {
        metadata = JSON.parse(await readFile(join(directory, 'ready.json'), 'utf8'));
        return (await fetch(metadata.origin)).ok;
      } catch { return false; }
    }, { timeout: 60000, intervals: [100, 250, 500] }).toBe(true);
    const faults = [];
    page.on('pageerror', error => faults.push(error.message));
    await page.goto(metadata.origin);
    await page.evaluate(secret => history.replaceState(null, '', `/#bootstrap=${encodeURIComponent(secret)}`), metadata.bootstrap);
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Cluster overview', exact: true })).toBeVisible();
    await page.locator('[data-view=workloads]').click();
    await expect(page.getByRole('table', { name: 'Project workloads', exact: true }).locator('tbody tr')).toHaveCount(count);
    await expect(page.getByRole('table', { name: 'Contributor workload offers', exact: true }).locator('tbody tr')).toHaveCount(count);
    delete metadata.bootstrap;
    return { ...metadata, close, faults };
  } catch (error) { await close(); throw error; }
}

export async function selectWorkload(page, name) {
  await page.getByRole('table', { name: 'Project workloads', exact: true }).getByRole('button', { name, exact: true }).click();
}
