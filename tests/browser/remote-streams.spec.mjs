// SPDX-License-Identifier: Apache-2.0
// Exercise the real HTTPS identity, observation, file, workspace and terminal paths.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

test.afterEach(async ({ page }, info) => {
  if (info.status !== info.expectedStatus) {
    writeFileSync(`${process.env.FICC_STREAM_DIRECTORY}/browser-failure.txt`, await page.locator('body').ariaSnapshot());
    await page.screenshot({ path: `${process.env.FICC_STREAM_DIRECTORY}/browser-failure.png` });
  }
});

test('remote project browser keeps data and closes revoked streams', async ({ page, context }) => {
  const seed = JSON.parse(readFileSync(process.env.FICC_STREAM_SEED, 'utf8'));
  const faults = [], polls = [], streams = [];
  page.on('pageerror', error => faults.push(error.message));
  page.on('dialog', dialog => dialog.accept());
  page.on('response', response => {
    if (new URL(response.url()).pathname === '/api/v1/nodes' && response.status() === 200) polls.push(Date.now());
  });
  page.on('websocket', socket => streams.push(socket));
  await page.goto(process.env.FICC_URL);
  await page.getByRole('button', { name: 'Sign in with organisation account', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Cluster overview', exact: true })).toBeVisible();
  const session = await page.evaluate(async () => (await fetch('/api/v1/session')).json());
  expect(session.remote).toBe(true);
  expect(session.principal.local_owner).toBe(false);
  expect(session.principal.subject_id).toBe(seed.subject);
  const cookies = await context.cookies();
  expect(cookies.some(value => value.secure && value.httpOnly && value.sameSite === 'Strict')).toBe(true);
  await expect(page.getByRole('table', { name: 'Enrolled machines', exact: true })).toContainText('Remote stream node');
  await expect.poll(() => polls.length, { timeout: 16000 }).toBeGreaterThanOrEqual(3);
  expect(polls.at(-1) - polls[0]).toBeGreaterThan(9000);
  const downloadPromise = page.waitForEvent('download');
  await page.evaluate(path => {
    const anchor = document.createElement('a'); anchor.href = path; anchor.download = 'browser.bin';
    document.body.append(anchor); anchor.click(); anchor.remove();
  }, seed.download);
  const download = await downloadPromise;
  expect(await download.failure()).toBeNull();
  const bytes = readFileSync(await download.path());
  expect(bytes.length).toBe(seed.size);
  expect(createHash('sha256').update(bytes).digest('hex')).toBe(seed.sha256);
  await page.locator('[data-view=workspaces]').click();
  await page.getByLabel('Saved workspace').selectOption(seed.workspace);
  await page.getByRole('button', { name: 'Open', exact: true }).click();
  const panel = page.getByRole('tabpanel', { name: 'Remote notes', exact: true });
  const notes = panel.getByLabel('Workspace notes', { exact: true });
  await notes.fill('Remote operations: retain this text across TLS sessions.');
  await panel.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(panel.locator('.module-editor-panel [role=status]')).toHaveText('Saved');
  await panel.getByRole('button', { name: 'Float', exact: true }).click();
  await page.getByRole('button', { name: 'Fullscreen', exact: true }).click();
  await expect.poll(() => page.evaluate(() => Boolean(document.fullscreenElement))).toBe(true);
  await panel.getByRole('button', { name: 'Expand', exact: true }).click();
  await panel.getByRole('button', { name: 'Restore panel', exact: true }).click();
  await page.getByRole('button', { name: 'Exit fullscreen', exact: true }).click();
  await page.setViewportSize({ width: 760, height: 620 });
  await page.getByRole('button', { name: 'Recover panels', exact: true }).click();
  await expect(notes).toBeVisible();
  await panel.getByRole('button', { name: 'Dock', exact: true }).click();
  await page.reload();
  await expect(notes).toHaveValue('Remote operations: retain this text across TLS sessions.');
  await page.screenshot({ path: `${process.env.FICC_STREAM_DIRECTORY}/browser-workspace.png` });
  await page.setViewportSize({ width: 1280, height: 1000 });
  if (seed.vm_workspace) {
    await page.getByLabel('Saved workspace').selectOption(seed.vm_workspace);
    await page.getByRole('button', { name: 'Open', exact: true }).click();
    await page.getByLabel('Installed module', { exact: true }).selectOption({ label: 'Libvirt VMs' });
    await page.getByRole('button', { name: 'Add module', exact: true }).click();
    const targets = page.getByRole('dialog', { name: 'Module targets', exact: true });
    await targets.getByRole('checkbox', { name: /Remote stream node/ }).check();
    await targets.getByRole('button', { name: 'Use selected targets', exact: true }).click();
    const virtual = page.getByRole('tabpanel', { name: 'Libvirt VMs', exact: true });
    await virtual.getByRole('button', { name: 'Read VM inventory', exact: true }).click();
    const row = virtual.getByRole('row').filter({ hasText: 'ficc-remote-display' });
    await expect(row).toBeVisible();
    await row.getByRole('checkbox').check();
    await virtual.getByRole('button', { name: 'Open selected console', exact: true }).click();
    await virtual.getByRole('button', { name: 'Open display in FICC', exact: true }).click();
    const viewer = virtual.getByRole('region', { name: 'FICC remote display', exact: true });
    await expect(viewer.getByRole('status')).toHaveText('Connected. Input is released.');
    const pixels = () => viewer.locator('.viewer-well').evaluate(well => {
      const canvas = [...well.querySelectorAll('canvas')]
        .filter(value => value.width >= 320 && value.height >= 200)
        .sort((left, right) => right.width * right.height - left.width * left.height)[0];
      if (!canvas) return { png: '', light: 0 };
      const data = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data;
      let light = 0;
      for (let index = 0; index < data.length; index += 4) {
        if (data[index + 3] > 128 && Math.min(data[index], data[index + 1], data[index + 2]) > 128) light++;
      }
      return { png: canvas.toDataURL('image/png'), light };
    });
    await expect.poll(async () => (await pixels()).light).toBeGreaterThan(500);
    const before = await pixels();
    await viewer.getByRole('button', { name: 'Capture input', exact: true }).click();
    await page.keyboard.type('BROWSER INPUT');
    await expect.poll(async () => (await pixels()).light).toBeGreaterThan(before.light + 200);
    expect((await pixels()).png).not.toBe(before.png);
    await page.keyboard.press('Control+Alt+Shift');
    await expect(viewer).toHaveAttribute('data-input', 'released');
    writeFileSync(`${process.env.FICC_STREAM_DIRECTORY}/browser-vm-pixels.png`, Buffer.from((await pixels()).png.split(',')[1], 'base64'));
    await page.getByRole('button', { name: 'Fullscreen', exact: true }).click();
    await viewer.getByRole('button', { name: 'Fullscreen display', exact: true }).click();
    await expect.poll(() => page.evaluate(() => document.fullscreenElement?.classList.contains('viewer-panel'))).toBe(true);
    await viewer.screenshot({ path: `${process.env.FICC_STREAM_DIRECTORY}/browser-vm-frame.png` });
    await viewer.getByRole('button', { name: 'Exit display fullscreen', exact: true }).click();
    await page.getByRole('button', { name: 'Exit fullscreen', exact: true }).click();
    await viewer.getByRole('button', { name: 'Expand display', exact: true }).click();
    await page.setViewportSize({ width: 760, height: 620 });
    await viewer.getByRole('button', { name: 'Restore display', exact: true }).click();
    await expect(viewer.getByRole('button', { name: 'Capture input', exact: true })).toBeEnabled();
    await page.screenshot({ path: `${process.env.FICC_STREAM_DIRECTORY}/browser-viewer.png` });
    await viewer.getByRole('button', { name: 'Disconnect display', exact: true }).click();
    await expect(viewer.getByRole('button', { name: 'Capture input', exact: true })).toBeDisabled();
    await page.setViewportSize({ width: 1280, height: 1000 });
  }
  await page.locator('[data-view=terminals]').click();
  await page.getByRole('button', { name: 'New terminal', exact: true }).click();
  await page.getByLabel('Terminal lifetime').selectOption('ephemeral');
  await page.getByLabel('Terminal label').fill('Remote browser shell');
  await page.getByLabel('Open a shell with full authority', { exact: false }).check();
  await page.getByRole('button', { name: 'Confirm and open terminal', exact: true }).click();
  await expect(page.getByText('Attached. Input goes only', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Focus terminal', exact: true }).click();
  await page.keyboard.type("stty -echo; printf '\\120ROOF_BROWSER\\n'\n");
  await expect(page.locator('.xterm-rows')).toContainText('PROOF_BROWSER');
  await page.keyboard.press('Control+Shift+Escape');
  await expect(page.getByRole('button', { name: 'Focus terminal', exact: true })).toBeFocused();
  const terminalStream = streams.find(socket => new URL(socket.url()).pathname.includes('/terminals/'));
  expect(terminalStream).toBeDefined();
  for (const socket of streams) {
    expect(new URL(socket.url()).protocol).toBe('wss:');
    expect(new URL(socket.url()).search).toBe('');
  }
  await page.screenshot({ path: `${process.env.FICC_STREAM_DIRECTORY}/browser-terminal.png` });
  execFileSync(process.env.FICC_PYTHON, ['-m', 'remote_streams.control'], { timeout: 15000, stdio: 'pipe' });
  await expect.poll(() => terminalStream.isClosed()).toBe(true);
  await expect(page.getByRole('button', { name: 'Sign in with organisation account', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Focus terminal', exact: true })).toHaveCount(0);
  expect(await page.evaluate(async () => (await fetch('/api/v1/nodes')).status)).toBe(401);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);
  expect(faults).toEqual([]);
});
