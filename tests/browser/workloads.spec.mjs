// SPDX-License-Identifier: Apache-2.0
// Exercise the actual project API and explicit synthetic executor boundaries.
import { readFile } from 'node:fs/promises';
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture } from './support.mjs';
import { fixture, selectWorkload } from './workload-support.mjs';

test.setTimeout(90000);
let current;
test.afterEach(async () => { if (current) { await current.close(); current = null; } });

test('publish complete retained output and select its dataset for another workload', async ({ page }) => {
  current = await fixture(page);
  await selectWorkload(page, 'Retained computation 01');
  await page.getByLabel('Output object', { exact: true }).selectOption('output:result');
  await page.getByRole('button', { name: 'Publish complete output', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByLabel('Destination location', { exact: true })).toContainText('Published workload outputs');
  await expect(dialog.getByText('Destination folder: Published workload outputs', { exact: true })).toBeVisible();
  await dialog.getByLabel('Destination filename', { exact: true }).fill('result.bin');
  await dialog.getByLabel('Register the verified result as a dataset', { exact: true }).check();
  await dialog.getByLabel('Dataset name', { exact: true }).fill('Published calculation');
  await dialog.getByRole('button', { name: 'Publish complete output', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  const publications = page.getByRole('table', { name: 'Workload publications', exact: true });
  await expect(publications).toContainText('result.bin');
  await expect(publications).toContainText('succeeded', { timeout: 20000 });
  await expect(publications.getByRole('button', { name: 'View dataset manifest', exact: true })).toBeVisible();
  await publications.getByRole('button', { name: 'View dataset manifest', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('Published calculation');
  await expect(page.getByRole('dialog')).toContainText('"kind": "workload"');
  await expect(page.getByRole('dialog')).toContainText('"object": "output:result"');
  await page.getByRole('dialog').getByRole('button', { name: 'Close', exact: true }).click();
  await page.getByRole('button', { name: 'Release retained output', exact: true }).click();
  await page.getByRole('button', { name: 'Delete output and release', exact: true }).click();
  await expect(page.getByText('Retained output was released and is no longer available.', { exact: true })).toBeVisible();
  await expect(publications).toContainText('result.bin');
  await expect(page.getByRole('button', { name: 'Publish complete output', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'New workload', exact: true }).click();
  await dialog.getByLabel('Workload name', { exact: true }).fill('Use the published result');
  await dialog.getByRole('button', { name: 'Select all candidates', exact: true }).click();
  await dialog.getByRole('button', { name: 'Browse datasets', exact: true }).click();
  await expect(dialog.getByLabel('Input dataset', { exact: true })).toContainText('Published calculation');
  await dialog.getByLabel('Input dataset', { exact: true }).selectOption({ label: 'Published calculation / 1 files' });
  await expect(dialog.getByText('/inputs/result.bin', { exact: true })).toBeVisible();
  await expect(dialog.getByLabel('Input references (JSON)', { exact: true })).toBeDisabled();
  const submitted = page.waitForResponse(value => value.url().endsWith('/workloads') && value.request().method() === 'POST');
  await dialog.getByRole('button', { name: 'Submit workload', exact: true }).click();
  const response = await submitted;
  const selection = response.request().postDataJSON().requests[0].request.dataset;
  expect(selection.manifest_digest).toMatch(/^[0-9a-f]{64}$/);
  const accepted = (await response.json()).results[0];
  expect(accepted.ok).toBe(true);
  expect(accepted.workload.request.dataset).toEqual(selection);
  expect(accepted.workload.request.job.inputs[0]).toMatchObject({ name: 'result.bin', delivery: 'stream' });
  await expect(dialog).toHaveCount(0);
  expect(current.faults).toEqual([]);
});

for (const count of [1, 64]) {
  test(`actual API: ${count} distinct offers and retained workloads, release, retry and submission`, async ({ page }) => {
    current = await fixture(page, count);
    expect(new Set(current.nodes).size).toBe(count); expect(new Set(current.jobs).size).toBe(count);
    const offers = page.getByRole('table', { name: 'Contributor workload offers', exact: true });
    await offers.locator('tbody tr').last().getByRole('button').click();
    await expect(page.getByRole('table', { name: 'Approved contributor runtimes', exact: true })).toContainText(`sha256:${'b'.repeat(64)}`);
    await expect(page.getByRole('table', { name: 'Offered resource limits', exact: true })).toContainText('Storage inodes');
    await expect(page.getByRole('button', { name: /^(Pause|Drain|Stop) contributor/ })).toHaveCount(0);
    await selectWorkload(page, `Retained computation ${String(count).padStart(2, '0')}`);
    await expect(page.getByText('Execution outcome is unknown.', { exact: false })).toBeVisible();
    expect(await page.locator('.workloads').innerText()).not.toMatch(/^(?:null)+$/m);
    await expect(page.getByRole('button', { name: 'Retry workload', exact: true })).toBeDisabled();
    const response = page.waitForResponse(value => value.url().endsWith('/output'));
    await page.getByRole('button', { name: 'Read from start', exact: true }).click();
    const first = (await (await response).json()).results[0];
    await expect(page.getByLabel('Workload output page', { exact: true })).toContainText('Synthetic retained output');
    expect(first.offset).toBe(0); expect(Buffer.from(first.data, 'base64').length).toBe(65536);
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Save this byte range', exact: true }).click();
    expect(await readFile(await (await download).path())).toEqual(Buffer.from(first.data, 'base64'));
    await page.getByRole('button', { name: 'Next page', exact: true }).click();
    await expect(page.getByLabel('Workload output page', { exact: true })).toContainText('<img src=x');
    expect(await page.evaluate(() => Boolean(window.injected))).toBe(false);
    await expect(page.getByRole('button', { name: 'Next page', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: 'Previous page', exact: true }).click();
    await expect(page.getByLabel('Workload output page', { exact: true })).toContainText('Synthetic retained output');
    await page.getByLabel('Output object', { exact: true }).selectOption('output:result');
    await expect(page.getByLabel('Workload output page', { exact: true })).toBeEmpty();
    await page.getByRole('button', { name: 'Read from start', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Save this byte range', exact: true })).toBeEnabled();
    await capture(page, `workloads-${count}-retained-output`);
    await page.getByRole('button', { name: 'Release retained output', exact: true }).click();
    let dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('permanently deletes all retained output');
    await expect(dialog).toContainText('not a full artifact download');
    await dialog.getByRole('button', { name: 'Delete output and release', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(page.getByText('Retained output was released and is no longer available.', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Retry workload', exact: true }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Confirm retry', exact: true }).click();
    await expect(dialog.getByRole('alert')).toContainText('Acknowledge the unknown outcome');
    await dialog.getByLabel('I understand that the previous outcome is unknown', { exact: false }).check();
    await dialog.getByRole('button', { name: 'Confirm retry', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await page.getByRole('button', { name: 'Cancel workload', exact: true }).click();
    await page.getByRole('button', { name: 'Confirm cancellation', exact: true }).click();
    await page.getByRole('button', { name: 'Remove record', exact: true }).click();
    await page.getByRole('button', { name: 'Remove workload record', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await page.getByRole('button', { name: 'New workload', exact: true }).click();
    await page.getByLabel('Workload name', { exact: true }).fill(`Submitted to ${count} candidates`);
    await page.getByRole('button', { name: 'Select all candidates', exact: true }).click();
    await expect(page.getByRole('dialog').getByText(`${count} candidates selected.`, { exact: false })).toBeVisible();
    await expect(page.getByLabel('Approved runtime', { exact: true })).toHaveValue('0');
    await expect(page.getByLabel('Memory (bytes)', { exact: true })).toHaveValue('1048576');
    await expect(page.getByLabel('Contains sensitive data', { exact: false })).toBeDisabled();
    const submission = page.waitForRequest(value => value.url().endsWith('/workloads') && value.method() === 'POST');
    await capture(page, `workloads-${count}-submission`);
    await page.getByRole('button', { name: 'Submit workload', exact: true }).click();
    const body = (await submission).postDataJSON();
    expect(body.requests).toHaveLength(1);
    expect(new Set(body.requests[0].request.node_ids)).toEqual(new Set(current.nodes));
    expect(body.requests[0].request.job.runtime.image_digest).toBe(`sha256:${'b'.repeat(64)}`);
    expect(body.requests[0].request.job.payload.argv).toEqual(['/usr/bin/printf', 'Hello from FICC\n']);
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('table', { name: 'Project workloads', exact: true }).locator('tbody tr')).toHaveCount(count);
    expect(current.faults).toEqual([]);
  });
}

test('lost submit acknowledgement uses the identical key and one actual record', async ({ page }) => {
  current = await fixture(page);
  const submissions = [];
  await page.route('**/api/v1/workloads', async route => {
    if (route.request().method() !== 'POST') return route.continue();
    submissions.push(route.request().postDataJSON());
    if (submissions.length === 1) { await route.fetch(); return route.abort('connectionfailed'); }
    return route.continue();
  });
  await page.getByRole('button', { name: 'New workload', exact: true }).click();
  await page.getByRole('button', { name: 'Select all candidates', exact: true }).click();
  await page.getByLabel('Workload name', { exact: true }).fill('Idempotent computation');
  await page.getByRole('button', { name: 'Submit workload', exact: true }).click();
  await expect(page.getByRole('dialog').getByRole('alert')).toContainText('outcome may be uncertain');
  await expect(page.getByLabel('Workload name', { exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Retry same submission', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(submissions).toHaveLength(2); expect(submissions[1]).toEqual(submissions[0]);
  await expect(page.getByRole('table', { name: 'Project workloads', exact: true }).locator('tbody tr')).toHaveCount(2);
});

test('invalid form data stays editable and never submits', async ({ page }) => {
  current = await fixture(page);
  let submitted = 0;
  page.on('request', value => { if (value.url().endsWith('/workloads') && value.method() === 'POST') submitted++; });
  await page.getByRole('button', { name: 'New workload', exact: true }).click();
  await page.getByRole('button', { name: 'Select all candidates', exact: true }).click();
  await page.getByLabel('Workload name', { exact: true }).fill('Invalid computation');
  await page.getByLabel('Executable and arguments (JSON)', { exact: true }).fill('["relative-program"]');
  await page.getByRole('button', { name: 'Submit workload', exact: true }).click();
  await expect(page.getByRole('dialog').getByRole('alert')).toContainText('absolute container executable');
  await expect(page.getByLabel('Workload name', { exact: true })).toBeEnabled();
  expect(submitted).toBe(0);
});

for (const fault of ['identity', 'attempt', 'range', 'oversized']) {
  test(`synthetic output ${fault} corruption clears the old page and refuses save`, async ({ page }) => {
    current = await fixture(page);
    await page.getByRole('button', { name: 'Read from start', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Save this byte range', exact: true })).toBeEnabled();
    await page.route('**/api/v1/workloads/*/output', async route => {
      const response = await route.fetch(), value = await response.json(), row = value.results[0];
      if (fault === 'identity') row.identity = `sha256:${'c'.repeat(64)}`;
      if (fault === 'attempt') row.attempt_id = 'f'.repeat(32);
      if (fault === 'range') row.offset++;
      if (fault === 'oversized') row.data = Buffer.alloc(65537).toString('base64');
      return route.fulfill({ response, json: value });
    });
    await page.getByRole('button', { name: 'Next page', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Request failed', exact: true })).toBeVisible();
    await expect(page.getByLabel('Workload output page', { exact: true })).toBeEmpty();
    await expect(page.getByRole('button', { name: 'Save this byte range', exact: true })).toBeDisabled();
  });
}

test('a denied output read discards retained text and open request dialogs', async ({ page }) => {
  current = await fixture(page);
  await page.getByRole('button', { name: 'Read from start', exact: true }).click();
  await expect(page.getByLabel('Workload output page', { exact: true })).toContainText('Synthetic retained output');
  await page.route('**/api/v1/workloads/*/output', route => route.fulfill({ status: 403,
    json: { error: { code: 'denied', message: 'Synthetic output grant revocation.' } } }));
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Access denied', exact: true })).toBeVisible();
  await expect(page.getByLabel('Workload output page', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('table', { name: 'Project workloads', exact: true })).toHaveCount(0);
});

test('actual project switch and logout discard retained output', async ({ page }) => {
  current = await fixture(page);
  await page.getByRole('button', { name: 'Read from start', exact: true }).click();
  await expect(page.getByLabel('Workload output page', { exact: true })).toContainText('Synthetic retained output');
  await page.getByLabel('Current project', { exact: true }).selectOption(current.other_project);
  await expect(page.getByRole('heading', { name: 'Cluster overview', exact: true })).toBeVisible();
  await page.locator('[data-view=workloads]').click();
  await expect(page.getByText('No contributor workloads', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Workload output page', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Console locked', exact: true })).toBeVisible();
  await expect(page.getByText('Synthetic retained output', { exact: false })).toHaveCount(0);
});

test('retired unknown attempt requires revoke-first and cannot imply storage cleanup', async ({ page }) => {
  current = await fixture(page);
  await page.getByRole('button', { name: 'Abandon retired attempt', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('local storage cannot be reclaimed');
  await dialog.getByRole('button', { name: 'Acknowledge and abandon', exact: true }).click();
  await expect(dialog.getByRole('alert')).toContainText('Revoke this contributor');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry workload', exact: true })).toBeDisabled();
});

test('released unknown workload can be removed without claiming a successful outcome', async ({ page }) => {
  current = await fixture(page);
  await page.getByRole('button', { name: 'Release retained output', exact: true }).click();
  await page.getByRole('button', { name: 'Delete output and release', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('button', { name: 'Remove record', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('execution outcome remains unknown');
  await page.getByRole('button', { name: 'Remove workload record', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByText('No contributor workloads', { exact: true })).toBeVisible();
  expect(current.faults).toEqual([]);
});

test('a pending output reply cannot repopulate a signed-out console', async ({ page }) => {
  current = await fixture(page);
  let release, waiting;
  const pending = new Promise(resolve => { waiting = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  await page.route('**/api/v1/workloads/*/output', async route => {
    const response = await route.fetch(); waiting(); await gate;
    await route.fulfill({ response }).catch(() => {});
  });
  try {
    await page.getByRole('button', { name: 'Read from start', exact: true }).click();
    await pending;
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Console locked', exact: true })).toBeVisible();
  } finally { release(); }
  await expect(page.getByLabel('Workload output page', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Synthetic retained output', { exact: false })).toHaveCount(0);
  expect(current.faults).toEqual([]);
});

test('synthetic read-only session projection hides mutations and output access', async ({ page }) => {
  await page.route('**/api/v1/session', async route => {
    const response = await route.fetch(), value = await response.json();
    if (value.principal) value.principal.scopes = ['nodes:read', 'jobs:read', 'contributors:read'];
    await route.fulfill({ response, json: value });
  });
  current = await fixture(page);
  await expect(page.getByRole('button', { name: 'New workload', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Release retained output', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Retry workload', exact: true })).toHaveCount(0);
  await expect(page.getByText('Output access requires the jobs:logs grant.', { exact: true })).toBeVisible();
});

test('different approved runtime digests cannot be combined in one candidate selection', async ({ page }) => {
  await page.route('**/api/v1/workload-offers', async route => {
    const response = await route.fetch(), value = await response.json();
    value.offers.at(-1).snapshot.offer.runtimes[0].image_digest = `sha256:${'c'.repeat(64)}`;
    await route.fulfill({ response, json: value });
  });
  current = await fixture(page, 64);
  await page.getByRole('button', { name: 'New workload', exact: true }).click();
  await page.getByRole('button', { name: 'Select all candidates', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Submit workload', exact: true })).toBeDisabled();
  await expect(page.getByRole('dialog').getByText('Select contributors with an approved runtime in common.', { exact: false })).toBeVisible();
  await page.getByLabel(`Candidate ${current.nodes.at(-1)}`, { exact: true }).uncheck();
  await expect(page.getByRole('button', { name: 'Submit workload', exact: true })).toBeEnabled();
});

for (const width of [390, 1280]) {
  test(`workload tables, output and form fit ${width} pixels`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 });
    current = await fixture(page);
    await page.getByRole('button', { name: 'Read from start', exact: true }).click();
    await expect(page.getByLabel('Workload output page', { exact: true })).toContainText('Synthetic retained output');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await capture(page, `workloads-detail-${width}`);
    await page.getByRole('button', { name: 'New workload', exact: true }).click();
    await page.getByRole('button', { name: 'Select all candidates', exact: true }).click();
    expect(await page.getByRole('dialog').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await capture(page, `workloads-form-${width}`);
    await page.keyboard.press('Escape');
    await expect(page.getByRole('button', { name: 'New workload', exact: true })).toBeFocused();
    expect(current.faults).toEqual([]);
  });
}
