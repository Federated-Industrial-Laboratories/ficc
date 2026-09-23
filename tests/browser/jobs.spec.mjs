// SPDX-License-Identifier: Apache-2.0
// Verify frozen submission, bounded output, grants and recovery for managed jobs.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture } from './support.mjs';
import { jobNode, jobScopes, operation, previewJob, setupJobs } from './job-support.mjs';

for (const count of [1, 64]) {
  test(`preview and submit exactly ${count} frozen targets`, async ({ page }) => {
    const nodes = Array.from({ length: count }, (_, index) => jobNode(index + 1));
    const fixture = await setupJobs(page, { nodes });
    await previewJob(page);
    await expect(page.getByRole('table', { name: 'Frozen job targets' }).locator('tbody tr')).toHaveCount(count);
    expect(fixture.submissions).toHaveLength(0);
    const accept = page.getByRole('button', { name: 'Confirm and start job', exact: true });
    await expect(accept).toBeDisabled();
    await page.getByLabel('Start this exact request', { exact: false }).check();
    await accept.click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('table', { name: 'Job target states' }).locator('tbody tr')).toHaveCount(count);
    expect(fixture.submissions).toHaveLength(1);
    expect(fixture.submissions[0].key.length).toBeGreaterThanOrEqual(16);
    expect(fixture.previews[0].node_ids).toEqual(nodes.map(node => node.id));
    expect(fixture.previews[0].job.argv).toEqual(['/usr/bin/printf', 'Hello from FICC\n']);
    expect(fixture.previews[0].job.limits.memory_max_bytes).toBe(268435456);
    await capture(page, `jobs-${count}-targets`);
  });
}

test('a lost submission acknowledgement retries with the same key', async ({ page }) => {
  const fixture = await setupJobs(page, { dropFirstSubmit: true });
  await previewJob(page);
  await page.getByLabel('Start this exact request', { exact: false }).check();
  await page.getByRole('button', { name: 'Confirm and start job', exact: true }).click();
  await expect(page.getByText('The outcome may be uncertain.', { exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Back', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Retry same submission', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(fixture.submissions).toHaveLength(2);
  expect(fixture.submissions[0]).toEqual(fixture.submissions[1]);
});

for (const changes of [{ expiry: -1 }, { ready: false }]) {
  test(`unready or expired preview cannot dispatch: ${JSON.stringify(changes)}`, async ({ page }) => {
    const fixture = await setupJobs(page, changes);
    await previewJob(page);
    await page.getByLabel('Start this exact request', { exact: false }).check();
    await expect(page.getByRole('button', { name: 'Confirm and start job', exact: true })).toBeDisabled();
    expect(fixture.submissions).toEqual([]);
  });
}

test('shell mode, resource limits and GPU reservations remain explicit', async ({ page }) => {
  const sample = jobNode();
  sample.resources.gpus = [{ uuid: 'GPU-SYNTHETIC', name: 'Synthetic GPU', memory_used_bytes: 1073741824,
    memory_total_bytes: 8589934592, utilization_percent: 10 }];
  const fixture = await setupJobs(page, { nodes: [sample] });
  await page.getByRole('button', { name: 'New job', exact: true }).click();
  await page.getByRole('button', { name: 'Select all machines', exact: true }).click();
  await page.getByLabel('Job label / purpose', { exact: true }).fill('Shell example');
  await page.getByLabel('Command mode', { exact: true }).selectOption('shell');
  await page.getByLabel('Shell script', { exact: true }).fill("printf '%s' 'literal; value'");
  await page.getByLabel('Synthetic GPU / GPU-SYNTHETIC', { exact: true }).check();
  await page.getByRole('spinbutton', { name: 'GPU memory MiB for Sample machine 1 GPU-SYNTHETIC' }).fill('512');
  await page.getByLabel('CPU quota (% of one CPU)', { exact: true }).fill('50');
  await page.getByRole('button', { name: 'Preview job', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Confirm frozen targets' })).toBeVisible();
  expect(fixture.previews[0].job.argv).toEqual(['/bin/sh', '-lc', "printf '%s' 'literal; value'"]);
  expect(fixture.previews[0].job.allow_session_lifetime).toBe(false);
  expect(fixture.previews[0].job.gpu_reservations).toEqual({ 'sample-1': [{ uuid: 'GPU-SYNTHETIC', memory_bytes: 536870912 }] });
  expect(fixture.previews[0].job.limits.cpu_percent).toBe(50);
});

test('invalid command input cannot reach preview admission', async ({ page }) => {
  const fixture = await setupJobs(page);
  await page.getByRole('button', { name: 'New job', exact: true }).click();
  await page.getByRole('button', { name: 'Select all machines', exact: true }).click();
  await page.getByLabel('Job label / purpose', { exact: true }).fill('Invalid example');
  await page.getByLabel('Executable and arguments', { exact: true }).fill('{"command":"echo"}');
  await page.getByRole('button', { name: 'Preview job', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Enter a JSON array');
  expect(fixture.previews).toEqual([]);
});

test('output remains safe text with bounded history and distinct streams', async ({ page }) => {
  const hostile = '<img src=x onerror="window.injected=true">';
  const fixture = await setupJobs(page, { operations: [operation()], stdout: `${'x'.repeat(70000)}${hostile}`, dropped: 2048 });
  await expect(page.getByLabel('Job output', { exact: true })).toContainText(hostile);
  expect(await page.getByLabel('Job output', { exact: true }).evaluate(node => node.textContent.length)).toBeLessThanOrEqual(65536);
  await expect(page.getByText('The browser shows only the latest', { exact: false })).toBeVisible();
  await expect(page.getByText('were discarded after the remote output limit.', { exact: false })).toBeVisible();
  expect(await page.evaluate(() => Boolean(window.injected))).toBe(false);
  expect(fixture.logCalls.every(url => Number(url.searchParams.get('limit')) <= 65536)).toBe(true);
  await page.getByLabel('Output stream', { exact: true }).selectOption('stderr');
  await expect(page.getByLabel('Job output', { exact: true })).toHaveText('Error stream sample\n');
  await page.getByRole('button', { name: 'Read from start', exact: true }).click();
  await expect(page.getByLabel('Job output', { exact: true })).toHaveText('Error stream sample\n');
});

test('output requires its own grant while results stay readable', async ({ page }) => {
  const fixture = await setupJobs(page, { operations: [operation()], scopes: jobScopes.filter(scope => scope !== 'jobs:logs') });
  await expect(page.getByRole('table', { name: 'Job target states' })).toBeVisible();
  await expect(page.getByText('Output access requires the jobs:logs grant.', { exact: false })).toBeVisible();
  expect(fixture.logCalls).toEqual([]);
  await expect(page.getByLabel('Job output', { exact: true })).toHaveCount(0);
});

test('read-only grants and demo mode cannot start or cancel work', async ({ page }) => {
  await setupJobs(page, { operations: [operation()], scopes: ['nodes:read', 'jobs:read'] });
  await expect(page.getByRole('button', { name: 'New job', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Cancel selected jobs', exact: true })).toHaveCount(0);
  await expect(page.getByText('depends on the remote login session.', { exact: false })).toBeVisible();
});

test('demo mode disables SSH job mutations despite owner grants', async ({ page }) => {
  await setupJobs(page, { operations: [operation()], mode: 'demo' });
  await expect(page.getByRole('button', { name: 'New job', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Cancel selected jobs', exact: true })).toHaveCount(0);
  await expect(page.getByText('Simulation mode. Job submission', { exact: false })).toBeVisible();
});

test('cancellation uses only selected nonterminal targets and explicit force', async ({ page }) => {
  const nodes = [jobNode(1), jobNode(2), jobNode(3)];
  const value = operation(nodes); value.targets[2].state = 'succeeded';
  const fixture = await setupJobs(page, { nodes, operations: [value] });
  await expect(page.getByLabel('Select Sample machine 3 for cancellation')).toBeDisabled();
  await page.getByLabel('Select Sample machine 2 for cancellation').check();
  await page.getByRole('button', { name: 'Cancel selected jobs', exact: true }).click();
  expect(fixture.cancellations).toEqual([]);
  await page.getByRole('button', { name: 'Confirm cancellation', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(fixture.cancellations).toEqual([{ node_ids: ['sample-2'], force: false }]);
  await page.getByLabel('Select Sample machine 1 for cancellation').check();
  await page.getByRole('button', { name: 'Force stop selected jobs', exact: true }).click();
  await page.getByRole('button', { name: 'Confirm force stop', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(fixture.cancellations[1]).toEqual({ node_ids: ['sample-1'], force: true });
});

test('disconnect preserves uncertain history and reconnect never resubmits', async ({ page }) => {
  const value = operation(); value.targets[0].state = 'unknown';
  const fixture = await setupJobs(page, { operations: [value] });
  await expect(page.getByText('Execution is uncertain.', { exact: false })).toBeVisible();
  fixture.available = false;
  await page.getByRole('button', { name: 'Refresh jobs', exact: true }).click();
  await expect(page.getByText('Service disconnected. These are cached results.', { exact: false })).toBeVisible();
  fixture.available = true;
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Service disconnected', exact: true })).toHaveCount(0);
  expect(fixture.submissions).toEqual([]);
  fixture.denied = true;
  await page.getByRole('button', { name: 'Refresh jobs', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Access denied', exact: true })).toBeVisible();
  await expect(page.getByRole('table', { name: 'Managed operations' })).toHaveCount(0);
  await expect(page.getByLabel('Job output', { exact: true })).toHaveCount(0);
});

for (const width of [390, 1280]) {
  test(`job detail and form fit a ${width}-pixel viewport`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 });
    const faults = []; page.on('pageerror', error => faults.push(error.message));
    await setupJobs(page, { operations: [operation()] });
    await expect(page.getByRole('table', { name: 'Job target states' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await capture(page, `job-detail-${width}`);
    await page.getByRole('button', { name: 'New job', exact: true }).click();
    expect(await page.getByRole('dialog').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await capture(page, `job-form-${width}`);
    await page.keyboard.press('Escape');
    await expect(page.getByRole('button', { name: 'New job', exact: true })).toBeFocused();
    expect(faults).toEqual([]);
  });
}

test('helper upgrade preserves enrollment and confirms the pinned fingerprint', async ({ page }) => {
  const sample = jobNode(); let submitted = null;
  await setupJobs(page, { nodes: [sample] });
  await page.route('**/api/v1/nodes/*/helper-upgrade', route => {
    submitted = route.request().postDataJSON(); return route.fulfill({ json: sample });
  });
  await page.getByRole('button', { name: 'Overview', exact: false }).click();
  await page.getByRole('button', { name: 'Upgrade helper', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Confirm helper upgrade', exact: true })).toBeDisabled();
  await expect(page.getByRole('dialog').getByText(sample.fingerprint, { exact: true })).toBeVisible();
  await page.getByLabel('Install the updated FICC helper', { exact: false }).check();
  await page.getByRole('button', { name: 'Confirm helper upgrade', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(submitted).toEqual({ expected_fingerprint: sample.fingerprint });
  await expect(page.getByRole('button', { name: sample.name, exact: true })).toBeVisible();
});


test('UTF-8 output remains intact across a completed stream chunk boundary', async ({ page }) => {
  await setupJobs(page, { operations: [operation()], stdout: `${'x'.repeat(65535)}☃` });
  await expect(page.getByLabel('Job output', { exact: true })).toContainText('☃');
  await expect(page.getByLabel('Job output', { exact: true })).not.toContainText('�');
});

test('cancellation confirmation stays bound to the original operation during refresh', async ({ page }) => {
  const original = operation(), replacement = operation(undefined, { id: '3'.repeat(32) });
  const fixture = await setupJobs(page, { operations: [original] });
  let cancelledPath = null;
  await page.route('**/api/v1/operations/*/cancel', route => {
    cancelledPath = new URL(route.request().url()).pathname;
    return route.fulfill({ status: 202, json: original });
  });
  await page.getByLabel('Select Sample machine 1 for cancellation').check();
  await page.getByRole('button', { name: 'Cancel selected jobs', exact: true }).click();
  fixture.operations = [replacement];
  await page.waitForResponse(response => response.url().endsWith('/api/v1/operations'));
  await expect(page.getByText(replacement.id, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Confirm cancellation', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(cancelledPath).toBe(`/api/v1/operations/${original.id}/cancel`);
});


test('revoking only the output grant clears cached text', async ({ page }) => {
  const fixture = await setupJobs(page, { operations: [operation()] });
  await expect(page.getByLabel('Job output', { exact: true })).toContainText('Hello from FICC');
  fixture.logDenied = true;
  await page.getByRole('button', { name: 'Read next output', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Access denied', exact: true })).toBeVisible();
  await expect(page.getByLabel('Job output', { exact: true })).toBeEmpty();
  await expect(page.getByRole('table', { name: 'Job target states' })).toBeVisible();
});

test('background reconciliation preserves command disclosure and keyboard focus', async ({ page }) => {
  await setupJobs(page, { operations: [operation()] });
  await page.getByText('Submitted request', { exact: true }).click();
  await page.getByLabel('Select Sample machine 1 for cancellation').check();
  const cancel = page.getByRole('button', { name: 'Cancel selected jobs', exact: true });
  await cancel.focus();
  await page.waitForResponse(response => response.url().endsWith('/api/v1/operations'));
  await expect(page.locator('details[data-disclosure="request"]')).toHaveAttribute('open', '');
  await expect(cancel).toBeFocused();
  await expect(page.getByLabel('Select Sample machine 1 for cancellation')).toBeChecked();
});

test('following output resumes after a temporary remote failure', async ({ page }) => {
  const fixture = await setupJobs(page, { operations: [operation()], logUnavailable: true });
  await expect(page.getByText('Remote output is temporarily unavailable.', { exact: true })).toBeVisible();
  fixture.logUnavailable = false;
  await expect(page.getByLabel('Job output', { exact: true })).toContainText('Hello from FICC');
  expect(fixture.logCalls.length).toBeGreaterThanOrEqual(2);
  expect(fixture.logCalls.slice(0, 2).map(url => url.searchParams.get('offset'))).toEqual(['0', '0']);
});
