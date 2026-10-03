// SPDX-License-Identifier: Apache-2.0
// Check the real dataset safety UI with a local harmless ClamAV signature.
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { confirmFiles } from './file-support.mjs';
import { capture } from './support.mjs';
import { fixture } from './workload-support.mjs';

test('local inspection coverage, quarantine and explicit owner exemption', async ({ page }) => {
  test.skip(!process.env.FICC_TEST_INSPECTION || !process.env.FICC_WORKLOAD_PYTHON || !process.env.FICC_TEST_OPA,
    'Select the actual API fixture and explicitly available local ClamAV engine.');
  test.setTimeout(90000);
  const assets = await mkdtemp(join(tmpdir(), 'ficc-inspection-browser-'));
  const marker = Buffer.from('FICC harmless browser inspection fixture.\n');
  const database = join(assets, 'fixture.ndb');
  await writeFile(database, `FICC.Browser.Fixture:0:*:${marker.toString('hex')}\n`, { mode: 0o600 });
  const current = await fixture(page);
  try {
    await page.locator('[data-view=files]').click();
    const left = page.locator('[data-pane=Left]');
    await left.getByRole('button', { name: 'Upload', exact: true }).click();
    await page.getByLabel('Files to upload').setInputFiles({ name: 'inspection.txt', mimeType: 'text/plain', buffer: marker });
    await page.getByRole('button', { name: 'Review upload', exact: true }).click();
    await page.getByRole('button', { name: 'Preview transfer', exact: true }).click();
    await confirmFiles(page);
    await expect(page.getByText('Verified SHA-256', { exact: false })).toBeVisible();
    await left.getByRole('button', { name: 'Refresh', exact: true }).click();
    await left.getByRole('row').filter({ hasText: 'inspection.txt' }).getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Register left selection', exact: true }).click();
    await page.getByLabel('Dataset name', { exact: true }).fill('Inspection fixture');
    await page.getByRole('button', { name: 'Verify sources and register', exact: true }).click();
    await page.getByRole('button', { name: 'Inspect dataset Inspection fixture', exact: true }).click();
    const manifest = page.getByRole('dialog', { name: 'Dataset manifest', exact: true });
    await manifest.getByRole('button', { name: 'Local scanner settings', exact: true }).click();
    const configuration = page.getByRole('dialog', { name: 'Local inspection settings', exact: true });
    await configuration.getByLabel('Owner scanner configuration').fill(JSON.stringify({ provider: 'clamav', configuration: { database },
      memory_bytes: '268435456', temp_bytes: '16777216', seconds: 30 }));
    await configuration.getByRole('button', { name: 'Approve local inspection settings', exact: true }).click();
    await expect(configuration).toHaveCount(0);
    await manifest.getByRole('button', { name: 'Owner safety controls', exact: true }).click();
    const controls = page.getByRole('dialog', { name: 'Owner dataset safety controls', exact: true });
    await controls.getByLabel('Sensitive: approved managed workload placement').check();
    await controls.getByLabel('Require no detection within recorded coverage before use or publication').check();
    await controls.getByLabel('Audited reason', { exact: true }).fill('Harmless browser fixture requires inspection.');
    await controls.getByRole('button', { name: 'Save owner controls', exact: true }).click();
    await expect(manifest.getByText('Dataset use and publication are blocked.', { exact: true })).toBeVisible();
    await manifest.getByRole('button', { name: 'Inspect / re-scan locally', exact: true }).click();
    await expect(manifest.getByText('Detection reported', { exact: true })).toBeVisible({ timeout: 30000 });
    await manifest.getByRole('button', { name: 'Coverage and provenance', exact: true }).click();
    const coverage = page.getByRole('dialog', { name: 'Inspection coverage', exact: true });
    await expect(coverage).toContainText('FICC.Browser.Fixture');
    await expect(coverage).toContainText('ClamAV 1.5.4');
    await expect(coverage.getByRole('table', { name: 'Recorded signature provenance' })).toContainText('fixture.ndb');
    await expect(coverage.getByText('null', { exact: true })).toHaveCount(0);
    await capture(page, 'dataset-inspection-coverage');
    await coverage.getByRole('button', { name: 'Close', exact: true }).click();
    await manifest.getByRole('button', { name: 'Explicit exemption', exact: true }).click();
    const exemption = page.getByRole('dialog', { name: 'Exempt this dataset', exact: true });
    await exemption.getByLabel('Audited exemption reason').fill('Explicit harmless signature qualification exemption.');
    await exemption.getByLabel('I authorise this exception for the exact current dataset safety state.').check();
    await exemption.getByRole('button', { name: 'Grant exemption', exact: true }).click();
    await expect(manifest.getByText('An explicit owner exemption permits use.', { exact: true })).toBeVisible();
    await manifest.getByRole('button', { name: 'Revoke exemption', exact: true }).click();
    await expect(manifest.getByText('Dataset use and publication are blocked.', { exact: true })).toBeVisible();
    expect(current.faults).toEqual([]);
  } finally {
    await current.close();
    await rm(assets, { recursive: true, force: true });
  }
});
