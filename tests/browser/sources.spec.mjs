// SPDX-License-Identifier: Apache-2.0
// Exercise a real source-driver export and its dataset handoff through the browser.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { confirmFiles } from './file-support.mjs';
import { capture } from './support.mjs';
import { fixture } from './workload-support.mjs';

test('actual CSV approval, exact integer preview, export and workload dataset selection', async ({ page }) => {
  test.skip(!process.env.FICC_WORKLOAD_PYTHON || !process.env.FICC_TEST_OPA, 'Select the existing isolated actual-API browser fixture.');
  test.setTimeout(90000);
  const current = await fixture(page);
  try {
    await page.locator('[data-view=files]').click();
    const left = page.locator('[data-pane=Left]');
    await left.getByRole('button', { name: 'Upload', exact: true }).click();
    const literal = '<img src=x onerror=window.injected=true>';
    await page.getByLabel('Files to upload').setInputFiles({ name: 'source.csv', mimeType: 'text/csv',
      buffer: Buffer.from(`id,label\n9007199254740992,first\n9007199254740993,${literal}\n`) });
    await page.getByRole('button', { name: 'Review upload', exact: true }).click();
    await page.getByRole('button', { name: 'Preview transfer', exact: true }).click();
    await confirmFiles(page);
    await expect(page.getByText('Verified SHA-256', { exact: false })).toBeVisible();
    await page.locator('[data-view=sources]').click();
    await page.getByRole('button', { name: 'Approve source', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Source name', { exact: true }).fill('Browser readings');
    await dialog.getByLabel('Installed provider', { exact: true }).selectOption('csv');
    await dialog.getByLabel('Provider configuration JSON', { exact: true }).fill(JSON.stringify({
      schema: { fields: [{ name: 'id', type: 'integer', nullable: false }, { name: 'label', type: 'string', nullable: false }] }, malformed: 'error' }));
    await dialog.locator('[data-pane=Source]').getByRole('row').filter({ hasText: 'source.csv' }).getByRole('checkbox').check();
    await dialog.getByLabel('Allow dataset exports', { exact: true }).check();
    await dialog.getByRole('button', { name: 'Approve source', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await page.getByRole('table', { name: 'Approved source connections' }).getByRole('button', { name: 'Browse catalogue' }).click();
    await dialog.getByRole('button', { name: 'Describe', exact: true }).click();
    const schemaDialog = page.getByRole('dialog').last();
    await expect(schemaDialog.getByRole('table', { name: 'Source schema' })).toContainText('integer');
    await schemaDialog.getByRole('button', { name: 'Register query', exact: true }).click();
    await dialog.getByLabel('Query name', { exact: true }).fill('Selected readings');
    await dialog.getByLabel('Provider query specification', { exact: true }).fill(JSON.stringify({ columns: ['id', 'label'],
      filters: [{ column: 'id', operator: 'ge', parameter: 'minimum' }] }));
    await dialog.getByLabel('Declared parameters', { exact: true }).fill('[{"name":"minimum","type":"integer"}]');
    await dialog.getByRole('button', { name: 'Register query', exact: true }).click();
    await page.getByRole('button', { name: 'Open pipeline', exact: true }).click();
    await dialog.getByLabel('minimum (integer)', { exact: true }).fill('9007199254740993');
    await dialog.getByRole('button', { name: 'Preview rows', exact: true }).click();
    const preview = dialog.getByRole('table', { name: 'Query preview' });
    await expect(preview).toContainText('9007199254740993');
    await expect(preview).toContainText(literal);
    expect(await preview.locator('img').count()).toBe(0);
    await dialog.getByLabel('Dataset name', { exact: true }).fill('Browser source output');
    await dialog.getByLabel('Output filename', { exact: true }).fill('source-result.csv');
    await expect(dialog.locator('[data-pane=Output]')).toContainText('source.csv');
    await dialog.getByRole('button', { name: 'Export to dataset', exact: true }).click();
    await expect(page.getByRole('table', { name: 'Source operation receipts' })).toContainText('completed', { timeout: 30000 });
    await page.getByRole('button', { name: 'Receipt', exact: true }).click();
    await expect(dialog).toContainText('Select this dataset ID in Workloads');
    await capture(page, 'source-query-export-receipt');
    await dialog.getByRole('button', { name: 'Close', exact: true }).click();
    await page.locator('[data-view=workloads]').click();
    await page.getByRole('button', { name: 'New workload', exact: true }).click();
    await dialog.getByRole('button', { name: 'Browse datasets', exact: true }).click();
    await dialog.getByLabel('Input dataset', { exact: true }).selectOption({ label: 'Browser source output / 1 files' });
    await expect(dialog.getByText('/inputs/source-result.csv', { exact: true })).toBeVisible();
    expect(current.faults).toEqual([]);
  } finally { await current.close(); }
});
