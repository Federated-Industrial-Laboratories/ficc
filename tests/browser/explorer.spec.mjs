// SPDX-License-Identifier: Apache-2.0
// Check file-table identity, bounded selection and keyboard column controls.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { fileEntry, setupFiles } from './file-support.mjs';

const pane = page => page.locator('[data-pane=Left]');
const names = page => pane(page).locator('tbody .file-name');

for (const count of [1, 64]) test(`file sort retains selected opaque identity at N=${count}`, async ({ page }) => {
  const entries = Array.from({ length: count }, (_, i) => fileEntry(i + 1, { size: (count - i) * 1024, name: `report-${i + 1}.txt` }));
  const state = await setupFiles(page, { entries });
  await pane(page).getByRole('checkbox', { name: `Select report-${count}.txt`, exact: true }).check();
  await pane(page).getByRole('button', { name: 'Size', exact: true }).click();
  await expect(names(page).first()).toHaveText(`report-${count}.txt`);
  await pane(page).getByRole('button', { name: 'Delete', exact: true }).click();
  expect(state.previews.at(-1).entries).toEqual([`opaque-file-${count}`]);
  expect(state.mutations).toHaveLength(0);
});

test('filter clears hidden selection and select page uses only visible identities', async ({ page }) => {
  const state = await setupFiles(page, { entries: [fileEntry(1, { name: 'keep.txt' }), fileEntry(2, { name: 'hide.txt' })] });
  await pane(page).getByRole('checkbox', { name: 'Select hide.txt' }).check();
  await page.getByRole('searchbox', { name: 'Left find on this page' }).fill('keep');
  await expect(pane(page).getByText('0 selected', { exact: true })).toBeVisible();
  await expect(pane(page).getByRole('button', { name: 'Delete', exact: true })).toBeDisabled();
  await expect(names(page)).toHaveText(['keep.txt']);
  await pane(page).getByRole('button', { name: 'Select page' }).click();
  await pane(page).getByRole('button', { name: 'Delete', exact: true }).click();
  expect(state.previews.at(-1).entries).toEqual(['opaque-file-1']);
});

test('column keyboard resizing changes width without changing sort or selection', async ({ page }) => {
  await setupFiles(page);
  const handle = page.getByRole('separator', { name: 'Left Name column width', exact: true });
  const before = Number(await handle.getAttribute('aria-valuenow'));
  await handle.focus(); await page.keyboard.press('ArrowRight');
  await expect(handle).toHaveAttribute('aria-valuenow', String(before + 16));
  await page.keyboard.press('Home'); await expect(handle).toHaveAttribute('aria-valuenow', '140');
  await expect(pane(page).getByRole('columnheader', { name: 'Name', exact: false })).toHaveAttribute('aria-sort', 'ascending');
  await expect(pane(page).getByText('0 selected', { exact: true })).toBeVisible();
});

test('row keyboard focus and space select exactly one distinct file', async ({ page }) => {
  const state = await setupFiles(page, { entries: [fileEntry(1), fileEntry(2), fileEntry(3)] });
  const rows = pane(page).locator('tr[data-entry]');
  await rows.first().focus(); await page.keyboard.press('ArrowDown'); await page.keyboard.press('Space');
  await expect(rows.nth(1)).toBeFocused();
  await expect(pane(page).getByRole('checkbox', { name: 'Select sample-2.txt' })).toBeChecked();
  await expect(pane(page).getByRole('checkbox', { name: 'Select sample-1.txt' })).not.toBeChecked();
  await pane(page).getByRole('button', { name: 'Delete', exact: true }).click();
  expect(state.previews.at(-1).entries).toEqual(['opaque-file-2']);
});

test('page transition clears its filter and cannot keep a hidden selection', async ({ page }) => {
  await setupFiles(page, { paginated: true });
  await page.getByRole('searchbox', { name: 'Left find on this page' }).fill('sample-1.txt');
  await pane(page).getByRole('button', { name: 'Select page' }).click();
  await pane(page).getByRole('button', { name: 'Next page' }).click();
  await expect(page.getByRole('searchbox', { name: 'Left find on this page' })).toHaveValue('');
  await expect(names(page)).toHaveText(['sample-100.txt']);
  await expect(pane(page).getByText('0 selected', { exact: true })).toBeVisible();
});

test('a late directory reply cannot replace the selected location', async ({ page }) => {
  let release;
  const waiting = new Promise(resolve => { release = resolve; });
  await setupFiles(page);
  await page.route('**/api/v1/files/list', async route => {
    const body = route.request().postDataJSON();
    if (body.root_id === 'root-local') await waiting;
    await route.fulfill({ json: { root_id: body.root_id, entry_id: body.entry_id, breadcrumbs: [{ name: 'Root', entry_id: body.entry_id }],
      entries: [fileEntry(1, { name: body.root_id === 'root-local' ? 'obsolete.txt' : 'current.txt' })], next_cursor: null } });
  });
  await pane(page).getByRole('button', { name: 'Refresh', exact: true }).click();
  await pane(page).getByLabel('Machine', { exact: true }).selectOption('sample-1');
  await expect(names(page)).toHaveText(['current.txt']); release();
  await page.waitForTimeout(100); await expect(names(page)).toHaveText(['current.txt']);
});

test('directory navigation and Up use returned opaque ancestors', async ({ page }) => {
  const state = await setupFiles(page, { entries: [fileEntry(1, { name: 'folder', kind: 'directory' })] });
  await page.route('**/api/v1/files/list', route => {
    const body = route.request().postDataJSON(); state.lists.push(body);
    return route.fulfill({ json: { root_id: body.root_id, entry_id: body.entry_id, entries: [], next_cursor: null,
      breadcrumbs: [{ name: 'Root', entry_id: 'parent-opaque' }, { name: 'folder', entry_id: body.entry_id }] } });
  });
  await pane(page).getByRole('button', { name: 'folder', exact: true }).click();
  await expect(pane(page).getByRole('button', { name: 'Up', exact: true })).toBeEnabled();
  expect(state.lists.at(-1).entry_id).toBe('opaque-file-1');
  await pane(page).getByRole('button', { name: 'Up', exact: true }).click();
  await expect.poll(() => state.lists.at(-1).entry_id).toBe('parent-opaque');
});
