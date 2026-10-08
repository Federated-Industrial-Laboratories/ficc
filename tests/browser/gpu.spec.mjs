// SPDX-License-Identifier: Apache-2.0
// Exercise observed GPU memory semantics and missing counters in the console.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, login, mockNodes, node } from './support.mjs';

for (const width of [390, 1280]) {
  test(`GPU observation at ${width} pixels distinguishes VRAM and unified memory`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1080 });
    const sample = node();
    sample.resources.gpu_status = 'available';
    sample.resources.gpus = [
      { uuid: 'GPU-sample', name: 'Sample NVIDIA GPU', memory_kind: 'vram',
        utilization_percent: 42, memory_used_bytes: 1024 ** 3, memory_total_bytes: 8 * 1024 ** 3,
        temperature_c: 55, reservation_supported: true },
      { uuid: 'AMD-PCI-0000:01:00.0', name: 'Sample AMD integrated GPU', memory_kind: 'vram',
        utilization_percent: 0, memory_used_bytes: 16 * 1024 ** 2, memory_total_bytes: 512 * 1024 ** 2,
        temperature_c: 37.5, reservation_supported: false },
      { uuid: 'APPLE-REGISTRY-64', name: 'Sample Apple GPU', memory_kind: 'unified',
        utilization_percent: null, memory_used_bytes: 2 * 1024 ** 3, memory_total_bytes: null,
        temperature_c: null, reservation_supported: false },
    ];
    await mockNodes(page, [sample]);
    await login(page);
    const cards = page.locator('.gpu-card');
    await expect(cards).toHaveCount(3);
    await expect(cards.nth(0)).toContainText('42.0%');
    await expect(cards.nth(1)).toContainText('0.0%');
    await expect(cards.nth(1)).toContainText('16.0 MiB / 512.0 MiB driver-reported VRAM');
    await expect(cards.nth(2)).toContainText('Unknown');
    await expect(cards.nth(2)).toContainText('2.0 GiB unified memory used; shared with the system');
    await expect(cards.nth(2)).toContainText('Temperature unknown');
    await expect(cards.nth(2)).toContainText('Observation only');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await capture(page, `gpu-observation-${width}`);
  });
}

test('detected GPU stays visible when its readings are unavailable', async ({ page }) => {
  const sample = node();
  sample.resources.gpu_status = 'unavailable';
  sample.resources.gpus = [{ uuid: 'APPLE-REGISTRY-64', name: 'Sample Apple GPU', memory_kind: 'unified',
    utilization_percent: null, memory_used_bytes: null, memory_total_bytes: null,
    temperature_c: null, reservation_supported: false }];
  await mockNodes(page, [sample]);
  await login(page);
  await expect(page.locator('.gpu-card')).toContainText('Sample Apple GPU');
  await expect(page.locator('.gpu-card')).toContainText('Unknown unified memory used');
  await expect(page.locator('.gpu-card')).not.toContainText('0.0%');
});
