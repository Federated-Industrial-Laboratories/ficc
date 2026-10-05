// SPDX-License-Identifier: Apache-2.0
// Verify portable themes, safe imports, persistence and appearance on real console assets.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { readFile } from 'node:fs/promises';
import { login, origin, capture } from './support.mjs';
import { setupTerminals, attachTerminal } from './terminal-support.mjs';
import { classics } from '../../web/static/theme-defaults.js';
import { validateTheme, parseTheme } from '../../web/static/theme-format.js';

const key = 'ficc.appearance.v1';
const open = page => page.getByRole('button', { name: 'Appearance', exact: true }).click();
const dark = page => page.getByRole('button', { name: 'Classic Dark', exact: true }).click();
const done = page => page.getByRole('button', { name: 'Done', exact: true }).click();
const upload = (page, value) => page.getByLabel('Import theme JSON').setInputFiles({
  name: 'theme.json', mimeType: 'application/json', buffer: Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)),
});

test('theme format rejects executable content, unknown fields and unbounded graphics', async () => {
  const base = { version: 1, id: 'test-theme', name: 'Test theme', scheme: 'dark' };
  expect(validateTheme(validateTheme(base))).toEqual(validateTheme(base));
  for (const value of [
    { ...base, version: 2 }, { ...base, css: 'body {display:none}' },
    { ...base, colors: { paper: 'url(https://example.com/image)' } },
    { ...base, colors: { ink: '#ffffff00' } },
    { ...base, materials: { metal: { angle: 90, stops: [{ color: 'ink', at: 90 }, { color: 'paper', at: 10 }] } } },
    { ...base, logo: { type: 'paths', viewBox: [0, 0, 20, 20], paths: [{ d: 'M0 0', onload: 'alert(1)' }] } },
    { ...base, logo: { type: 'paths', viewBox: [0, 0, 20, 20], paths: Array(65).fill({ d: 'M0 0' }) } },
  ]) expect(() => validateTheme(value)).toThrow();
  expect(() => parseTheme('{"version":1,"__proto__":{"css":"x"}}')).toThrow();
  expect(() => parseTheme(' '.repeat(65537))).toThrow(/64 KiB/);
});

test('classic dark persists across reload, separate windows and sign-out', async ({ page, context }) => {
  await login(page); await open(page); await dark(page); await done(page);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'classic-dark');
  await expect(page.locator('main')).toHaveCSS('background-color', 'rgb(36, 44, 51)');
  await page.reload(); await expect(page.locator('html')).toHaveAttribute('data-theme', 'classic-dark');
  const second = await context.newPage(); await second.goto(`${origin}/?window=1`);
  await expect(second.locator('html')).toHaveAttribute('data-theme', 'classic-dark');
  await open(page); await page.getByLabel('Flat materials', { exact: true }).check(); await done(page);
  await expect(second.locator('html')).toHaveAttribute('data-materials', 'flat');
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Console locked' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'classic-dark');
  const saved = await page.evaluate(key => JSON.parse(localStorage.getItem(key)), key);
  expect(Object.keys(saved).sort()).toEqual(['custom', 'flat', 'selected', 'version']);
  await second.close();
});

test('all built-in palettes round-trip with legible primary text and flat materials', async ({ page }) => {
  const collection = JSON.parse(await readFile(new URL('../../web/static/themes.json', import.meta.url), 'utf8'));
  const themes = [...classics, ...collection].map(validateTheme);
  expect(themes).toHaveLength(26); expect(new Set(themes.map(theme => theme.id)).size).toBe(26);
  const luminance = hex => {
    const [r, g, b] = hex.slice(1).match(/../g).slice(0, 3).map(value => parseInt(value, 16) / 255)
      .map(value => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4);
    return .2126 * r + .7152 * g + .0722 * b;
  };
  const pairs = [['ink', 'white'], ['ink', 'paper'], ['ink', 'surface'], ['ink', 'orange-light'],
    ['muted', 'white'], ['muted', 'paper'], ['muted', 'orange-light'], ['on-accent', 'orange'],
    ['on-danger', 'red'], ['status-ink', 'dark'], ['green', 'paper'], ['red', 'paper'], ['warning', 'paper'],
    ['info', 'info-bg'], ['warning', 'warning-bg'], ['red', 'error-bg'], ['terminal-ink', 'terminal-bg']];
  for (const theme of themes) {
    expect(parseTheme(JSON.stringify(theme))).toEqual(theme);
    for (const [fg, bg] of pairs) {
      const a = luminance(theme.colors[fg]), b = luminance(theme.colors[bg]);
      expect((Math.max(a, b) + .05) / (Math.min(a, b) + .05), `${theme.name}: ${fg}/${bg}`).toBeGreaterThanOrEqual(4.5);
    }
  }
  await login(page); await open(page);
  await expect(page.locator('.theme-card')).toHaveCount(26);
  await page.getByLabel('Flat materials', { exact: true }).check();
  for (const theme of themes) {
    await page.getByRole('button', { name: theme.name, exact: true }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme.id);
    const gradients = await page.evaluate(() => [...document.querySelectorAll('body, button, .masthead, .sidebar, .panel-title, th, .shell-cap span, .shell-bottom')]
      .filter(element => /gradient\(/.test(getComputedStyle(element).backgroundImage)).map(element => element.className));
    expect(gradients, theme.name).toEqual([]);
  }
  await page.getByLabel('Find a theme').fill('prism');
  await expect(page.locator('.theme-card')).toHaveCount(1);
  await dark(page); await page.getByLabel('Flat materials', { exact: true }).uncheck(); await done(page);
  await capture(page, 'theme-classic-dark');
});

test('custom gradients and replacement logos import, update, export and remove', async ({ page }) => {
  await login(page); await open(page);
  const custom = { version: 1, id: 'custom-signal', name: 'Custom Signal', scheme: 'dark',
    colors: { orange: '#83c9bf' }, materials: { metal: { angle: 45, stops: [{ color: 'paper', at: 0 }, { color: 'surface', at: 100 }] } },
    logo: { type: 'paths', viewBox: [0, 0, 32, 32], paths: [{ d: 'M4 4H28V28H4Z', fill: 'orange' }] } };
  await upload(page, custom);
  await expect(page.locator('.theme-feedback')).toContainText('Custom Signal imported and applied');
  await expect(page.locator('[data-theme-logo] svg')).toHaveAttribute('viewBox', '0 0 32 32');
  await expect(page.locator('[data-theme-logo] path')).toHaveAttribute('fill', '#83c9bf');
  await expect(page.locator('.panel-title').first()).toHaveCSS('background-image', 'linear-gradient(45deg, rgb(41, 52, 61) 0%, rgb(48, 59, 68) 100%)');
  await upload(page, { ...custom, name: 'Updated Signal' });
  await expect(page.locator('.theme-card')).toHaveCount(27);
  await page.getByLabel('Flat materials', { exact: true }).check();
  const waiting = page.waitForEvent('download'); await page.getByRole('button', { name: 'Export JSON' }).click();
  const download = await waiting, stream = await download.createReadStream();
  let raw = ''; for await (const chunk of stream) raw += chunk;
  const exported = parseTheme(raw); expect(exported.name).toBe('Updated Signal'); expect(exported.materials.enabled).toBe(false);
  expect(exported.logo.paths[0].d).toBe('M4 4H28V28H4Z');
  await upload(page, { ...custom, colors: { paper: 'url(https://example.com/track)' } });
  await expect(page.locator('.theme-feedback')).toContainText('Import failed');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'custom-signal');
  await upload(page, { ...custom, id: 'classic-light' });
  await expect(page.locator('.theme-feedback')).toContainText('built-in theme');
  await page.getByRole('button', { name: 'Remove custom theme' }).click();
  await expect(page.locator('.theme-card')).toHaveCount(26);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'classic-light');
});

test('invalid saved data and unavailable browser storage leave the console usable', async ({ page }) => {
  await page.goto(origin);
  await page.evaluate(key => localStorage.setItem(key, '{invalid json'), key);
  await page.reload(); await expect(page.locator('html')).toHaveAttribute('data-theme', 'classic-light');
  await open(page); await expect(page.locator('.appearance-dialog .notice')).toContainText('could not be read');
  await page.evaluate(() => { Storage.prototype.setItem = () => { throw new DOMException('Full', 'QuotaExceededError'); }; });
  await dark(page);
  await expect(page.locator('.appearance-dialog .notice')).toContainText('storage is unavailable or full');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'classic-dark');
  await page.keyboard.press('Escape'); await expect(page.locator('#appearance-dialog')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Appearance', exact: true })).toBeFocused();
});

for (const width of [320, 390, 800, 1440]) {
  test(`appearance and navigation fit a ${width}px viewport`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 }); await login(page);
    await open(page); await dark(page);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const dialog = page.locator('#appearance-dialog');
    expect(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    await capture(page, `appearance-${width}`); await done(page);
    await page.locator('[data-view=operations]').click();
    await expect(page.getByRole('heading', { name: 'Installation health', exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}

test('a theme change recolors attached terminals without reconnecting or sending input', async ({ page }) => {
  const state = await setupTerminals(page); await attachTerminal(page, state);
  await open(page); await dark(page); await done(page);
  await expect(page.locator('.terminal-well')).toHaveCSS('background-color', 'rgb(23, 30, 36)');
  await expect(page.locator('.xterm-scrollable-element')).toHaveCSS('background-color', 'rgb(23, 30, 36)');
  expect(state.tickets).toHaveLength(1); expect(state.connections[0].closed).toBe(false);
  expect(state.connections[0].frames.filter(Buffer.isBuffer)).toHaveLength(0);
  await page.getByRole('button', { name: 'Focus terminal', exact: true }).click(); await page.keyboard.type('still-attached');
  await expect(page.locator('.xterm-rows')).toContainText('still-attached');
});

test('catalogue recovery preserves conflicting customs and valid siblings', async ({ page }) => {
  await page.route('**/static/themes.json', route => route.abort());
  await login(page); await open(page);
  const custom = { version: 1, id: 'my-own-theme', name: 'My own theme', scheme: 'dark' };
  await upload(page, custom);
  await upload(page, { ...custom, id: 'midnight-observatory', name: 'My observatory' });
  await expect(page.locator('.theme-card')).toHaveCount(4);
  await page.unroute('**/static/themes.json'); await page.reload(); await open(page);
  await expect(page.locator('.theme-card')).toHaveCount(28);
  await expect(page.locator('.appearance-dialog .notice')).toContainText('renamed to avoid a catalogue conflict');
  await expect(page.getByRole('button', { name: 'My observatory', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await dark(page); await done(page); await page.reload(); await open(page);
  await expect(page.getByRole('button', { name: 'My observatory', exact: true })).toBeVisible();
  const saved = await page.evaluate(key => JSON.parse(localStorage.getItem(key)), key);
  expect(saved.custom.map(theme => theme.id)).toEqual(['my-own-theme', 'midnight-observatory-custom-1']);
  await page.evaluate(key => {
    const saved = JSON.parse(localStorage.getItem(key)); saved.custom.push({ version: 20 });
    localStorage.setItem(key, JSON.stringify(saved));
  }, key);
  await page.reload(); await open(page);
  await expect(page.locator('.theme-card')).toHaveCount(28);
  await expect(page.locator('.appearance-dialog .notice')).toContainText('invalid saved theme was ignored');
});
