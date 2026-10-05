// SPDX-License-Identifier: Apache-2.0
// Apply browser-local appearance preferences and synchronize workspace windows.
import { classics } from './theme-defaults.js';
import { validateTheme, parseTheme, materialNames } from './theme-format.js';
import { themeLogo } from './theme-logo.js';

export const STORAGE_KEY = 'ficc.appearance.v1';
let builtins = classics.map(validateTheme), custom = [], selected = 'classic-light', flat = false;
let message = '', ready;
const copy = value => structuredClone(value);
export function appearance() {
  return { themes: copy([...builtins, ...custom]), selected, flat, message,
    customIds: custom.map(theme => theme.id), theme: copy(currentTheme()) };
}
function currentTheme() { return [...builtins, ...custom].find(theme => theme.id === selected) ?? builtins[0]; }
function tell() { window.dispatchEvent(new CustomEvent('ficc-theme-changed')); }
function read(source) {
  if (!source) { custom = []; selected = 'classic-light'; flat = false; return; }
  const value = JSON.parse(source);
  if (!value || value.version !== 1 || !Array.isArray(value.custom) || value.custom.length > 32 ||
      typeof value.selected !== 'string' || typeof value.flat !== 'boolean') throw Error('Invalid appearance preferences.');
  const themes = [], ids = new Set(builtins.map(theme => theme.id));
  let renamed = 0, invalid = 0, customSelection;
  for (const entry of value.custom) {
    let theme;
    try { theme = validateTheme(entry); } catch { invalid++; continue; }
    const previous = theme.id;
    if (ids.has(theme.id)) {
      let suffix = 1;
      do { theme.id = `${previous.slice(0, 36)}-custom-${suffix++}`; }
      while (ids.has(theme.id) || value.custom.some(item => item?.id === theme.id));
      renamed++;
    }
    if (previous === value.selected && !customSelection) customSelection = theme.id;
    ids.add(theme.id); themes.push(theme);
  }
  custom = themes; selected = customSelection ?? (ids.has(value.selected) ? value.selected : 'classic-light'); flat = value.flat;
  if (renamed || invalid) message = [
    renamed ? `${renamed} saved custom theme id${renamed === 1 ? ' was' : 's were'} renamed to avoid a catalogue conflict. Your custom themes are kept.` : '',
    invalid ? `${invalid} invalid saved theme${invalid === 1 ? ' was' : 's were'} ignored. Other custom themes are kept.` : '',
  ].filter(Boolean).join(' ');
}
function restore() {
  message = '';
  try { read(localStorage.getItem(STORAGE_KEY)); }
  catch { read(null); message = 'Saved appearance could not be read. Classic Light is active; choose a theme to save new preferences.'; }
}
function persist() {
  message = '';
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ version: 1, selected, flat, custom })); }
  catch { message = 'Appearance changed for this window, but browser storage is unavailable or full. Export custom themes to keep them.'; }
}
function apply() {
  const theme = currentTheme(), root = document.documentElement, enabled = theme.materials.enabled && !flat;
  root.dataset.theme = theme.id; root.dataset.scheme = theme.scheme; root.dataset.materials = enabled ? 'textured' : 'flat';
  root.style.colorScheme = theme.scheme;
  document.querySelector('meta[name="color-scheme"]')?.setAttribute('content', theme.scheme);
  for (const [key, value] of Object.entries(theme.colors)) root.style.setProperty(`--${key}`, value);
  const paint = value => theme.colors[value] ?? value;
  const variables = { metal: 'metal', control: 'control', rail: 'rail-fill', masthead: 'masthead-fill', table: 'table-fill' };
  for (const key of materialNames) {
    const material = theme.materials[key];
    const fill = enabled ? `linear-gradient(${material.angle}deg, ${material.stops.map(stop => `${paint(stop.color)} ${stop.at}%`).join(', ')})` :
      theme.colors[key === 'rail' ? 'rail' : 'surface'];
    root.style.setProperty(`--${variables[key]}`, fill);
  }
  const grid = theme.materials.grid;
  root.style.setProperty('--canvas-fill', enabled && grid.enabled ?
    `repeating-linear-gradient(0deg, transparent 0 ${grid.size - 1}px, ${grid.color} ${grid.size - 1}px ${grid.size}px), ` +
    `repeating-linear-gradient(90deg, transparent 0 ${grid.size - 1}px, ${grid.color} ${grid.size - 1}px ${grid.size}px), ${theme.colors.canvas}` : theme.colors.canvas);
  document.querySelector('[data-theme-logo]')?.replaceChildren(themeLogo(theme, !enabled));
  const favicon = document.querySelector('link[rel="icon"]');
  if (favicon) favicon.href = `data:image/svg+xml,${encodeURIComponent(new XMLSerializer().serializeToString(themeLogo(theme, !enabled)))}`;
  tell();
}
export function initializeAppearance() {
  if (ready) return ready;
  restore(); apply();
  window.addEventListener('storage', event => {
    if (event.key !== STORAGE_KEY && event.key !== null) return;
    restore(); apply();
  });
  ready = (async () => {
    try {
      const response = await fetch('/static/themes.json');
      if (!response.ok) throw Error('Theme catalogue is unavailable.');
      const data = await response.json();
      if (!Array.isArray(data) || data.length > 100) throw Error('Invalid theme catalogue.');
      const collection = [...classics.map(validateTheme), ...data.map(validateTheme)];
      if (new Set(collection.map(theme => theme.id)).size !== collection.length) throw Error('Duplicate built-in theme id.');
      builtins = collection;
      restore(); apply();
    } catch {
      message = 'The extra theme collection could not load. Classic themes and imported themes are still available.';
      tell();
    }
  })();
  return ready;
}
export function selectTheme(id) {
  if (![...builtins, ...custom].some(theme => theme.id === id)) throw Error('Theme is unavailable.');
  selected = id; persist(); apply();
}
export function setFlatMaterials(value) { flat = Boolean(value); persist(); apply(); }
export function importTheme(source) {
  const theme = parseTheme(source);
  if (builtins.some(item => item.id === theme.id)) throw Error('This id belongs to a built-in theme. Give your theme a new id before importing.');
  const existing = custom.findIndex(item => item.id === theme.id);
  if (existing < 0 && custom.length >= 32) throw Error('This browser has 32 custom themes. Remove one before importing another.');
  if (existing < 0) custom.push(theme); else custom[existing] = theme;
  selected = theme.id; persist(); apply();
  return theme.name;
}
export function removeTheme() {
  if (!custom.some(theme => theme.id === selected)) return;
  custom = custom.filter(theme => theme.id !== selected); selected = 'classic-light'; persist(); apply();
}
export function resetAppearance() { selected = 'classic-light'; flat = false; persist(); apply(); }
export function exportTheme() {
  const theme = copy(currentTheme());
  if (flat) theme.materials.enabled = false;
  return `${JSON.stringify(theme, null, 2)}\n`;
}
export function terminalTheme() {
  const colors = currentTheme().colors;
  return { background: colors['terminal-bg'], foreground: colors['terminal-ink'], cursor: colors['terminal-cursor'] };
}
