// SPDX-License-Identifier: Apache-2.0
// Validate bounded theme data before it can set colors or create vector paths.
import { palettes, materials } from './theme-defaults.js';

export const MAX_THEME_BYTES = 65536;
export const materialNames = ['metal', 'control', 'rail', 'masthead', 'table'];
const has = (object, key) => Object.hasOwn(object, key);
function object(value, keys, where) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !keys.includes(key))) throw Error(`${where}: unsupported field or object.`);
  return value;
}
function text(value, limit, where) {
  if (typeof value !== 'string' || !value.trim() || value.length > limit || /[\x00-\x1f\x7f]/.test(value)) {
    throw Error(`${where}: enter 1 to ${limit} characters without control characters.`);
  }
  return value.trim();
}
function number(value, low, high, where) {
  if (!Number.isFinite(value) || value < low || value > high) throw Error(`${where}: expected ${low} to ${high}.`);
  return value;
}
function boolean(value, where) {
  if (typeof value !== 'boolean') throw Error(`${where}: expected true or false.`);
  return value;
}
function color(value, alpha = false) {
  if (typeof value !== 'string' || !(alpha ? /^#[\da-f]{6}([\da-f]{2})?$/i : /^#[\da-f]{6}$/i).test(value)) {
    throw Error('Colors must use #RRGGBB hex notation; only shadows, overlays and grid colors accept alpha.');
  }
  return value.toLowerCase();
}
function paint(value, colors, none = false) {
  if (none && value === 'none' || typeof value === 'string' && has(colors, value)) return value;
  return color(value);
}
function gradient(value, colors, where) {
  object(value, ['angle', 'stops'], where);
  const angle = number(value.angle, 0, 360, `${where}.angle`);
  if (!Array.isArray(value.stops) || value.stops.length < 2 || value.stops.length > 8) {
    throw Error(`${where}: use 2 to 8 gradient stops.`);
  }
  let previous = -1;
  const stops = value.stops.map(stop => {
    object(stop, ['color', 'at'], `${where}.stops`);
    const at = number(stop.at, 0, 100, `${where}.stops.at`);
    if (at < previous) throw Error(`${where}: gradient stops must be in ascending order.`);
    previous = at;
    return { color: paint(stop.color, colors), at };
  });
  return { angle, stops };
}
function logo(value, colors) {
  object(value, ['type', 'color', 'secondary', 'viewBox', 'paths'], 'logo');
  if (!['cluster', 'orbit', 'monogram', 'paths'].includes(value.type)) throw Error('logo.type is not supported.');
  const result = { type: value.type, color: paint(value.color ?? 'orange', colors),
    secondary: paint(value.secondary ?? 'brand', colors) };
  if (value.type !== 'paths') {
    if (has(value, 'viewBox') || has(value, 'paths')) throw Error('Custom paths require logo.type paths.');
    return result;
  }
  if (!Array.isArray(value.viewBox) || value.viewBox.length !== 4) throw Error('logo.viewBox needs four numbers.');
  result.viewBox = value.viewBox.map((item, index) => number(item, index < 2 ? -4096 : 1, 4096, 'logo.viewBox'));
  if (!Array.isArray(value.paths) || !value.paths.length || value.paths.length > 64) throw Error('Use 1 to 64 logo paths.');
  result.paths = value.paths.map(path => {
    object(path, ['d', 'fill', 'stroke', 'strokeWidth'], 'logo.paths');
    const d = text(path.d, 4096, 'logo path');
    if (!/^[Mm]/.test(d) || !/^[MmLlHhVvCcSsQqTtAaZzEe\d.,+\s-]+$/.test(d)) throw Error('Invalid SVG path data.');
    return { d, fill: paint(path.fill ?? 'orange', colors, true), stroke: paint(path.stroke ?? 'none', colors, true),
      strokeWidth: number(path.strokeWidth ?? 1, 0, 32, 'logo strokeWidth') };
  });
  return result;
}

export function validateTheme(value) {
  object(value, ['version', 'id', 'name', 'description', 'scheme', 'colors', 'materials', 'logo'], 'theme');
  if (new TextEncoder().encode(JSON.stringify(value)).length > MAX_THEME_BYTES) throw Error('Theme exceeds 64 KiB.');
  if (value.version !== 1) throw Error('Unsupported theme version. Expected version 1.');
  if (!['light', 'dark'].includes(value.scheme)) throw Error('Theme scheme must be light or dark.');
  const id = text(value.id, 48, 'Theme id');
  if (!/^[a-z][a-z0-9-]*$/.test(id)) throw Error('Theme id needs lowercase letters, digits or hyphens.');
  const colors = { ...palettes[value.scheme] };
  if (has(value, 'colors')) {
    object(value.colors, Object.keys(colors), 'colors');
    for (const [key, item] of Object.entries(value.colors)) colors[key] = color(item, ['shadow', 'overlay'].includes(key));
  }
  const material = structuredClone(materials);
  if (has(value, 'materials')) {
    object(value.materials, ['enabled', ...materialNames, 'grid'], 'materials');
    if (has(value.materials, 'enabled')) material.enabled = boolean(value.materials.enabled, 'materials.enabled');
    for (const key of materialNames) {
      if (has(value.materials, key)) material[key] = gradient(value.materials[key], colors, `materials.${key}`);
    }
    if (has(value.materials, 'grid')) {
      object(value.materials.grid, ['enabled', 'size', 'color'], 'materials.grid');
      for (const [key, item] of Object.entries(value.materials.grid)) {
        material.grid[key] = key === 'enabled' ? boolean(item, 'grid.enabled') :
          key === 'size' ? number(item, 8, 160, 'grid.size') : color(item, true);
      }
    }
  }
  const result = { version: 1, id, name: text(value.name, 64, 'Theme name'),
    description: value.description === undefined || value.description === '' ? '' : text(value.description, 240, 'Description'),
    scheme: value.scheme, colors, materials: material,
    logo: logo(value.logo ?? { type: 'cluster' }, colors) };
  if (new TextEncoder().encode(`${JSON.stringify(result, null, 2)}\n`).length > MAX_THEME_BYTES) {
    throw Error('Theme with inherited defaults exceeds 64 KiB. Reduce the logo paths.');
  }
  return result;
}

export function parseTheme(source) {
  if (new TextEncoder().encode(source).length > MAX_THEME_BYTES) throw Error('Theme exceeds 64 KiB.');
  let value;
  try { value = JSON.parse(source); } catch { throw Error('The file is not valid JSON.'); }
  return validateTheme(value);
}
