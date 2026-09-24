// SPDX-License-Identifier: Apache-2.0
// Arrange stable terminal leaves in a bounded binary split tree.
import { el } from './components.js';

const GAP = 8, MIN_WIDTH = 280, MIN_HEIGHT = 280;
export function terminalLayout(canvas, changed) {
  let root = null, nextId = 0, active = true, frame;
  const bars = new Map();
  function leaves(node = root) { return !node ? [] : node.tile ? [node.tile] : [...leaves(node.first), ...leaves(node.second)]; }
  function replace(node, target, replacement) {
    if (node === target) return replacement;
    if (!node?.tile) { node.first = replace(node.first, target, replacement); node.second = replace(node.second, target, replacement); }
    return node;
  }
  function minimum(node) {
    if (node.tile) return { width: MIN_WIDTH, height: MIN_HEIGHT };
    const a = minimum(node.first), b = minimum(node.second), across = node.axis === 'right';
    return { width: across ? a.width + b.width + GAP : Math.max(a.width, b.width),
      height: across ? Math.max(a.height, b.height) : a.height + b.height + GAP };
  }
  function box(element, x, y, width, height) {
    Object.assign(element.style, { left: `${x}px`, top: `${y}px`, width: `${width}px`, height: `${height}px` });
  }
  function divider(node) {
    const across = node.axis === 'right';
    const bar = el('div', { class: `terminal-divider ${node.axis}`, role: 'separator', tabindex: '0',
      'aria-label': across ? 'Resize side by side terminals' : 'Resize stacked terminals',
      'aria-orientation': across ? 'vertical' : 'horizontal', 'aria-valuemin': 0, 'aria-valuemax': 100 });
    let drag;
    bar.addEventListener('pointerdown', event => {
      if (event.button !== 0) return;
      drag = { start: across ? event.clientX : event.clientY, ratio: node.ratio };
      bar.setPointerCapture(event.pointerId); bar.focus(); event.preventDefault();
    });
    bar.addEventListener('pointermove', event => {
      if (!drag || !bar.hasPointerCapture(event.pointerId)) return;
      const rect = canvas.getBoundingClientRect(), scale = across ? rect.width / canvas.offsetWidth : rect.height / canvas.offsetHeight;
      if (!Number.isFinite(scale) || scale <= 0 || !node.span) return;
      node.ratio = drag.ratio + ((across ? event.clientX : event.clientY) - drag.start) / scale / node.span;
      schedule();
    });
    bar.addEventListener('lostpointercapture', () => { drag = null; });
    bar.addEventListener('pointerup', event => { if (bar.hasPointerCapture(event.pointerId)) bar.releasePointerCapture(event.pointerId); });
    bar.addEventListener('keydown', event => {
      const keys = across ? ['ArrowLeft', 'ArrowRight'] : ['ArrowUp', 'ArrowDown'];
      if (!keys.includes(event.key) && !['Home', 'End'].includes(event.key)) return;
      node.ratio = event.key === 'Home' ? 0 : event.key === 'End' ? 1 : node.ratio + (event.key === keys[0] ? -0.05 : 0.05);
      event.preventDefault(); schedule();
    });
    bars.set(node.id, bar); canvas.append(bar); return bar;
  }
  function place(node, x, y, width, height) {
    if (node.tile) { box(node.tile.element, x, y, width, height); return; }
    const across = node.axis === 'right', dimension = across ? 'width' : 'height';
    const a = minimum(node.first)[dimension], b = minimum(node.second)[dimension];
    node.span = (across ? width : height) - GAP;
    node.ratio = Math.max(a / node.span, Math.min(1 - b / node.span, node.ratio));
    const cut = Math.round(node.span * node.ratio), rest = node.span - cut;
    const bar = bars.get(node.id) ?? divider(node);
    bar.hidden = false; bar.setAttribute('aria-valuenow', String(Math.round(node.ratio * 100)));
    bar.setAttribute('aria-valuemin', String(Math.round(a / node.span * 100)));
    bar.setAttribute('aria-valuemax', String(Math.round((1 - b / node.span) * 100)));
    box(bar, across ? x + cut : x, across ? y : y + cut, across ? GAP : width, across ? height : GAP);
    place(node.first, x, y, across ? cut : width, across ? height : cut);
    place(node.second, across ? x + cut + GAP : x, across ? y : y + cut + GAP, across ? rest : width, across ? height : rest);
  }
  let zoom = null;
  function render() {
    if (!active || !root || !canvas.parentElement.clientWidth) return;
    const min = zoom ? { width: MIN_WIDTH, height: MIN_HEIGHT } : minimum(root);
    const width = Math.max(min.width, canvas.parentElement.clientWidth), height = Math.max(min.height, canvas.parentElement.clientHeight);
    canvas.style.width = `${width}px`; canvas.style.height = `${height}px`;
    for (const tile of leaves()) tile.element.hidden = Boolean(zoom && tile !== zoom);
    for (const bar of bars.values()) bar.hidden = Boolean(zoom);
    if (zoom) box(zoom.element, 0, 0, width, height); else place(root, 0, 0, width, height);
    changed();
  }
  function schedule() { cancelAnimationFrame(frame); frame = requestAnimationFrame(render); }
  const observer = new ResizeObserver(schedule); observer.observe(canvas.parentElement);
  return {
    leaves, render: schedule,
    add(tile, focused, axis = 'right') {
      const leaf = { tile };
      if (!root) root = leaf;
      else {
        const target = find(root, focused) ?? find(root, leaves().at(-1));
        root = replace(root, target, { id: ++nextId, axis, ratio: 0.5, first: target, second: leaf });
      }
      zoom = null; canvas.append(tile.element); schedule();
    },
    remove(tile) {
      let neighbour = null;
      function prune(node) {
        if (node.tile) return node.tile === tile ? null : node;
        node.first = prune(node.first); node.second = prune(node.second);
        if (!node.first || !node.second) {
          const sibling = node.first ?? node.second;
          neighbour ??= leaves(sibling)[0] ?? null;
          bars.get(node.id)?.remove(); bars.delete(node.id); return sibling;
        }
        return node;
      }
      if (root) root = prune(root);
      tile.element.remove(); if (zoom === tile) zoom = null; schedule(); return neighbour;
    },
    zoom(tile) { zoom = zoom === tile ? null : tile; schedule(); return zoom; },
    get zoomed() { return zoom; },
    dispose() { active = false; cancelAnimationFrame(frame); observer.disconnect(); bars.clear(); root = null; },
  };
}
function find(node, tile) { return !node ? null : node.tile ? node.tile === tile ? node : null : find(node.first, tile) ?? find(node.second, tile); }
