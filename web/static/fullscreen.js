// SPDX-License-Identifier: Apache-2.0
// Expand a host surface while preserving its element, layout and input ownership.
export function fullscreen(surface, changed = () => {}) {
  const doc = surface.ownerDocument;
  let expanded = false, disposed = false;
  const update = () => {
    if (disposed) return;
    surface.classList.toggle('workspace-expanded', expanded || doc.fullscreenElement === surface);
    surface.dispatchEvent(new Event('ficc-release-input', { bubbles: true }));
    changed({ expanded, fullscreen: doc.fullscreenElement === surface });
  };
  const escape = event => {
    if (event.key === 'Escape' && expanded && !doc.fullscreenElement) { expanded = false; update(); }
  };
  doc.addEventListener('fullscreenchange', update);
  doc.addEventListener('keydown', escape);
  return {
    expand() { expanded = !expanded; update(); },
    async toggle() {
      if (doc.fullscreenElement === surface) await doc.exitFullscreen();
      else await surface.requestFullscreen();
      update();
    },
    dispose() {
      disposed = true; doc.removeEventListener('fullscreenchange', update); doc.removeEventListener('keydown', escape);
      if (doc.fullscreenElement === surface) void doc.exitFullscreen().catch(() => {});
      surface.classList.remove('workspace-expanded');
    },
  };
}
