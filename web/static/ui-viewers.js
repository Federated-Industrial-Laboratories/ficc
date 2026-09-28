// SPDX-License-Identifier: Apache-2.0
// Open opaque host display references without exposing provider addresses.
import { button, el } from './components.js';
import { viewer } from './viewer.js';

export function viewers() {
  const element = el('div', { class: 'module-viewers' });
  let active, disposed = false;
  return { element,
    controls(result) {
      const refs = [...new Set((Array.isArray(result?.results) ? result.results : [])
        .map(item => item?.data?.viewer_ref).filter(value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value)))].slice(0, 4);
      return refs.map(ref => button('Open display in FICC', () => {
        if (disposed) return;
        active?.dispose(); active = viewer(ref); element.replaceChildren(active.element);
        active.element.scrollIntoView({ block: 'nearest' });
      }));
    },
    setVisible(value) { if (!value) active?.release(); },
    dispose() { disposed = true; active?.dispose(); element.remove(); },
  };
}
