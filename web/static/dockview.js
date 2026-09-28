// SPDX-License-Identifier: Apache-2.0
// Load the pinned browser bundle with its required structural styles.
import './vendor/dockview/dockview-core.min.js';

const core = globalThis['dockview-core'];
export const { createDockview, FloatingGroupModule, registerModules, themeLight } = core;
