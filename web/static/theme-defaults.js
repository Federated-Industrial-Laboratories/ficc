// SPDX-License-Identifier: Apache-2.0
// Define the light and PRISM Graphite palettes and declarative material defaults.
export const palettes = {
  light: {
    canvas: '#d9dcde', white: '#f6f4ef', paper: '#ffffff', surface: '#e6e9ec', rail: '#dce0e4',
    ink: '#202327', muted: '#505862', orange: '#d97a12', accent: '#a35b09', 'orange-light': '#fff0db',
    line: '#a2a8ae', frame: '#778794', brand: '#334b60', dark: '#30363d', 'status-ink': '#ffffff',
    highlight: '#ffffff', shadow: '#30363d25', green: '#24583d', red: '#8f2923', warning: '#76400b',
    info: '#24445c', 'info-bg': '#eff6fb', 'warning-bg': '#fff4e5', 'error-bg': '#fcefed',
    focus: '#145f97', 'on-accent': '#202327', 'on-danger': '#ffffff',
    'terminal-bg': '#242a31', 'terminal-ink': '#f6f4ef', 'terminal-cursor': '#f3a94e', overlay: '#1e283880',
  },
  dark: {
    canvas: '#1c252d', white: '#242c33', paper: '#29343d', surface: '#303b44', rail: '#2e3943',
    ink: '#eef2f5', muted: '#b6c6d2', orange: '#de943d', accent: '#efb368', 'orange-light': '#483b2b',
    line: '#657580', frame: '#738591', brand: '#deebf5', dark: '#171e24', 'status-ink': '#eef2f5',
    highlight: '#7b8b97', shadow: '#00000077', green: '#9ad5b3', red: '#ffaca5', warning: '#efc080',
    info: '#b6d9f2', 'info-bg': '#263c4c', 'warning-bg': '#433628', 'error-bg': '#492e30',
    focus: '#efb368', 'on-accent': '#201b15', 'on-danger': '#301414',
    'terminal-bg': '#171e24', 'terminal-ink': '#eef2f5', 'terminal-cursor': '#efb368', overlay: '#080d14b3',
  },
};

const gradient = (angle, pairs) => ({ angle, stops: pairs.map(([color, at]) => ({ color, at })) });
export const materials = {
  enabled: true,
  metal: gradient(180, [['paper', 0], ['surface', 21], ['rail', 49], ['surface', 51], ['rail', 100]]),
  control: gradient(180, [['paper', 0], ['surface', 100]]),
  rail: gradient(90, [['rail', 0], ['surface', 57], ['rail', 100]]),
  masthead: gradient(115, [['paper', 0], ['rail', 57], ['paper', 77], ['surface', 100]]),
  table: gradient(180, [['paper', 0], ['surface', 100]]),
  grid: { enabled: true, size: 40, color: '#717c8710' },
};

export const classics = [
  { version: 1, id: 'classic-light', name: 'Classic Light', scheme: 'light',
    description: 'The original silver console, warm paper and industrial orange.',
    materials: {
      metal: gradient(180, [['#ffffff', 0], ['#e6e8e9', 21], ['#b9bfc5', 49], ['#e3e6e8', 51], ['#bec4ca', 100]]),
      control: gradient(180, [['#ffffff', 0], ['#e4e7e9', 100]]),
      rail: gradient(90, [['#d6dade', 0], ['#f2f3f4', 57], ['#d9dde0', 100]]),
      masthead: gradient(115, [['#ffffff', 0], ['#e0e4e6', 57], ['#fdfdfd', 77], ['#c1c7cd', 100]]),
      table: gradient(180, [['#f5f7f8', 0], ['#dce2e7', 100]]),
    } },
  { version: 1, id: 'classic-dark', name: 'Classic Dark', scheme: 'dark',
    description: 'PRISM Graphite: blue-grey metal, pale text and warm orange.',
    materials: {
      metal: gradient(180, [['#72818d', 0], ['#4b5a66', 23], ['#35434e', 49], ['#576671', 51], ['#3d4b56', 100]]),
      control: gradient(180, [['#495763', 0], ['#303d47', 100]]),
      rail: gradient(90, [['#28343e', 0], ['#35424c', 57], ['#293640', 100]]),
      masthead: gradient(115, [['paper', 0], ['rail', 57], ['paper', 77], ['line', 100]]),
    } },
];
