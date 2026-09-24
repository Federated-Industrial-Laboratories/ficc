// SPDX-License-Identifier: Apache-2.0
// Copy local web assets into the Python package; exit zero on success.
import { cp, mkdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('./static/', import.meta.url));
const destination = fileURLToPath(new URL('../src/ficc/static/', import.meta.url));
await mkdir(destination, { recursive: true });
await rm(destination, { recursive: true });
await cp(source, destination, { recursive: true, errorOnExist: true });
for (const [name, files] of Object.entries({
  xterm: ['lib/xterm.mjs', 'lib/xterm.mjs.map', 'css/xterm.css', 'LICENSE'],
  'addon-fit': ['lib/addon-fit.mjs', 'lib/addon-fit.mjs.map', 'LICENSE'],
})) {
  const target = `${destination}/vendor/${name}`;
  await mkdir(target, { recursive: true });
  for (const file of files) {
    const input = fileURLToPath(new URL(`./node_modules/@xterm/${name}/${file}`, import.meta.url));
    await cp(input, `${target}/${file.split('/').at(-1)}`);
  }
}
console.log('Local web assets built.');
