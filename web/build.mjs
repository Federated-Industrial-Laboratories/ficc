// SPDX-License-Identifier: Apache-2.0
// Copy local web assets into the Python package; exit zero on success.
import { cp, mkdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

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
const dockview = `${destination}/vendor/dockview`;
await mkdir(dockview, { recursive: true });
for (const file of ['dist/dockview-core.min.js', 'LICENCE.md']) {
  const input = fileURLToPath(new URL(`./node_modules/dockview-core/${file}`, import.meta.url));
  await cp(input, `${dockview}/${file.split('/').at(-1)}`);
}
await promisify(execFile)('python3', [
  fileURLToPath(new URL('../tools/viewer_assets.py', import.meta.url)),
  '--cache', fileURLToPath(new URL('./node_modules/.ficc-viewer/', import.meta.url)),
  '--output', `${destination}/vendor/guacamole`,
], { timeout: 180000, maxBuffer: 8192 });
console.log('Local web assets built.');
