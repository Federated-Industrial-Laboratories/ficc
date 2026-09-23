// SPDX-License-Identifier: Apache-2.0
// Copy local web assets into the Python package; exit zero on success.
import { cp, mkdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('./static/', import.meta.url));
const destination = fileURLToPath(new URL('../src/ficc/static/', import.meta.url));
await mkdir(destination, { recursive: true });
await rm(destination, { recursive: true });
await cp(source, destination, { recursive: true, errorOnExist: true });
console.log('Local web assets built.');
