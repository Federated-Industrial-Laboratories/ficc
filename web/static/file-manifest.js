// SPDX-License-Identifier: Apache-2.0
// Commit the whole browser source using native bounded SHA-256 operations.
const chunkSize = 262144;
const hash = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const hex = bytes => [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');

export async function sourceManifest(file, progress = () => {}, cancelled = () => false) {
  if (!Number.isSafeInteger(file.size) || file.size < 0) throw Error('This browser cannot address that file size exactly. Use a registered filesystem source.');
  let chain = await hash(new TextEncoder().encode(`ficc-upload-v1:${file.size}:${chunkSize}`));
  for (let offset = 0; offset < file.size; offset += chunkSize) {
    if (cancelled()) throw Error('Source verification was cancelled.');
    const block = await file.slice(offset, offset + chunkSize).arrayBuffer();
    const joined = new Uint8Array(64);
    joined.set(chain); joined.set(await hash(block), 32);
    chain = await hash(joined);
    progress(Math.min(file.size, offset + chunkSize));
  }
  return { algorithm: 'sha256-chain-v1', digest: hex(chain) };
}
