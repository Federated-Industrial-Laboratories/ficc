// SPDX-License-Identifier: Apache-2.0
// Serve one bounded host batch without network or browser access.
import { readSync, writeSync } from 'node:fs';
const MAX_FRAME = 1024 * 1024;

function read(size) {
  const value = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = readSync(0, value, offset, size - offset, null);
    if (!count) throw Error('Incomplete frame');
    offset += count;
  }
  return value;
}

function frame(account = () => {}) {
  const size = read(4).readUInt32BE();
  if (size < 1 || size > MAX_FRAME) throw Error('Invalid frame size');
  account(size + 4);
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(read(size)));
}

function encode(value) {
  const bytes = Buffer.from(JSON.stringify(value), 'utf8');
  if (!bytes.length || bytes.length > MAX_FRAME) throw Error('Invalid output size');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(bytes.length);
  return Buffer.concat([header, bytes]);
}

function object(value, keys) {
  return value && !Array.isArray(value) && typeof value === 'object' &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

export function serve(handler) {
  try {
    const hello = frame(), request = frame();
    if (readSync(0, Buffer.alloc(1), 0, 1, null) ||
        !object(hello, ['version', 'type', 'host_api']) || hello.version !== 1 ||
        hello.type !== 'hello' || hello.host_api !== 1 ||
        !object(request, ['version', 'type', 'id', 'action', 'targets', 'parameters']) ||
        request.version !== 1 || request.type !== 'invoke' ||
        typeof request.id !== 'string' || !request.id.length || request.id.length > 128 ||
        typeof request.action !== 'string' || !request.parameters ||
        Array.isArray(request.parameters) || typeof request.parameters !== 'object') throw Error('Invalid request');
    const targets = request.targets;
    if (!Array.isArray(targets) || !targets.length || targets.length > 64 ||
        targets.some(t => typeof t !== 'string' || !t.length || [...t].length > 128 || /[\x00/\\:]/.test(t)) ||
        new Set(targets).size !== targets.length) throw Error('Invalid targets');
    const output = Buffer.concat([encode({ version: 1, type: 'hello', protocol: 1 }),
      encode({ version: 1, type: 'result', id: request.id, results: handler(request) })]);
    let offset = 0;
    while (offset < output.length) offset += writeSync(1, output, offset, output.length - offset);
  } catch {
    process.stderr.write('Invalid module request or result.\n');
    process.exitCode = 1;
  }
}

const ID = /^[0-9a-f]{32}$/, NAME = /^[a-z][a-z0-9_.-]{0,95}$/;
function bounded(value, depth = 0) {
  if (depth > 12) throw Error('Excessive nesting');
  if (typeof value === 'string' && ([...value].length > 65536 || value.includes('\0'))) throw Error('Invalid text');
  if (typeof value === 'number' && (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))) throw Error('Invalid number');
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length > 256) throw Error('Excessive collection');
    for (const [key, item] of entries) {
      if ([...key].length > 240 || key.includes('\0')) throw Error('Invalid key');
      bounded(item, depth + 1);
    }
  } else if (value !== null && !['string', 'number', 'boolean'].includes(typeof value)) throw Error('Invalid JSON value');
}
function targets(value) {
  if (!Array.isArray(value) || !value.length || value.length > 64 ||
      value.some(t => typeof t !== 'string' || !t.length || [...t].length > 128 || /[\x00/\\:]/.test(t)) ||
      new Set(value).size !== value.length) throw Error('Invalid targets');
}
function results(value, selected) {
  bounded(value);
  if (!Array.isArray(value) || value.length !== selected.length) throw Error('Invalid results');
  value.forEach((row, index) => {
    if (!object(row, ['target', Object.hasOwn(row, 'data') ? 'data' : 'error']) || row.target !== selected[index]) throw Error('Invalid result identity');
    if (Object.hasOwn(row, 'error') && (!object(row.error, ['code', 'message']) ||
        typeof row.error.code !== 'string' || !NAME.test(row.error.code) ||
        typeof row.error.message !== 'string' || [...row.error.message].length > 1024)) throw Error('Invalid error');
  });
  return value;
}

export function serveBroker(handler) {
  try {
    let incoming = 0, outgoing = 0, calls = 0, failed = false;
    const account = size => { if ((incoming += size) > 2 * (MAX_FRAME + 4)) throw Error('Input limit'); };
    const receive = () => { const value = frame(account); bounded(value); return value; };
    const send = value => {
      bounded(value);
      const data = encode(value);
      if ((outgoing += data.length) > 2 * (MAX_FRAME + 4)) throw Error('Output limit');
      let offset = 0;
      while (offset < data.length) offset += writeSync(1, data, offset, data.length - offset);
    };
    const hello = receive(), request = receive();
    if (!object(hello, ['version', 'type', 'host_api']) || hello.version !== 2 ||
        hello.type !== 'hello' || hello.host_api !== 1 ||
        !object(request, ['version', 'type', 'id', 'action', 'targets', 'parameters']) ||
        request.version !== 2 || request.type !== 'invoke' || typeof request.id !== 'string' ||
        !ID.test(request.id) || typeof request.action !== 'string' || !NAME.test(request.action) ||
        !request.parameters || Array.isArray(request.parameters) || typeof request.parameters !== 'object') throw Error('Invalid request');
    targets(request.targets);
    const frozen = [...request.targets], invocation = request.id;
    send({version: 2, type: 'hello', protocol: 2});
    const broker = (primitive, selected, parameters = {}) => {
      try {
        if (failed || ++calls > 16 || typeof primitive !== 'string' || !NAME.test(primitive)) throw Error('Invalid call');
        targets(selected);
        if (selected.some(target => !frozen.includes(target))) throw Error('Target outside invocation');
        if (!parameters || Array.isArray(parameters) || typeof parameters !== 'object' ||
            Buffer.byteLength(JSON.stringify(parameters)) > 65536) throw Error('Invalid parameters');
        let id = calls.toString(16).padStart(32, '0');
        if (id === invocation) id = 'f' + id.slice(1);
        const expected = [...selected];
        send({version: 2, type: 'broker', id, invocation_id: invocation, primitive, targets: expected, parameters});
        const reply = receive();
        if (!object(reply, ['version', 'type', 'id', 'invocation_id', 'results']) ||
            reply.version !== 2 || reply.type !== 'broker-result' || reply.id !== id ||
            reply.invocation_id !== invocation) throw Error('Cancelled or invalid broker identity');
        return results(reply.results, expected);
      } catch (error) { failed = true; throw error; }
    };
    const value = handler(request, broker);
    if (failed) throw Error('Broker failed');
    send({version: 2, type: 'result', id: invocation, results: results(value, frozen)});
  } catch {
    process.stderr.write('Invalid module request, cancellation or broker result.\n');
    process.exitCode = 1;
  }
}
