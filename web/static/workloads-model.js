// SPDX-License-Identifier: Apache-2.0
// Format contributor offers and validate bounded, immutable output pages.
export const terminal = new Set(['succeeded', 'failed', 'cancelled', 'expired']);
export const pageSize = 65536;
export const limitFields = [
  ['cpu_millis', 'CPU (millicores)', 1000], ['memory_bytes', 'Memory (bytes)', 268435456],
  ['swap_bytes', 'Swap (bytes)', 0], ['processes', 'Processes', 64],
  ['storage_bytes', 'Storage (bytes)', 268435456], ['storage_inodes', 'Storage inodes', 16384],
];
export const runtimeKey = value => JSON.stringify([
  value.provider, value.package_digest, value.image_digest, value.isolation, value.network,
]);
export const nodeLabel = value => `Node ${value.snapshot.node_id.slice(0, 6)}...${value.snapshot.node_id.slice(-6)}`;
export const words = value => value ? value.replaceAll('_', ' ') : 'None';
export function commonRuntimes(offers) {
  if (!offers.length) return [];
  return offers[0].snapshot.offer.runtimes.filter(runtime => offers.every(value =>
    value.snapshot.offer.runtimes.some(other => runtimeKey(other) === runtimeKey(runtime))));
}
export function schedule(windows) {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const clock = value => `${String(Math.floor(value / 60)).padStart(2, '0')}:${String(value % 60).padStart(2, '0')}`;
  return windows.length ? windows.map(value => `${value.weekdays.map(day => days[day]).join(', ')} ${clock(value.start_minute)}-${clock(value.end_minute)} UTC`).join('; ') : 'Any time (UTC)';
}
export function readPage(value, job, object, offset, previous = null) {
  const row = value.results?.[0], attempt = job.attempt;
  const observed = attempt?.observed || attempt?.outcome;
  if (!row || value.results.length !== 1 || !attempt || !observed || value.attempt_id !== attempt.id ||
      row.attempt_id !== attempt.id || row.generation !== attempt.generation || row.plan_digest !== observed.plan_digest ||
      row.object !== object || row.offset !== offset || row.ok !== true ||
      !Number.isSafeInteger(row.next_offset) || !Number.isSafeInteger(row.total_bytes) ||
      row.total_bytes < 0 || !/^sha256:[a-f0-9]{64}$/.test(row.identity) ||
      typeof row.complete !== 'boolean' || typeof row.eof !== 'boolean' || typeof row.data !== 'string' ||
      row.data.length > 87384 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(row.data)) {
    throw new Error('The output response does not match this attempt and byte range. Refresh the workload before reading again.');
  }
  const data = Uint8Array.from(atob(row.data), character => character.charCodeAt(0));
  if (data.length > pageSize || row.next_offset !== offset + data.length || row.next_offset > row.total_bytes ||
      row.eof !== (row.next_offset === row.total_bytes) ||
      previous && (row.identity !== previous.identity || row.total_bytes < previous.total_bytes ||
        previous.complete && (!row.complete || row.total_bytes !== previous.total_bytes))) {
    throw new Error('The output object changed or returned an invalid range. Read from the start to inspect the current object.');
  }
  return { ...row, bytes: data };
}
