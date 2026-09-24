// SPDX-License-Identifier: Apache-2.0
// Read bounded output chunks and keep a finite, text-only browser view.
import { request } from './api.js';
import { button, bytes, el, errorPanel, notice } from './components.js';

export function jobLogs(operationId, nodeId) {
  let active = true, loading = false, offset = 0, generation = 0, timer, text = '', trimmed = false;
  let decoder = new TextDecoder('utf-8');
  const stream = el('select', { id: 'job-log-stream' }, el('option', { value: 'stdout' }, 'Standard output'),
    el('option', { value: 'stderr' }, 'Standard error'));
  const content = el('pre', { class: 'job-output', tabindex: '0', 'aria-label': 'Job output' }, 'No output loaded.');
  const status = el('div');
  const progress = el('p', { class: 'muted' });
  const follow = el('input', { type: 'checkbox', id: 'job-log-follow', checked: true });
  const next = button('Read next output', () => load());
  const restart = button('Read from start', () => reset());
  const element = el('section', { class: 'job-log-section', 'aria-label': 'Job logs' }, el('h3', {}, 'Job output'),
    el('div', { class: 'job-log-controls' }, el('div', {}, el('label', { for: stream.id }, 'Output stream'), stream),
      el('label', { class: 'check-label', for: follow.id }, follow, 'Follow output'), el('div', { class: 'actions' }, restart, next)),
    status, progress, content);
  function reset() {
    generation++; loading = false; clearTimeout(timer); offset = 0; text = ''; trimmed = false;
    decoder = new TextDecoder('utf-8'); content.textContent = 'No output loaded.'; load();
  }
  stream.addEventListener('change', reset);
  follow.addEventListener('change', () => { clearTimeout(timer); if (follow.checked) load(); });
  async function load() {
    if (!active || loading) return;
    loading = true; next.disabled = true; clearTimeout(timer);
    const current = generation;
    try {
      const result = await request(`/operations/${encodeURIComponent(operationId)}/logs/${encodeURIComponent(nodeId)}?stream=${stream.value}&offset=${offset}&limit=65536`);
      if (!active || current !== generation) return;
      const raw = Uint8Array.from(atob(result.data_base64), character => character.charCodeAt(0));
      if (raw.length > 65536 || !Number.isSafeInteger(result.next_offset) || result.next_offset < offset) {
        throw new Error('The service returned an invalid output chunk.');
      }
      const previous = offset;
      offset = result.next_offset;
      text += decoder.decode(raw, { stream: !result.complete || offset < result.total_bytes });
      if (text.length > 65536) { text = text.slice(-65536); trimmed = true; }
      content.textContent = text || (result.complete ? 'No output was recorded.' : 'No output yet.');
      status.replaceChildren();
      if (trimmed) status.append(notice('The browser shows only the latest 65,536 characters. Use Read from start to inspect earlier output.', 'warning'));
      if (result.dropped_bytes > 0) status.append(notice(`${bytes(result.dropped_bytes)} were discarded after the remote output limit.`, 'warning'));
      progress.textContent = `${bytes(offset)} read of ${bytes(result.total_bytes)} retained / ${result.complete ? 'Stream complete' : 'Output may continue'}`;
      if (follow.checked && (!result.complete || offset < result.total_bytes)) {
        timer = setTimeout(load, offset > previous && offset < result.total_bytes ? 250 : 2000);
      }
    } catch (error) {
      if (!active || current !== generation) return;
      if ([401, 403].includes(error.status)) { text = ''; content.textContent = ''; follow.checked = false; }
      status.replaceChildren(errorPanel(error, load));
      if ((error.status === 0 || error.status === 429 || error.status >= 500) && follow.checked) {
        timer = setTimeout(load, 5000);
      }
    } finally {
      if (current === generation) { loading = false; next.disabled = false; }
    }
  }
  load();
  return { element, dispose() { active = false; generation++; clearTimeout(timer); text = ''; } };
}
