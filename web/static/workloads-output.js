// SPDX-License-Identifier: Apache-2.0
// Preview bounded output ranges and publish complete artifacts with durable recovery.
import { allowed } from './api.js';
import { button, bytes, confirmation, el, errorPanel, notice, table } from './components.js';
import { fileDialog } from './file-dialog.js';
import { pageSize, readPage } from './workloads-model.js';

export function workloadOutput(job, send, valid) {
  let active = true, busy = false, version = 0, offset = 0, page = null, identity = null;
  let publicationTimer, publicationLoading = false, dialog = null;
  const published = el('div'), publicationErrors = el('div');
  const object = el('select', { 'aria-label': 'Output object' },
    el('option', { value: 'stdout' }, 'Standard output'), el('option', { value: 'stderr' }, 'Standard error'),
    job.request.job.outputs.map(value => el('option', { value: `output:${value.name}` }, `Output: ${value.name}`)));
  const content = el('pre', { class: 'job-output', tabindex: '0', 'aria-label': 'Workload output page' });
  const metadata = el('p', { class: 'muted', role: 'status' }, 'No output page loaded.'), errors = el('div');
  const first = button('Read from start', () => { identity = null; void read(0); });
  const previous = button('Previous page', () => read(Math.max(0, offset - pageSize)), { disabled: true });
  const next = button('Next page', () => read(page.next_offset), { disabled: true });
  const save = button('Save this byte range', () => {
    if (!active || !valid() || !page || busy) return;
    const url = URL.createObjectURL(new Blob([page.bytes], { type: 'application/octet-stream' }));
    const link = el('a', { href: url, download: `ficc-${job.id}-${object.value.replace(':', '-')}-${page.offset}-${page.next_offset}.bin` });
    document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
  }, { disabled: true });
  const publish = button('Publish complete output', () => publishDialog(), { disabled: true });
  function retained() { return job.attempt && !['released', 'abandoned'].includes(job.attempt.state); }
  function controls() {
    if (!retained()) {
      page = null; content.textContent = '';
      metadata.textContent = 'Retained output was released and is no longer available.';
    }
    first.disabled = busy || !retained(); previous.disabled = busy || !retained() || !page || offset === 0;
    next.disabled = busy || !retained() || !page || page.eof; save.disabled = busy || !page;
    publish.disabled = !retained() || !job.attempt?.observed?.cleanup_confirmed || !allowed('files:write') || !allowed('files:read');
  }
  async function read(start) {
    if (busy || !active || !valid()) return;
    busy = true; const current = ++version, selected = object.value;
    page = null; content.textContent = ''; metadata.textContent = 'Reading a bounded byte range.';
    errors.replaceChildren(); controls();
    try {
      const result = await send(`/workloads/${job.id}/output`, { method: 'POST',
        body: { reads: [{ object: selected, offset: start, length: pageSize }] } });
      if (!active || !valid() || current !== version) return;
      page = readPage(result, job, selected, start, identity); identity = page; offset = start;
      content.textContent = new TextDecoder().decode(page.bytes);
      metadata.textContent = `Bytes ${page.offset}-${page.next_offset} of ${page.total_bytes} (end exclusive). ${page.complete ? 'Object complete.' : 'Object still open; it may grow.'} ${page.eof ? 'At observed end.' : 'More bytes available.'} Identity: ${page.identity}`;
    } catch (error) {
      if (!active || !valid() || current !== version) return;
      page = null; content.textContent = ''; metadata.textContent = 'No verified output page.';
      errors.replaceChildren(errorPanel(error));
    } finally { if (current === version) { busy = false; controls(); } }
  }
  object.addEventListener('change', () => {
    version++; busy = false; page = null; identity = null; offset = 0; content.textContent = '';
    metadata.textContent = 'No output page loaded.'; errors.replaceChildren(); controls();
  });
  async function changePublication(value, operation, discard = false) {
    try {
      await send(`/workloads/${job.id}/artifacts/${value.transfer.id}/${operation}`, {
        method: 'POST', body: operation === 'cancel' ? { discard_partial: discard } : {}, timeout: null });
      if (active && valid()) { publicationErrors.replaceChildren(); await loadPublications(); }
    } catch (error) { if (active && valid()) publicationErrors.replaceChildren(errorPanel(error)); }
  }
  async function loadPublications(before = null) {
    if (!active || !valid() || publicationLoading || !allowed('files:read')) return;
    publicationLoading = true; clearTimeout(publicationTimer);
    try {
      const result = await send(`/workloads/${job.id}/artifacts${before ? `?before=${before}` : ''}`);
      if (!active || !valid()) return;
      const rows = result.publications.map(value => {
        const item = value.transfer.items[0], controls = [];
        const datasetPending = item.state === 'succeeded' && value.dataset_requested && !value.dataset && !value.dataset_cancelled;
        if (allowed('files:write') && (['interrupted', 'unknown'].includes(item.state) || datasetPending)) {
          controls.push(button(item.state === 'unknown' ? 'Reconcile publication' : datasetPending ? 'Retry dataset registration' : 'Resume publication',
            () => changePublication(value, 'resume')));
        }
        if (allowed('files:write') && !['succeeded', 'cancelled', 'unknown'].includes(item.state)) {
          controls.push(button('Cancel and discard partial', () => confirmation('Cancel output publication',
            'Discard this partial copy. A committed destination is preserved. Retained contributor output can be released after cancellation is confirmed.',
            'Cancel publication', () => changePublication(value, 'cancel', true)), { class: 'danger-text' }));
        }
        if (allowed('files:write') && datasetPending) controls.push(button('Skip dataset registration', () => confirmation('Skip dataset registration',
          'Keep the published file and stop registering it as a dataset.', 'Keep file only', () => changePublication(value, 'cancel'))));
        if (value.dataset) controls.push(button('View dataset manifest', async () => {
          const view = fileDialog('Published dataset manifest'); dialog = view;
          try {
            const manifest = await send(`/datasets/${value.dataset.id}`);
            if (view.active() && active && valid()) view.content.append(el('pre', { class: 'job-request' }, JSON.stringify(manifest, null, 2)));
          } catch (error) { if (view.active() && active) view.content.replaceChildren(errorPanel(error)); }
        }));
        const progress = value.phase === 'hashing' ? `Hashing ${bytes(value.hashed_bytes)} / ${bytes(item.size)}` : `${bytes(item.offset)} / ${bytes(item.size)}`;
        return el('tr', {}, el('td', {}, item.name, el('small', { class: 'cell-note' }, value.source.object)),
          el('td', {}, item.state, el('small', { class: 'cell-note' }, value.phase.replaceAll('_', ' '))),
          el('td', {}, progress), el('td', { class: 'wrap transfer-hash' },
            value.dataset ? `Dataset ${value.dataset.id}` : value.dataset_cancelled ? 'File retained; dataset registration skipped.' :
              value.dataset_error?.message || item.error?.message || (item.state === 'succeeded' ? `Verified SHA-256 ${item.sha256}` : 'Verification pending')),
          el('td', {}, el('div', { class: 'actions' }, controls)));
      });
      published.replaceChildren(el('h4', {}, 'Published outputs and recovery'),
        rows.length ? table(['Destination file', 'State', 'Progress', 'Verified result', 'Actions'], rows, 'Workload publications') :
          el('p', { class: 'muted' }, 'No output publications on this page.'),
        before ? button('Latest publications', () => loadPublications()) : null,
        result.next_cursor ? button('Older publications', () => loadPublications(result.next_cursor)) : null);
    } catch (error) { if (active && valid()) publicationErrors.replaceChildren(errorPanel(error)); }
    finally {
      publicationLoading = false;
      if (active && valid() && !before) publicationTimer = setTimeout(loadPublications, 5000);
    }
  }
  async function publishDialog() {
    if (publish.disabled || !active || !valid()) return;
    const selectedObject = object.value, view = fileDialog('Publish workload output'); dialog = view;
    const destination = el('select', { id: 'workload-publication-root' }), folders = el('div'), errors = el('div');
    const name = el('input', { id: 'workload-publication-name', required: true, maxlength: 255,
      value: selectedObject.startsWith('output:') ? selectedObject.slice(7) : `${selectedObject}.log` });
    const register = el('input', { id: 'workload-publication-dataset', type: 'checkbox' });
    const datasetName = el('input', { id: 'workload-publication-dataset-name', maxlength: 120, value: `${job.request.job.name} result` });
    const format = el('select', { id: 'workload-publication-format' }, ['binary', 'csv', 'parquet', 'arrow'].map(value => el('option', { value }, value)));
    const schema = el('textarea', { id: 'workload-publication-schema', rows: 4 }, '{"fields":[],"description":""}');
    const datasetFields = el('fieldset', { hidden: true }, el('legend', {}, 'Dataset version'),
      el('label', { for: datasetName.id }, 'Dataset name'), datasetName, el('label', { for: format.id }, 'Format'), format,
      el('label', { for: schema.id }, 'Explicit schema JSON'), schema);
    register.addEventListener('change', () => { datasetFields.hidden = !register.checked; datasetName.required = register.checked; });
    const submit = el('button', { type: 'submit', class: 'primary', disabled: true }, 'Publish complete output');
    let roots = [], parent = null, selectedRoot = null, key = crypto.randomUUID(), submitted = null;
    async function folder(entry, cursor = null) {
      if (view.busy()) return;
      view.working(true); destination.disabled = true; submit.disabled = true; parent = null;
      try {
        const result = await send('/files/list', { method: 'POST', body: { root_id: destination.value, entry_id: entry, cursor, limit: 100 } });
        if (!view.active() || !active || !valid()) return;
        parent = result.entry_id; selectedRoot = destination.value;
        folders.replaceChildren(el('p', {}, `Destination folder: ${result.breadcrumbs.map(part => part.name).join(' / ')}`),
          el('div', { class: 'actions' }, result.breadcrumbs.length > 1 ? button('Up', () => folder(result.breadcrumbs.at(-2).entry_id)) : null,
            result.entries.filter(item => item.kind === 'directory').map(item => button(`Open ${item.name}`, () => folder(item.entry_id))),
            result.next_cursor ? button('Next folder page', () => folder(result.entry_id, result.next_cursor)) : null));
      } catch (error) { if (view.active()) errors.replaceChildren(errorPanel(error)); }
      finally { view.working(false); destination.disabled = false; submit.disabled = !parent; }
    }
    destination.addEventListener('change', () => folder(roots.find(root => root.id === destination.value).entry_id));
    view.content.append(notice('The complete output is relayed through the controller to the selected registered folder. Existing filenames are refused. Keep contributor output until this copy succeeds or is cancelled.'),
      el('form', { onsubmit: async event => {
        event.preventDefault(); if (view.busy() || !parent) return;
        try {
          const body = { revision: job.revision, object: selectedObject, name: name.value,
            destination: { root_id: selectedRoot, entry_id: parent },
            dataset: register.checked ? { name: datasetName.value, format: format.value, schema: JSON.parse(schema.value) } : null };
          if (JSON.stringify(body) !== submitted) { key = crypto.randomUUID(); submitted = JSON.stringify(body); }
          view.working(true); destination.disabled = true; submit.disabled = true;
          await send(`/workloads/${job.id}/artifacts`, { method: 'POST', body, idempotencyKey: key });
          if (view.active() && active && valid()) { view.dialog.close(); await loadPublications(); }
        } catch (error) {
          if (view.active()) errors.replaceChildren(errorPanel(error), notice('Retry preserves this request key. Check recorded publications before creating another request.'));
        } finally { view.working(false); destination.disabled = false; submit.disabled = !parent; }
      } }, el('label', { for: destination.id }, 'Destination location'), destination, folders,
      el('label', { for: name.id }, 'Destination filename'), name,
      el('label', { class: 'check-label', for: register.id }, register, 'Register the verified result as a dataset'), datasetFields,
      errors, el('div', { class: 'actions' }, submit)));
    try {
      const result = await send('/file-roots');
      if (!view.active() || !active || !valid()) return;
      roots = result.roots.filter(root => root.available && root.actions.includes('write') && root.actions.includes('read'));
      destination.replaceChildren(...roots.map(root => el('option', { value: root.id }, root.display_label || root.label)));
      if (roots.length) await folder(roots[0].entry_id);
      else errors.replaceChildren(notice('Register a writable file location before publishing output.', 'warning'));
    } catch (error) { if (view.active()) errors.replaceChildren(errorPanel(error)); }
  }
  const instructions = el('details', {}, el('summary', {}, 'Read larger output with the API'),
    el('p', {}, 'The preview reads and saves at most 64 KiB per page. Publish complete output transfers the entire object to registered storage. Text pages may split a UTF-8 character; saved byte ranges preserve the exact original bytes.'),
    el('code', { class: 'workload-api' }, `POST /api/v1/workloads/${job.id}/output\n{"reads":[{"object":"stdout","offset":0,"length":1048576}]}`),
    el('p', {}, 'Use an authenticated client with jobs:logs access in this project. Stream each decoded base64 data range to a file, advance to next_offset, and verify the attempt ID, generation, plan digest, object identity and contiguous offsets on every response. Each request is limited to 1 MiB in total. A complete transfer requires both eof and complete. Read again after growth; never combine changed identities.'));
  const element = el('section', { class: 'workload-output', 'aria-label': 'Retained workload output' },
    el('h3', {}, 'Retained output'),
    notice('Preview one 64 KiB range, or publish the complete output to registered storage before releasing it.'),
    allowed('jobs:logs') ? [el('div', { class: 'job-log-controls' }, el('label', {}, 'Output object', object), first, previous, next, save),
      errors, metadata, content, instructions, allowed('files:write') ? publish : null, publicationErrors, published] : el('p', {}, 'Output access requires the jobs:logs grant.'));
  controls(); if (allowed('jobs:logs')) void loadPublications();
  return { element, update(value) { job = value; controls(); }, dispose() {
    active = false; version++; clearTimeout(publicationTimer); dialog?.dialog.close();
    page = null; identity = null; content.textContent = ''; element.replaceChildren();
  } };
}
