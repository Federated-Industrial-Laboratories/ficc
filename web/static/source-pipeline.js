// SPDX-License-Identifier: Apache-2.0
// Preview registered queries and publish durable dataset exports.
import { allowed, request } from './api.js';
import { button, details, el, errorPanel, notice, table } from './components.js';
import { fileDialog } from './file-dialog.js';
import { field, parameterFields, picker, text } from './source-forms.js';

export async function queryPipeline(value, connection, received) {
  const view = fileDialog(value.query.name), status = el('div'), preview = el('div');
  const parameters = parameterFields(value.query), write = value.query.mode === 'write';
  const dataset = text('pipeline-dataset', value.query.name), filename = text('pipeline-filename', 'export.csv');
  const format = el('select', { id: 'pipeline-format' }, (connection.provider === 's3' ? ['original'] : ['csv', 'arrow', 'parquet']).map(name => el('option', { value: name }, name)));
  format.addEventListener('change', () => { filename.value = 'export.' + (format.value === 'original' ? 'bin' : format.value); });
  const consent = text('pipeline-write-consent', '', { type: 'checkbox' });
  let destination;
  view.content.append(el('div', {}, details([['Connection', connection.name], ['Template SHA-256', value.template_digest]]), ...parameters.elements,
    write ? el('label', { for: consent.id }, consent, 'Apply this registered write with the approved write account.') : null,
    write ? notice('Uncertain transaction outcomes remain unknown. FICC never automatically replays a write.') : button('Preview rows', async () => {
      if (view.busy()) return; view.working(true);
      try {
        const result = await request(`/source-queries/${value.id}/preview`, { method: 'POST', body: { parameters: parameters.values() }, timeout: null });
        preview.replaceChildren(el('div', {}, table(result.schema.fields.map(item => item.name), result.rows.map(row => el('tr', {}, row.map(item => el('td', {},
          item === null ? 'NULL' : typeof item === 'object' ? JSON.stringify(item) : String(item))))), 'Query preview'),
          notice(result.truncated ? 'Preview reached its row or byte limit.' : `${result.rows.length} preview rows.`),
          result.preview_base64 ? el('pre', {}, `Object prefix (base64): ${result.preview_base64}`) : null,
          result.receipt?.malformed_rows_skipped ? notice(`${result.receipt.malformed_rows_skipped} malformed rows skipped under the approved policy.`, 'warning') : null));
      } catch (error) { preview.replaceChildren(errorPanel(error)); }
      finally { view.working(false); }
    }), preview));
  if (!write && allowed('data:export') && allowed('files:write')) {
    try {
      destination = await picker(view, 'Output', true);
      view.content.append(...field('Dataset name', dataset), ...field('Output filename', filename), ...field('Output format', format),
        destination.element, notice('The current output directory receives a new file. Existing files are never overwritten.'));
    } catch (error) { status.replaceChildren(errorPanel(error)); }
  }
  let key = crypto.randomUUID(), previous = null;
  const submit = button(write ? 'Apply registered write' : 'Export to dataset', async () => {
    if (view.busy()) return;
    try {
      if (write && !consent.checked) throw new Error('Confirm the registered write before applying it.');
      const chosen = destination?.value();
      if (!write && !chosen?.ready) throw new Error('Choose an available output directory.');
      const body = { action: write ? 'write' : 'export', parameters: parameters.values(),
        ...(write ? {} : { destination: { root_id: chosen.root.id, entry_id: chosen.entry_id }, filename: filename.value, dataset_name: dataset.value, format: format.value }) };
      if (previous !== JSON.stringify(body)) { key = crypto.randomUUID(); previous = JSON.stringify(body); }
      view.working(true); submit.disabled = true;
      const result = await request(`/source-queries/${value.id}/runs`, { method: 'POST', body, idempotencyKey: key });
      view.dialog.close(); received(result);
    } catch (error) { status.replaceChildren(errorPanel(error)); }
    finally { view.working(false); submit.disabled = false; }
  }, { class: write ? 'danger' : 'primary', disabled: !allowed(write ? 'data:write' : 'data:export') });
  view.content.append(status, submit);
}

export async function runResult(identity) {
  const view = fileDialog('Data operation receipt');
  try {
    const value = await request(`/source-runs/${identity}`);
    view.content.append(el('div', {}, details([['State', value.state], ['Dataset ID', value.dataset_id ?? 'No dataset published'],
      ['Manifest SHA-256', value.manifest_digest ?? 'Pending'], ['Rows', String(value.rows)], ['Bytes', String(value.bytes)]]),
      value.dataset_id && value.action === 'export' ? notice('Select this dataset ID in Workloads when submitting a dataset-backed job.') : null,
      value.error ? notice(value.error.message, 'warning') : null, el('pre', { class: 'wrap' }, JSON.stringify(value.receipt ?? {}, null, 2))));
  } catch (error) { view.content.append(errorPanel(error)); }
}
