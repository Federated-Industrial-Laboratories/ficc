// SPDX-License-Identifier: Apache-2.0
// Register explicit project dataset versions from the selected filesystem objects.
import { allowed, request } from './api.js';
import { button, bytes, details, el, errorPanel, notice, panel, state, table, time } from './components.js';
import { fileDialog } from './file-dialog.js';
import { datasetSafety } from './dataset-safety.js';

export function datasetPanel(selection, demo) {
  let active = true, cursor = null;
  const content = el('div'), status = el('div'), element = panel('Datasets', [
    notice('A dataset pins file identities, digests, schema and provenance in this project. Changed sources require a new version.'),
    el('div', { class: 'actions' }, button('Register left selection', () => create(selection('left')), { disabled: demo || !allowed('files:write') }),
      button('Register right selection', () => create(selection('right')), { disabled: demo || !allowed('files:write') }),
      button('Refresh datasets', () => load())), status, content]);

  async function inspect(id) {
    const view = fileDialog('Dataset manifest'); view.content.append(state('Loading manifest', 'Reading the authenticated dataset version.'));
    try {
      const value = await request(`/datasets/${id}`);
      if (!view.active()) return;
      const checked = el('div');
      view.content.replaceChildren(details([['Dataset', value.name], ['Dataset ID', value.id], ['Project', value.project_id],
        ['Format', value.format], ['Created', time(value.created_at)], ['Manifest SHA-256', value.manifest_digest],
        ['Previous version', value.previous_version_id ?? 'None'], ['Provenance', value.provenance.description || 'None supplied'],
        ['Input datasets', value.provenance.input_dataset_ids.join(', ') || 'None']]),
      notice(value.description || 'No additional dataset description.'),
      table(['Field', 'Type', 'Nullable'], value.schema.fields.map(field => el('tr', {}, el('td', {}, field.name),
        el('td', {}, field.type), el('td', {}, field.nullable ? 'Yes' : 'No'))), 'Explicit dataset schema'),
      table(['File', 'Bytes', 'SHA-256'], value.files.map(file => el('tr', {}, el('td', {}, file.name),
        el('td', {}, String(file.size)), el('td', { class: 'wrap transfer-hash' }, file.sha256))), 'Dataset files'), datasetSafety(id, view), checked,
      button('Verify current sources', async () => {
        if (view.busy()) return; view.working(true); checked.replaceChildren(notice('Verifying each complete source with bounded memory.'));
        try { await request(`/datasets/${id}/verify`, { method: 'POST', body: {}, timeout: null }); checked.replaceChildren(notice('Every source still matches this manifest.')); }
        catch (error) { checked.replaceChildren(errorPanel(error)); }
        finally { view.working(false); }
      }));
    } catch (error) { if (view.active()) view.content.replaceChildren(errorPanel(error)); }
  }

  function create(selected) {
    if (!selected?.ready || !selected.entries.length || selected.entries.some(file => file.kind !== 'file')) {
      status.replaceChildren(notice('Select ordinary files in that pane before registering a dataset.', 'warning')); return;
    }
    const view = fileDialog('Register dataset version'), errors = el('div');
    const name = el('input', { id: 'dataset-name', required: true, maxlength: 120 });
    const format = el('select', { id: 'dataset-format' }, ['binary', 'csv', 'parquet', 'arrow'].map(value => el('option', { value }, value)));
    const schema = el('textarea', { id: 'dataset-schema', rows: 5, required: true }, '{"fields":[],"description":""}');
    const description = el('textarea', { id: 'dataset-description', rows: 2, maxlength: 2048 });
    const provenance = el('textarea', { id: 'dataset-provenance', rows: 2, maxlength: 2048 });
    const prior = el('input', { id: 'dataset-prior', pattern: '[a-f0-9]{32}', placeholder: 'Optional dataset ID' });
    let key = crypto.randomUUID(), saved = null;
    const submit = el('button', { type: 'submit', class: 'primary' }, 'Verify sources and register');
    view.content.append(el('p', {}, `${selected.entries.length} selected files from ${selected.root.display_label}`),
      notice('Schema describes the intended data. Format parsing and column validation are separate import steps.'),
      el('form', { onsubmit: async event => {
        event.preventDefault(); if (view.busy()) return;
        try {
          const body = { name: name.value, format: format.value, schema: JSON.parse(schema.value), description: description.value,
            sources: selected.entries.map(entry => ({ root_id: selected.root.id, entry_id: entry.entry_id })),
            provenance: { description: provenance.value, input_dataset_ids: [] }, previous_version_id: prior.value || null };
          if (saved !== JSON.stringify(body)) { key = crypto.randomUUID(); saved = JSON.stringify(body); }
          view.working(true); submit.disabled = true; errors.replaceChildren(notice('Hashing source files and recording this immutable manifest.'));
          const result = await request('/datasets', { method: 'POST', body, idempotencyKey: key, timeout: null });
          if (view.active()) view.dialog.close();
          status.replaceChildren(notice(`Dataset ${result.name} registered. ID: ${result.id}`)); await load();
        } catch (error) { if (view.active()) errors.replaceChildren(errorPanel(error)); }
        finally { view.working(false); submit.disabled = false; }
      } }, el('label', { for: name.id }, 'Dataset name'), name, el('label', { for: format.id }, 'Format'), format,
      el('label', { for: schema.id }, 'Explicit schema JSON'), schema,
      el('label', { for: description.id }, 'Description'), description, el('label', { for: provenance.id }, 'Source provenance'), provenance,
      el('label', { for: prior.id }, 'Previous dataset version'), prior, errors, el('div', { class: 'actions' }, submit)));
  }

  async function load(before = null) {
    try {
      const result = await request(`/datasets${before ? `?before=${before}` : ''}`);
      if (!active) return;
      cursor = result.next_cursor;
      content.replaceChildren(...[!result.provider_available ? notice('Install the filesystem artifact runtime package before registering or verifying datasets.', 'warning') : null,
        result.datasets.length ? table(['Dataset', 'Format', 'Files', 'Size', 'Safety / manifest'], result.datasets.map(value => el('tr', {},
          el('td', {}, value.name), el('td', {}, value.format), el('td', {}, value.file_count), el('td', {}, bytes(value.total_bytes)),
          el('td', {}, value.safety?.blocked ? 'Blocked · ' : value.safety?.sensitive ? 'Sensitive · ' : '',
            button('Inspect', () => inspect(value.id), { 'aria-label': `Inspect dataset ${value.name}` })))), 'Project datasets') :
          state('No datasets on this page', 'Select source files above to register a dataset.'),
        cursor ? button('Next datasets', () => load(cursor)) : null].filter(Boolean));
    } catch (error) { if (active) content.replaceChildren(errorPanel(error, () => load())); }
  }
  load();
  return { element, reload: load, dispose() { active = false; } };
}
