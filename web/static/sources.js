// SPDX-License-Identifier: Apache-2.0
// Project data-source catalogue and query-to-dataset pipelines.
import { allowed, getSession, request } from './api.js';
import { button, bytes, el, errorPanel, heading, panel, state, table } from './components.js';
import { fileDialog } from './file-dialog.js';
import { approveSource, registerQuery } from './source-forms.js';
import { queryPipeline, runResult } from './source-pipeline.js';
import { beginObjectUpload, objectUpload } from './source-uploads.js';

export function sources() {
  let active = true, timer, providers = [], connections = [], loading = false;
  const demo = getSession().mode === 'demo', status = el('div'), connectionsPanel = el('div'), queryPanel = el('div'), runsPanel = el('div'), uploadPanel = el('div');
  const approve = button('Approve source', () => approveSource(providers, () => load()), { disabled: true });
  const element = el('div', {}, heading('DATA / PIPELINES', 'Data sources', 'Browse approved sources, preview registered queries and publish verified datasets.', [
    approve, button('Refresh', () => load())]),
    status, connectionsPanel, queryPanel, uploadPanel, runsPanel);

  async function catalogue(connection, cursor = null, view = fileDialog('Source catalogue')) {
    try {
      const result = await request(`/sources/${connection.id}/catalogue${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`, { timeout: null });
      if (!view.active()) return;
      view.content.replaceChildren(el('div', {}, table(['Resource', 'Kind', 'Schema'], result.resources.map(item => el('tr', {}, el('td', {}, item.name),
        el('td', {}, item.kind), el('td', {}, button('Describe', async () => {
          try {
            const shape = await request(`/sources/${connection.id}/describe`, { method: 'POST', body: { resource: item.id }, timeout: null });
            const detail = fileDialog(item.name);
            detail.content.append(el('div', {}, table(['Column', 'Type', 'Nullable'], shape.schema.fields.map(field => el('tr', {},
              el('td', {}, field.name), el('td', {}, field.type), el('td', {}, field.nullable ? 'Yes' : 'No'))), 'Source schema'),
              el('pre', { class: 'wrap' }, JSON.stringify(shape.receipt, null, 2)), allowed('data:manage') ? button('Register query', () => {
                detail.dialog.close(); view.dialog.close(); registerQuery(connection, () => load(), { ...item, ...shape.receipt });
              }) : null));
          } catch (error) { view.content.append(errorPanel(error)); }
        })))), 'Source catalogue'), result.next_cursor ? button('Next resources', () => catalogue(connection, result.next_cursor, view)) : null));
    } catch (error) { if (view.active()) view.content.replaceChildren(errorPanel(error)); }
  }

  async function approval(connection) {
    try { await request(`/sources/${connection.id}/approval`, { method: 'PUT', body: { enabled: !connection.enabled, revision: connection.revision } }); await load(); }
    catch (error) { status.replaceChildren(errorPanel(error)); }
  }

  async function pipeline(query) {
    try {
      const connection = connections.find(item => item.id === query.connection_id) ?? await request(`/sources/${query.connection_id}`);
      await queryPipeline(query, connection, () => load());
    } catch (error) { status.replaceChildren(errorPanel(error)); }
  }

  async function load(before = {}) {
    if (!active || loading) return;
    loading = true; clearTimeout(timer);
    try {
      const query = (path, value) => request(path + (value ? `?before=${value}` : ''));
      const [installed, saved, queries, runs, uploads] = await Promise.all([request('/data-providers'), query('/sources', before.sources),
        query('/source-queries', before.queries), query('/source-runs', before.runs), query('/source-uploads', before.uploads)]);
      if (!active) return;
      providers = installed.providers; connections = saved.items;
      approve.disabled = demo || !allowed('data:manage') || !providers.length;
      const connection = id => connections.find(item => item.id === id);
      connectionsPanel.replaceChildren(panel('Approved connections', [saved.items.length ? table(['Source', 'Provider', 'Permissions', 'Actions'], saved.items.map(value => el('tr', {},
        el('td', {}, value.name, value.enabled ? '' : ' (disabled)'), el('td', {}, value.provider), el('td', {}, value.permissions.join(', ')), el('td', {},
          button('Browse catalogue', () => catalogue(value), { disabled: !value.enabled }),
          allowed('data:manage') ? button('Register query', () => registerQuery(value, () => load()), { disabled: demo || !value.enabled }) : null,
          allowed('data:manage') ? button(value.enabled ? 'Disable' : 'Enable', () => approval(value), { disabled: demo }) : null,
          providers.find(item => item.name === value.provider)?.objects && allowed('data:write') ? button('Upload dataset', () => beginObjectUpload(value, () => load()), { disabled: demo || !value.enabled }) : null))), 'Approved source connections') :
          state('No data sources', providers.length ? 'Approve a source and register a query to begin.' : 'Install trusted data-provider runtime packages before approving a connection.'),
        saved.next_cursor ? button('Next connections', () => load({ sources: saved.next_cursor })) : null]));
      queryPanel.replaceChildren(panel('Registered queries', [table(['Query', 'Source', 'Mode', 'Pipeline'], queries.items.map(value => el('tr', {},
        el('td', {}, value.query.name), el('td', {}, connection(value.connection_id)?.name ?? value.connection_id), el('td', {}, value.query.mode),
        el('td', {}, button('Open pipeline', () => pipeline(value), { disabled: connection(value.connection_id)?.enabled === false })))), 'Registered source queries'),
        queries.next_cursor ? button('Next queries', () => load({ queries: queries.next_cursor })) : null]));
      uploadPanel.replaceChildren(panel('Object uploads', [table(['Object key', 'State', 'Dataset', 'Recovery'], uploads.items.map(value => el('tr', {},
        el('td', {}, value.key), el('td', {}, value.state), el('td', {}, value.dataset_id),
        el('td', {}, button('Open upload', () => objectUpload(value.id, () => load()), { disabled: !allowed('data:write') })))), 'Retained object uploads'),
        uploads.next_cursor ? button('Next uploads', () => load({ uploads: uploads.next_cursor })) : null]));
      runsPanel.replaceChildren(panel('Pipeline operations', [table(['Action', 'State', 'Rows / bytes', 'Result'], runs.items.map(value => el('tr', {},
        el('td', {}, value.operation ?? value.action), el('td', {}, value.state), el('td', {}, `${value.rows} rows / ${bytes(value.bytes)}`),
        el('td', {}, button('Receipt', () => runResult(value.id)), ['queued', 'running', 'committing', 'publishing'].includes(value.state) || value.staging?.cleanup === 'pending' ? button(
          ['queued', 'running', 'committing', 'publishing'].includes(value.state) ? 'Cancel' : 'Clean up partial export', async () => {
          try { await request(`/source-runs/${value.id}/cancel`, { method: 'POST', body: {}, timeout: null }); await load(); }
          catch (error) { status.replaceChildren(errorPanel(error)); }
        }, { disabled: demo || !allowed(`data:${value.action}`) }) : null))), 'Source operation receipts'),
        runs.next_cursor ? button('Next operations', () => load({ runs: runs.next_cursor })) : null]));
    } catch (error) { if (active) status.replaceChildren(errorPanel(error, () => load())); }
    finally { loading = false; if (active) timer = setTimeout(() => load(before), 4000); }
  }
  load();
  return { element, dispose() { active = false; clearTimeout(timer); } };
}
