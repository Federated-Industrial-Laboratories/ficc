// SPDX-License-Identifier: Apache-2.0
// Source approval and query forms use opaque registered file references.
import { allowed, request } from './api.js';
import { button, el, errorPanel, notice } from './components.js';
import { fileDialog } from './file-dialog.js';
import { filePane } from './file-pane.js';

export function field(label, input) { return [el('label', { for: input.id }, label), input]; }
export function text(id, value = '', attributes = {}) { const input = el('input', { id, ...attributes }); input.value = value; return input; }
export function json(id, value) { return el('textarea', { id, rows: 6 }, JSON.stringify(value, null, 2)); }

export async function picker(view, label = 'Source', write = false) {
  const { roots } = await request('/file-roots');
  const pane = filePane(label, roots.filter(root => root.node_id == null && root.actions.includes(write ? 'write' : 'read')), [], () => {}, false);
  pane.element.querySelectorAll('[data-file-action]').forEach(item => item.remove());
  view.dialog.addEventListener('close', () => pane.dispose(), { once: true });
  return pane;
}

export async function approveSource(providers, received) {
  const view = fileDialog('Approve data source'), status = el('div');
  const name = text('source-name', '', { required: true, maxlength: 120 });
  const provider = el('select', { id: 'source-provider' }, providers.map(item => el('option', { value: item.name }, item.name)));
  const config = json('source-configuration', {}), permissions = ['export', 'write'].map(value => text(`source-${value}`, '', { type: 'checkbox' }));
  const host = text('source-host'), port = text('source-port', '5432', { type: 'number', min: 1, max: 65535 });
  const addresses = text('source-addresses'), privateNetwork = text('source-private', '', { type: 'checkbox' });
  const fixed = text('source-fixed');
  const ca = el('textarea', { id: 'source-ca', rows: 4 }), read = text('source-read-secret'), write = text('source-write-secret');
  const local = el('div'), network = el('div', {}, ...field('TLS hostname or IP SAN', host), ...field('Port', port),
    ...field('Approved IP addresses, comma separated', addresses), ...field('Approved CA certificate PEM', ca),
    ...field('Fixed approved IP, optional; bypasses DNS, preserves TLS name', fixed),
    el('label', { for: privateNetwork.id }, privateNetwork, 'Allow these explicit private-network addresses'),
    ...field('Read-account secret reference', read), ...field('Separate write-account secret reference', write));
  let pane;
  try { if (allowed('files:read')) { pane = await picker(view); local.append(pane.element, notice('Select exactly one file for a local source.')); } }
  catch (error) { local.append(errorPanel(error)); }
  const defaults = { sqlite: {}, csv: { schema: { fields: [{ name: 'value', type: 'integer', nullable: false }] }, encoding: 'utf-8', delimiter: ',', null: '', malformed: 'error' },
    arrow: { format: 'parquet' }, duckdb: { format: 'parquet' }, postgresql: { database: 'measurements' }, mysql: { database: 'measurements' }, s3: { bucket: 'datasets', prefix: 'project/' } };
  function change() {
    const selected = providers.find(item => item.name === provider.value);
    local.hidden = selected?.kind !== 'local'; network.hidden = selected?.kind !== 'network';
    config.value = JSON.stringify(defaults[provider.value] ?? {}, null, 2);
    port.value = provider.value === 'mysql' ? '3306' : provider.value === 's3' ? '443' : '5432';
    permissions[1].disabled = !selected?.write;
  }
  provider.addEventListener('change', change); change();
  const submit = el('button', { type: 'submit', class: 'primary' }, 'Approve source');
  let key = crypto.randomUUID(), previous = null;
  view.content.append(el('form', { onsubmit: async event => {
    event.preventDefault(); if (view.busy()) return;
    try {
      const remote = providers.find(item => item.name === provider.value)?.kind === 'network';
      const selected = pane?.value();
      if (!remote && (!selected?.ready || selected.entries.length !== 1 || selected.entries[0].kind !== 'file')) throw new Error('Select exactly one ordinary source file.');
      const body = { name: name.value, provider: provider.value, configuration: JSON.parse(config.value), permissions: ['read', ...permissions.filter(item => item.checked && !item.disabled).map(item => item.id.slice(7))],
        source: remote ? null : { root_id: selected.root.id, entry_id: selected.entries[0].entry_id },
        endpoint: remote ? { host: host.value, port: Number(port.value), addresses: addresses.value.split(',').map(value => value.trim()).filter(Boolean), ca_pem: ca.value, private_network: privateNetwork.checked, fixed_address: fixed.value || null } : null,
        read_secret: remote ? read.value : null, write_secret: remote && write.value ? write.value : null };
      if (previous !== JSON.stringify(body)) { key = crypto.randomUUID(); previous = JSON.stringify(body); }
      view.working(true); submit.disabled = true;
      const value = await request('/sources', { method: 'POST', body, idempotencyKey: key });
      view.dialog.close(); received(value);
    } catch (error) { status.replaceChildren(errorPanel(error)); }
    finally { view.working(false); submit.disabled = false; }
  } }, ...field('Source name', name), ...field('Installed provider', provider), ...field('Provider configuration JSON', config),
  local, network, notice('Read access is the default. Database account grants enforce actual SQL rights. Secret references name private credentials provisioned by the deployment administrator.'),
  permissions.map(input => el('label', { for: input.id }, input, input.id.endsWith('export') ? 'Allow dataset exports' : 'Allow explicit writes with the separate account')),
  status, submit));
}

export function registerQuery(connection, received, resource = null) {
  const view = fileDialog('Register query'), status = el('div');
  const name = text('source-query-name', '', { required: true, maxlength: 120 });
  const mode = el('select', { id: 'source-query-mode' }, el('option', { value: 'read' }, 'Read'),
    connection.permissions.includes('write') ? el('option', { value: 'write' }, 'Explicit write') : null);
  const sql = ['sqlite', 'postgresql', 'mysql', 'duckdb'].includes(connection.provider);
  const specification = json('source-query-spec', sql ? { statement: connection.provider === 'sqlite' ? 'SELECT :value AS value' :
    connection.provider === 'duckdb' ? 'SELECT * FROM source WHERE $value IS NOT NULL' : 'SELECT %(value)s AS value' } :
    connection.provider === 's3' ? { key: resource?.id ?? connection.configuration.prefix, version_id: resource?.version_id ?? null, sha256: resource?.sha256_metadata ?? null } : { columns: [], filters: [] });
  const parameters = json('source-query-parameters', sql ? [{ name: 'value', type: 'string', nullable: false }] : []);
  const submit = el('button', { type: 'submit', class: 'primary' }, 'Register query');
  let key = crypto.randomUUID(), previous = null;
  view.content.append(notice(`Connection: ${connection.name}. Ordinary users can supply the declared parameter values; changing a template requires data:manage.`),
    el('form', { onsubmit: async event => {
      event.preventDefault(); if (view.busy()) return;
      try {
        const body = { name: name.value, mode: mode.value, specification: JSON.parse(specification.value), parameters: JSON.parse(parameters.value) };
        if (previous !== JSON.stringify(body)) { key = crypto.randomUUID(); previous = JSON.stringify(body); }
        view.working(true); submit.disabled = true;
        const result = await request(`/sources/${connection.id}/queries`, { method: 'POST', idempotencyKey: key,
          body });
        view.dialog.close(); received(result);
      } catch (error) { status.replaceChildren(errorPanel(error)); }
      finally { view.working(false); submit.disabled = false; }
    } }, ...field('Query name', name), ...field('Operation', mode), ...field('Provider query specification', specification),
    ...field('Declared parameters', parameters), status, submit));
}

export function parameterFields(query) {
  const inputs = query.parameters.map(item => {
    const input = item.type === 'boolean' && item.nullable ? el('select', { id: `parameter-${item.name}` },
      ['', 'true', 'false'].map(value => el('option', { value }, value || 'NULL'))) :
      text(`parameter-${item.name}`, '', { type: item.type === 'boolean' ? 'checkbox' : 'text', required: !item.nullable && item.type !== 'boolean' });
    return { item, input };
  });
  return { elements: inputs.flatMap(({ item, input }) => field(`${item.name} (${item.type}${item.nullable ? ', nullable' : ''})`, input)),
    values() { return Object.fromEntries(inputs.map(({ item, input }) => [item.name,
      item.type === 'boolean' ? item.nullable ? input.value === '' ? null : input.value === 'true' : input.checked :
        item.nullable && input.value === '' ? null : item.type === 'number' ? Number(input.value) : input.value])); } };
}
