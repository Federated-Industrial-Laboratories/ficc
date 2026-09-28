// SPDX-License-Identifier: Apache-2.0
// Register fixed Windows management and display connections without exposing saved credentials.
import { request } from './api.js';
import { button, el, notice, table } from './components.js';

export function windowsEndpoints() {
  let disposed = false;
  const dialog = el('dialog', { class: 'module-manager', 'aria-label': 'Windows endpoints' });
  const body = el('div'), editor = el('div'), status = el('div', { role: 'status' });
  const fail = error => { if (!disposed) status.replaceChildren(notice(error.message, 'error')); };
  const text = value => el('span', { class: String(value).length <= 24 ? 'module-nowrap' : '' }, String(value));
  async function load() {
    try {
      const { endpoints } = await request('/windows-endpoints');
      if (disposed) return;
      body.replaceChildren(table(['Name', 'Host', 'JEA configuration', 'State', 'Actions'], endpoints.map(endpoint => {
        const toggle = button(endpoint.enabled ? 'Disable' : 'Probe and enable', async event => {
          const control = event.currentTarget; control.disabled = true;
          try {
            await request(`/windows-endpoints/${endpoint.id}/activation`, { method: 'POST', body: {
              enabled: !endpoint.enabled, expected_revision: endpoint.revision,
            } });
            status.replaceChildren(notice('Windows endpoint state saved. Adapter grants remain separate.')); await load();
          } catch (error) { fail(error); }
          finally { control.disabled = false; }
        });
        const remove = button('Remove', () => {
          const confirm = el('input', { type: 'checkbox' });
          status.replaceChildren(el('label', {}, confirm, ` Remove ${endpoint.name} and its saved credentials. Remove its adapter profiles first.`),
            button('Confirm endpoint removal', async event => {
              if (!confirm.checked) return;
              const control = event.currentTarget; control.disabled = true;
              try {
                await request(`/windows-endpoints/${endpoint.id}`, { method: 'DELETE', body: {
                  expected_revision: endpoint.revision, confirm: true,
                } });
                editor.replaceChildren(); status.replaceChildren(notice('Windows endpoint removed.')); await load();
              } catch (error) { fail(error); }
              finally { control.disabled = false; }
            }));
        });
        return el('tr', {}, el('td', {}, endpoint.name), el('td', {}, `${endpoint.host}:${endpoint.port}`),
          el('td', {}, endpoint.configuration), el('td', {}, text(endpoint.enabled ? 'Enabled' : 'Disabled'),
            endpoint.diagnostic ? el('p', {}, endpoint.diagnostic) : null),
          el('td', {}, toggle, button('Edit', () => edit(endpoint)), remove));
      }), 'Registered Windows endpoints'));
      if (!endpoints.length) body.append(notice('No Windows endpoints are registered.'));
    } catch (error) { fail(error); }
  }
  function edit(prior = null) {
    const fields = el('div', { class: 'module-sources' }), inputs = {};
    function field(key, label, value = '', options = {}) {
      const { multiline, ...attributes } = options;
      const input = el(multiline ? 'textarea' : 'input', { 'aria-label': label, ...attributes });
      input.value = value ?? ''; inputs[key] = input;
      fields.append(el('label', {}, label, input)); return input;
    }
    field('name', 'Endpoint name', prior?.name, { maxlength: 128 });
    field('host', 'Windows host name or IP address', prior?.host, { maxlength: 253 });
    field('port', 'WinRM HTTPS port', prior?.port ?? 5986, { type: 'number', min: 1, max: 65535 });
    field('configuration', 'JEA configuration name', prior?.configuration, { maxlength: 64 });
    field('commands', 'Allowed JEA commands (JSON)', JSON.stringify(prior?.commands || [
      { name: 'Get-FICCEndpointIdentity', parameters: [] },
    ], null, 2), { multiline: true, rows: 6, maxlength: 32768 });
    field('certificate_sha256', 'Management certificate SHA-256', prior?.certificate_sha256, { maxlength: 64, spellcheck: 'false' });
    field('ca_pem', 'Trusted management CA certificate (PEM)', '', { multiline: true, rows: 5, maxlength: 65536, spellcheck: 'false' });
    const secretInputs = [];
    function account(prefix, label) {
      fields.append(el('h3', {}, label));
      for (const [key, caption, limit] of [['username', 'User name', 128], ['domain', 'Domain (optional)', 253], ['password', 'Password', 256]]) {
        const input = field(`${prefix}${key}`, `${label}: ${caption}`, '', {
          maxlength: limit, type: key === 'password' ? 'password' : 'text', autocomplete: 'off', spellcheck: 'false',
        });
        secretInputs.push(input);
      }
    }
    account('management_', 'Management account');
    const display = el('input', { type: 'checkbox' }); display.checked = Boolean(prior?.vmconnect);
    fields.append(el('label', {}, display, ' Configure a separate VMConnect display connection'));
    field('display_port', 'VMConnect port', prior?.vmconnect?.port ?? 2179, { type: 'number', min: 1, max: 65535 });
    field('display_pin', 'Display certificate SHA-256', prior?.vmconnect?.certificate_sha256, { maxlength: 64, spellcheck: 'false' });
    account('display_', 'Display account');
    const enabled = el('input', { type: 'checkbox' }); enabled.checked = Boolean(prior?.enabled);
    fields.append(el('label', {}, enabled, ' Probe and enable this endpoint when saved'));
    const feedback = el('div', { role: 'status' });
    function credentials(prefix) {
      const value = Object.fromEntries(['username', 'password', 'domain'].map(key => [key, inputs[prefix + key].value]));
      if (!Object.values(value).some(Boolean)) return undefined;
      if (!value.username || !value.password) throw Error('Enter both the account user name and password.');
      return value;
    }
    const save = button(prior ? 'Save endpoint' : 'Register endpoint', async () => {
      save.disabled = true;
      try {
        const value = { name: inputs.name.value, host: inputs.host.value, port: Number(inputs.port.value),
          configuration: inputs.configuration.value, commands: JSON.parse(inputs.commands.value),
          certificate_sha256: inputs.certificate_sha256.value, enabled: enabled.checked,
          vmconnect: display.checked ? { port: Number(inputs.display_port.value),
            certificate_sha256: inputs.display_pin.value, credentials: credentials('display_') } : null,
          credentials: credentials('management_'), ca_pem: inputs.ca_pem.value || undefined,
        };
        if (prior) value.expected_revision = prior.revision;
        await request(`/windows-endpoints${prior ? '/' + prior.id : ''}`, { method: prior ? 'PUT' : 'POST', body: value });
        if (!disposed) {
          editor.replaceChildren(); status.replaceChildren(notice('Windows endpoint saved. Add and grant its adapter profile separately.'));
          await load();
        }
      } catch (error) { if (!disposed) feedback.replaceChildren(notice(error instanceof SyntaxError ? 'Enter a valid JSON command list.' : error.message, 'error')); }
      finally { secretInputs.forEach(input => { input.value = ''; }); save.disabled = false; }
    });
    editor.replaceChildren(el('h3', {}, prior ? `Edit ${prior.name}` : 'Register Windows endpoint'),
      notice('Use a dedicated JEA endpoint with the exact command and parameter list supplied by the trusted adapter.'),
      el('p', {}, 'TLS verifies the host name, trusted CA and certificate digest. Management and display credentials stay in private host storage.'),
      prior ? el('p', {}, 'Leave an account and its CA field empty to keep their saved values. A changed endpoint invalidates adapter bindings.') : null,
      fields, feedback, save, button('Cancel', () => { secretInputs.forEach(input => { input.value = ''; }); editor.replaceChildren(); }));
    inputs.name.focus();
  }
  dialog.append(el('h2', {}, 'Windows endpoints'),
    el('p', {}, 'Register Windows connections separately from enrolled SSH systems. Install and configure the trusted JEA endpoint on Windows first.'),
    body, status, button('Register Windows endpoint', () => edit()), button('Refresh', load), editor, button('Close', () => dialog.close()));
  dialog.addEventListener('close', () => { disposed = true; dialog.remove(); }, { once: true });
  document.body.append(dialog); dialog.showModal(); void load();
  return { dispose() { dialog.close(); } };
}
