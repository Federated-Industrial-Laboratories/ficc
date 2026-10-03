// SPDX-License-Identifier: Apache-2.0
// Share explicit project runbooks and load recipes into an editable submission.
import { button, confirmation, details, el, notice } from './components.js';

export function workloadTemplates(send, valid, snapshot, apply) {
  const element = el('details'), message = el('div', { role: 'status' }), description = el('div');
  const select = el('select', { 'aria-label': 'Shared workload template' }, el('option', { value: '' }, 'Select a template'));
  const name = el('input', { 'aria-label': 'Workload template name', maxlength: '80' });
  const instructions = el('textarea', { 'aria-label': 'Runbook instructions', maxlength: '4096' });
  let values = [], active = true;
  const fail = error => { if (active && valid()) message.replaceChildren(notice(error.message, 'error')); };
  async function load() {
    try {
      const result = await send('/workload-templates');
      if (!active || !valid()) return;
      values = result.templates;
      select.replaceChildren(el('option', { value: '' }, 'Select a template'), ...values.map(value =>
        el('option', { value: value.id }, `${value.name} / version ${value.version}`)));
      description.replaceChildren();
    } catch (error) { fail(error); }
  }
  select.addEventListener('change', () => {
    const value = values.find(item => item.id === select.value);
    description.replaceChildren(...(value ? [details([['Content digest', value.digest], ['Image', value.job.runtime.image_digest]]),
      el('pre', { class: 'wrap' }, value.instructions || 'No runbook instructions.')] : []));
  });
  element.append(el('summary', {}, 'Project workload templates and runbooks'),
    el('p', {}, 'Templates retain the command, image, limits and output declarations. Select contributors, GPU devices and input data for each submission. Environment variables are excluded.'),
    el('label', {}, 'Shared workload template', select),
    el('div', { class: 'actions' }, button('Refresh templates', load), button('Use template', () => {
      try {
        const value = values.find(item => item.id === select.value);
        if (!value) throw Error('Select a template.');
        apply(value.job); name.value = value.name; instructions.value = value.instructions;
        message.replaceChildren(notice('Template loaded. Review the command, contributors, resources and data before submitting.'));
      } catch (error) { fail(error); }
    }), button('Remove template version', () => {
      const value = values.find(item => item.id === select.value);
      if (!value) return;
      confirmation('Remove workload template?', 'Existing workloads retain their requests.', 'Remove version', async () => {
        try { await send(`/workload-templates/${value.id}`, { method: 'DELETE' }); await load(); }
        catch (error) { fail(error); }
      });
    })), description,
    el('label', {}, 'Workload template name', name), el('label', {}, 'Runbook instructions', instructions),
    button('Share current workload template', () => {
      let job;
      try { job = snapshot(); if (!name.value.trim()) throw Error('Enter a template name.'); }
      catch (error) { fail(error); return; }
      confirmation('Share workload template with this project?',
        'Project colleagues can read its executable, arguments and runbook. Remove credentials and private text from these fields before sharing. Environment variables, inputs and GPU identities are excluded.',
        'Share template', async () => {
          try {
            await send('/workload-templates', { method: 'POST', body: { name: name.value.trim(), instructions: instructions.value, job } });
            if (active && valid()) { await load(); message.replaceChildren(notice('A new immutable template version is shared.')); }
          } catch (error) { fail(error); }
        });
    }), message);
  element.addEventListener('toggle', () => { if (element.open && !values.length) void load(); });
  return { element, dispose() { active = false; } };
}
