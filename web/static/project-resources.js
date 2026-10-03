// SPDX-License-Identifier: Apache-2.0
// Assign registered machines and folders to a project with revision checks.
import { request } from './api.js';
import { button, el, errorPanel, panel, table } from './components.js';

export function projectResources(projects) {
  const message = el('div', { role: 'status' }), choices = el('div');
  const project = el('select', { 'aria-label': 'Resource project' },
    projects.map(item => el('option', { value: item.id }, item.label)));
  let disposed = false, saving = false, generation = 0, revision = 0, selectedProject = null;
  let nodes = new Map(), roots = new Map();
  const fail = error => { if (!disposed) message.replaceChildren(errorPanel(error)); };

  async function load() {
    if (saving) return;
    const serial = ++generation, identity = project.value;
    selectedProject = null; save.disabled = true;
    choices.textContent = 'Loading project resources.';
    try {
      const [options, value] = await Promise.all([
        request('/project-resource-options'), request(`/projects/${identity}/resources`),
      ]);
      if (disposed || serial !== generation) return;
      revision = value.revision; nodes = new Map(); roots = new Map();
      const nodeRows = options.nodes.map(item => {
        const input = el('input', { type: 'checkbox', checked: value.node_ids.includes(item.id),
          'aria-label': `Assign machine ${item.name}` });
        nodes.set(item.id, input);
        input.addEventListener('change', () => {
          for (const root of options.roots.filter(root => root.node_id === item.id)) {
            const field = roots.get(root.id);
            field.disabled = !input.checked;
            if (!input.checked) field.checked = false;
          }
        });
        return el('tr', {}, el('td', {}, input), el('td', {}, item.name), el('td', {}, item.kind));
      });
      const rootRows = options.roots.map(item => {
        const enabled = !item.node_id || nodes.get(item.node_id)?.checked;
        const input = el('input', { type: 'checkbox', checked: enabled && value.root_ids.includes(item.id),
          disabled: !enabled, 'aria-label': `Assign folder ${item.label}` });
        roots.set(item.id, input);
        return el('tr', {}, el('td', {}, input), el('td', {}, item.label),
          el('td', {}, options.nodes.find(node => node.id === item.node_id)?.name || 'Controller'),
          el('td', {}, item.read_only ? 'Read only' : 'Read and write'));
      });
      choices.replaceChildren(
        table(['Assigned', 'Machine', 'Connection'], nodeRows, 'Project machines'),
        table(['Assigned', 'Folder', 'Machine', 'Registration'], rootRows, 'Project folders'));
      selectedProject = identity; save.disabled = false;
    } catch (error) { fail(error); }
  }

  const save = button('Save project resources', async () => {
    if (!selectedProject || selectedProject !== project.value) return;
    const serial = generation, identity = selectedProject;
    saving = true;
    save.disabled = true; project.disabled = true; choices.inert = true;
    try {
      const value = await request(`/projects/${identity}/resources`, { method: 'PUT', body: {
        revision,
        node_ids: [...nodes].filter(([, field]) => field.checked).map(([id]) => id),
        root_ids: [...roots].filter(([, field]) => field.checked).map(([id]) => id),
      } });
      if (disposed || serial !== generation) return;
      revision = value.revision;
      message.textContent = 'Project resources saved. Current requests use these assignments.';
    } catch (error) { fail(error); }
    finally {
      saving = false;
      if (!disposed && serial === generation) { save.disabled = false; project.disabled = false; choices.inert = false; }
    }
  }, { disabled: true });
  project.addEventListener('change', load);
  const element = panel('Project resources', [
    el('p', {}, 'Assign machines and registered folders. Membership capabilities and credential limits still apply. Select a machine before its folders.'),
    project, choices, el('div', { class: 'actions' }, save, button('Reload project resources', load)), message,
  ]);
  void load();
  return { element, dispose() { disposed = true; generation += 1; } };
}
