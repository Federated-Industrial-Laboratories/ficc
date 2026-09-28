// SPDX-License-Identifier: Apache-2.0
// Select exact granted targets for one saved module instance.
import { request } from './api.js';
import { button, el, notice } from './components.js';

export const workspaceCapability = capability => ['workspace:read', 'workspace:write', 'audio:playback'].includes(capability);

export const requiredCapabilities = manifest => manifest.capabilities.filter(capability =>
  !(manifest.optional_capabilities || []).includes(capability));

export function targetOptions(module, catalogue) {
  const required = requiredCapabilities(module.manifest).filter(capability => !workspaceCapability(capability));
  const optional = module.manifest.capabilities.filter(capability => !workspaceCapability(capability) &&
    !required.includes(capability) && module.grants.some(grant => grant.capability === capability));
  const capabilities = required.length ? required : optional;
  const kinds = [...new Set(capabilities.map(capability => catalogue.capabilities[capability]?.kind))];
  if (required.length && (kinds.length !== 1 || !kinds[0])) throw Error('This module requires an unavailable target type.');
  const candidates = kinds.flatMap(kind => catalogue.targets[kind] || []);
  const granted = (target, capability) => (!target.capabilities || target.capabilities.includes(capability)) && module.grants.some(grant =>
    grant.capability === capability && grant.target_ids.includes(target.id));
  const targets = [...new Map(candidates.filter(target => required.length ?
    required.every(capability => granted(target, capability)) : optional.some(capability => granted(target, capability)))
    .map(target => [target.id, target])).values()];
  return { targets, required: required.length > 0 };
}

export async function selectTargets(module, selected = []) {
  if (!module.manifest.capabilities.some(capability => !workspaceCapability(capability))) return [];
  const catalogue = await request('/module-targets');
  const { targets, required } = targetOptions(module, catalogue);
  if (!targets.length) {
    if (!required) return [];
    throw Error('Grant this module access to a target in Manage modules first.');
  }
  return new Promise(resolve => {
    let result = null;
    const dialog = el('dialog', { 'aria-label': 'Module targets', class: 'module-manager' });
    const choices = targets.map(target => {
      const input = el('input', { type: 'checkbox' }); input.checked = selected.includes(target.id);
      return { id: target.id, input, element: el('label', {}, input, ` ${target.name}`) };
    });
    const status = el('div', { role: 'status' });
    dialog.append(el('h2', {}, 'Select module targets'),
      el('p', {}, 'This panel can request actions only for these selected targets. Each action also requires current package grants.'),
      el('fieldset', {}, el('legend', {}, module.manifest.display_name || module.manifest.id), choices.map(item => item.element)),
      status, button('Use selected targets', () => {
        const ids = choices.filter(item => item.input.checked).map(item => item.id);
        if ((required && !ids.length) || ids.length > 64) {
          status.replaceChildren(notice(required ? 'Select between one and 64 targets.' : 'Select at most 64 targets.', 'error')); return;
        }
        result = ids; dialog.close();
      }), button('Cancel', () => dialog.close()));
    dialog.addEventListener('close', () => { dialog.remove(); resolve(result); }, { once: true });
    document.body.append(dialog); dialog.showModal();
  });
}
