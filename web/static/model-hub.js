// SPDX-License-Identifier: Apache-2.0
// Resolve public publisher metadata before registering an immutable GGUF revision.
import { button, bytes, el, notice } from './components.js';

export function modelHub(send, done) {
  const repository = el('input', { 'aria-label': 'Hugging Face repository', placeholder: 'Qwen/Qwen3-0.6B-GGUF' });
  const revision = el('input', { 'aria-label': 'Source revision', value: 'main' });
  const filename = el('input', { 'aria-label': 'Exact GGUF filename (optional)' });
  const licence = el('input', { 'aria-label': 'Publisher licence (if missing)' });
  const choices = el('select', { 'aria-label': 'Model quantization and size' }), status = el('div');
  let manifests = [], selected = null;
  const dialog = el('dialog', { class: 'workload-dialog' });
  const register = button('Register selected revision', async () => {
    try {
      register.disabled = true;
      await send('/models', { method: 'POST', body: selected });
      dialog.close(); await done();
    } catch (error) { status.replaceChildren(notice(error.message, 'error')); register.disabled = !selected; }
  }, { disabled: true });
  const change = () => {
    selected = manifests[Number(choices.value)]; register.disabled = !selected;
    if (selected) status.replaceChildren(notice(`${selected.licence} / commit ${selected.revision}. Registration adds metadata; use Acquire HTTPS or Upload files to store the weights.`));
  };
  choices.addEventListener('change', change);
  for (const input of [repository, revision, filename, licence]) input.addEventListener('input', () => { selected = null; register.disabled = true; });
  const inspect = button('Find available weights', async () => {
    try {
      inspect.disabled = true; register.disabled = true;
      const result = await send('/models/hub-preview', { method: 'POST', body: { repository: repository.value, revision: revision.value,
        ...(filename.value ? { filename: filename.value } : {}), ...(licence.value ? { licence: licence.value } : {}) } });
      manifests = result.manifests;
      choices.replaceChildren(...manifests.map((item, index) => el('option', { value: String(index) }, `${item.entrypoint} / ${bytes(item.files[0].bytes)}`)));
      change();
    } catch (error) { status.replaceChildren(notice(error.message, 'error')); } finally { inspect.disabled = false; }
  });
  const field = (label, control) => el('label', { class: 'field' }, el('span', {}, label), control);
  dialog.append(el('h2', {}, 'Import from Hugging Face'), el('p', {}, 'Choose public GGUF weights. FICC resolves the source commit, size and SHA256 before registration.'),
    field('Repository', repository), field('Branch, tag or commit', revision), field('Exact GGUF filename (optional)', filename),
    field('Publisher licence (only if the model card omits it)', licence), inspect, field('Available weights', choices), status, register, button('Cancel', () => dialog.close()));
  dialog.addEventListener('close', () => dialog.remove()); document.body.append(dialog); dialog.showModal();
  return dialog;
}
