// SPDX-License-Identifier: Apache-2.0
// Prepare bounded file previews without interpreting remote names as paths or markup.
import { request } from './api.js';
import { button, el, errorPanel, notice, state } from './components.js';
import { fileDialog } from './file-dialog.js';

export function fileAction(action, pane, recorded, transferred) {
  const value = pane.value(), ids = value.entries.map(entry => entry.entry_id);
  if (action === 'preview') { previewFile(value); return; }
  if (action === 'download') { transferPreview('download', value, null, transferred); return; }
  if (action === 'upload') { chooseUpload(value, transferred); return; }
  const view = fileDialog(action === 'delete' ? 'Delete selected entries' : 'Change registered files');
  const body = { action, root_id: value.root.id, entries: ids };
  if (action === 'delete') { view.preview('/file-operation-previews', body, '/file-operations', recorded, [['Root', value.root.display_label]]); return; }
  const name = el('input', { id: 'file-new-name', required: true, maxlength: 255, autocomplete: 'off' });
  const mode = el('input', { id: 'file-new-mode', required: true, pattern: '[0-7]{3}', value: '640', maxlength: 3, inputmode: 'numeric' });
  const errors = el('div');
  view.content.append(notice(`Root: ${value.root.display_label}. The next step previews exact affected entries.`),
    el('form', { onsubmit: event => {
      event.preventDefault();
      if (action === 'mode') body.mode = parseInt(mode.value, 8);
      else {
        if (['.', '..'].includes(name.value) || /[\0/]/.test(name.value) || new TextEncoder().encode(name.value).length > 255) {
          errors.replaceChildren(notice('Use a name of at most 255 UTF-8 bytes without slash, NUL, dot or dot-dot.', 'error')); return;
        }
        body.name = name.value; body.parent_id = value.entry_id;
        if (action === 'mkdir') body.entries = [];
      }
      view.preview('/file-operation-previews', body, '/file-operations', recorded, [['Root', value.root.display_label],
        action === 'mode' ? ['Requested mode', mode.value] : ['New name', name.value]]);
    } }, el('label', { for: action === 'mode' ? mode.id : name.id }, action === 'mode' ? 'Ordinary mode (three octal digits)' : 'New name'),
    action === 'mode' ? mode : name,
    notice(action === 'mode' ? 'Only owner-controlled ordinary files and directories permit mode changes. No ownership or special permission bits.' : 'Names are literal. Rename never overwrites an existing destination.'),
    errors, el('div', { class: 'actions' }, el('button', { type: 'submit', class: 'primary' }, 'Preview exact change'))));
  (action === 'mode' ? mode : name).focus();
}

async function previewFile(value) {
  const view = fileDialog(`Preview: ${value.entries[0].name}`);
  view.content.append(state('Loading preview', 'Reading at most 64 KiB as safe text.'));
  try {
    const result = await request('/files/preview', { method: 'POST', body: { root_id: value.root.id, entry_id: value.entries[0].entry_id, limit: 65536 } });
    if (!view.active()) return;
    const text = result.encoding === 'utf-8' ? new TextDecoder().decode(Uint8Array.from(atob(result.data_base64), c => c.charCodeAt(0))) : null;
    view.content.replaceChildren(notice(`${result.bytes} preview bytes${result.truncated ? '; preview truncated' : ''}. Remote content is displayed only as text.`),
      text === null ? state('Binary file', 'Use Download to retrieve this file. Binary content is not rendered.') : el('pre', { class: 'file-content', tabindex: '0' }, text));
  } catch (error) { if (view.active()) view.content.replaceChildren(errorPanel(error)); }
}

export function transferPreview(kind, source, destination, received, files = null) {
  const view = fileDialog(kind === 'copy' ? 'Copy selected files' : kind === 'upload' ? 'Upload browser files' : 'Download selected files');
  const sources = files ? files.map(file => ({ name: file.name, size: file.size, last_modified: file.lastModified })) :
    source.entries.map(entry => ({ root_id: source.root.id, entry_id: entry.entry_id }));
  const body = { kind, sources, overwrite: false };
  if (destination) body.destination = { root_id: destination.root.id, entry_id: destination.entry_id };
  const overwrite = el('input', { id: 'transfer-overwrite', type: 'checkbox' });
  view.content.append(el('p', {}, destination ? `Destination: ${destination.root.display_label}` : 'Prepare verified files for browser download.'),
    el('ul', { class: 'file-selected-names' }, (files ?? source.entries).map(item => el('li', {}, item.name))),
    kind === 'download' ? notice('FICC verifies the server download copy. The browser controls saving; FICC cannot attest that the browser saved these bytes.') :
      el('label', { class: 'check-label', for: overwrite.id }, overwrite, 'Allow replacement of existing destination files identified in the preview.'),
    el('div', { class: 'actions' }, button('Preview transfer', () => {
      body.overwrite = overwrite.checked;
      view.preview('/transfer-previews', body, '/transfers', result => received(result, files),
        [['Source', files ? 'Selected browser files' : source.root.display_label], ['Destination', destination?.root.display_label ?? 'Verified browser download']]);
    }, { class: 'primary' })));
}

export function chooseUpload(destination, received) {
  const view = fileDialog('Select browser files');
  const picker = el('input', { id: 'browser-files', type: 'file', multiple: true, required: true });
  const error = el('div');
  view.content.append(notice(`Upload to ${destination.root.display_label}. Each file is sent in bounded chunks and verified before replacement.`),
    el('form', { onsubmit: event => {
      event.preventDefault();
      const files = [...picker.files];
      if (!files.length || files.length > 64 || files.some(file => file.size > 17179869184)) {
        error.replaceChildren(notice('Select 1 to 64 files, each at most 16 GiB.', 'error')); return;
      }
      if (new Set(files.map(file => file.name)).size !== files.length) { error.replaceChildren(notice('Each selected file must have a distinct name.', 'error')); return; }
      view.dialog.close(); transferPreview('upload', null, destination, received, files);
    } }, el('label', { for: picker.id }, 'Files to upload'), picker, error,
    el('div', { class: 'actions' }, el('button', { type: 'submit', class: 'primary' }, 'Review upload'))));
}
