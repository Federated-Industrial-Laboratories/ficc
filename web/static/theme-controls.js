// SPDX-License-Identifier: Apache-2.0
// Provide an accessible theme catalogue with local import, export and flat materials.
import { button, el } from './components.js';
import { appearance, initializeAppearance, selectTheme, setFlatMaterials, importTheme,
  removeTheme, resetAppearance, exportTheme } from './theme.js';
import { MAX_THEME_BYTES } from './theme-format.js';

export async function openAppearance() {
  if (document.querySelector('#appearance-dialog')) return;
  await initializeAppearance();
  if (document.querySelector('#appearance-dialog')) return;
  const close = button('Done', () => dialog.close(), { class: 'primary' });
  const search = el('input', { type: 'search', id: 'theme-search', placeholder: 'Search themes', autocomplete: 'off' });
  const scheme = el('select', { id: 'theme-scheme' }, el('option', { value: '' }, 'All themes'),
    el('option', { value: 'light' }, 'Light themes'), el('option', { value: 'dark' }, 'Dark themes'),
    el('option', { value: 'custom' }, 'My themes'));
  const catalogue = el('div', { class: 'theme-catalogue', 'aria-label': 'Theme collection' });
  let catalogueIdentity = '';
  const count = el('p', { class: 'muted theme-count', role: 'status' });
  const title = el('strong'), description = el('p', { class: 'muted' });
  const flat = el('input', { type: 'checkbox', id: 'theme-flat', 'aria-label': 'Flat materials', 'aria-describedby': 'theme-flat-help' });
  const feedback = el('p', { class: 'theme-feedback', role: 'status', 'aria-live': 'polite' });
  const warning = el('p', { class: 'notice warning', role: 'status', hidden: true });
  const file = el('input', { type: 'file', accept: '.json,application/json', hidden: true, 'aria-label': 'Import theme JSON' });
  const remove = button('Remove custom theme', () => {
    const name = appearance().theme.name;
    removeTheme(); feedback.textContent = `${name} removed from this browser.`;
  }, { class: 'danger-text' });
  const dialog = el('dialog', { id: 'appearance-dialog', class: 'appearance-dialog', 'aria-labelledby': 'appearance-title' },
    el('div', { class: 'dialog-heading' }, el('h2', { id: 'appearance-title' }, 'Appearance'),
      button('Close', () => dialog.close(), { 'aria-label': 'Close appearance', class: 'quiet' })),
    el('p', { class: 'muted' }, 'Make this console your own. Changes apply immediately and are saved in this browser.'),
    el('div', { class: 'theme-filters' }, el('div', {}, el('label', { for: 'theme-search' }, 'Find a theme'), search),
      el('div', {}, el('label', { for: 'theme-scheme' }, 'Collection'), scheme)), count, catalogue,
    el('div', { class: 'theme-current' }, title, description,
      el('label', { class: 'check-label', for: 'theme-flat' }, flat,
        el('span', {}, el('strong', {}, 'Flat materials'), el('small', { id: 'theme-flat-help' }, 'Disable all material gradients and the background grid.')))),
    warning, feedback,
    el('div', { class: 'actions theme-tools' }, button('Import JSON', () => file.click()),
      button('Export JSON', download), remove, file),
    el('details', { class: 'theme-help' }, el('summary', {}, 'Design your own theme'),
      el('p', {}, 'Export a theme, give it a new id and name, then edit its colors, materials or logo in a text editor. Import the JSON to try it. Colors use #RRGGBB; gradients use angles and stops. Custom graphics use vector paths.'),
      el('p', { class: 'muted' }, 'Up to 32 custom themes, 64 KiB each. Importing the same custom id updates it. Export custom themes before clearing browser data. See docs/themes.md in the FICC documentation for the full format.')),
    el('div', { class: 'actions theme-footer' }, button('Restore Classic Light', () => {
      resetAppearance(); feedback.textContent = 'Classic Light restored. Custom themes are kept.';
    }), close));

  function download() {
    const selected = appearance().theme;
    const href = URL.createObjectURL(new Blob([exportTheme()], { type: 'application/json' }));
    const link = el('a', { href, download: `${selected.id}.json` });
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(href), 1000);
    feedback.textContent = 'Theme exported. Use a new id when customising a built-in theme.';
  }
  function renderCatalogue() {
    const value = appearance(), query = search.value.toLocaleLowerCase().trim();
    catalogueIdentity = JSON.stringify(value.themes);
    const matches = value.themes.filter(theme => (!scheme.value || (scheme.value === 'custom' ? value.customIds.includes(theme.id) : theme.scheme === scheme.value)) &&
      `${theme.name} ${theme.description}`.toLocaleLowerCase().includes(query));
    catalogue.replaceChildren(...matches.map(theme => {
      const swatches = el('span', { class: 'theme-swatches', 'aria-hidden': 'true' },
        ...['white', 'surface', 'orange', 'ink'].map(key => {
          const swatch = el('i'); swatch.style.backgroundColor = theme.colors[key]; return swatch;
        }));
      const card = button('', () => { selectTheme(theme.id); feedback.textContent = `${theme.name} applied.`; },
        { class: 'theme-card', 'data-theme-id': theme.id, 'aria-pressed': String(theme.id === value.selected),
          'aria-label': theme.name, title: theme.description });
      card.append(el('span', { class: 'theme-card-content' }, swatches, el('strong', {}, theme.name),
        el('small', {}, `${theme.scheme === 'light' ? 'Light' : 'Dark'}${value.customIds.includes(theme.id) ? ' / Custom' : ''}`)));
      return card;
    }));
    count.textContent = `${matches.length} theme${matches.length === 1 ? '' : 's'}${matches.length ? '' : ' found. Try another search.'}`;
  }
  function update() {
    const value = appearance();
    if (catalogueIdentity !== JSON.stringify(value.themes)) renderCatalogue();
    title.textContent = value.theme.name; description.textContent = value.theme.description;
    flat.checked = value.flat; remove.hidden = !value.customIds.includes(value.selected);
    warning.hidden = !value.message; warning.textContent = value.message;
    for (const card of catalogue.querySelectorAll('[data-theme-id]')) {
      card.setAttribute('aria-pressed', String(card.dataset.themeId === value.selected));
    }
  }
  search.addEventListener('input', renderCatalogue); scheme.addEventListener('change', renderCatalogue);
  flat.addEventListener('change', () => { setFlatMaterials(flat.checked); feedback.textContent = flat.checked ? 'Flat materials applied.' : 'Theme materials restored.'; });
  file.addEventListener('change', async () => {
    const selected = file.files?.[0]; if (!selected) return;
    try {
      if (selected.size > MAX_THEME_BYTES) throw Error('Theme exceeds 64 KiB.');
      const source = await selected.text();
      if (!dialog.isConnected) return;
      const name = importTheme(source); search.value = ''; scheme.value = ''; renderCatalogue(); update();
      feedback.textContent = `${name} imported and applied.`;
    } catch (error) { feedback.textContent = `Import failed: ${error.message}`; }
    finally { file.value = ''; }
  });
  window.addEventListener('ficc-theme-changed', update);
  dialog.addEventListener('close', () => { window.removeEventListener('ficc-theme-changed', update); dialog.remove(); });
  (document.fullscreenElement ?? document.body).append(dialog); renderCatalogue(); update(); dialog.showModal(); search.focus();
}
