// SPDX-License-Identifier: Apache-2.0
// Manage the local browser session and console navigation.
import { connect, getSession, request, setSession } from './api.js';
import { button, el, errorPanel, state } from './components.js';
import { jobs } from './jobs.js';
import { overview } from './overview.js';
import { access, activity } from './access.js';

const main = document.querySelector('#main');
const nav = [...document.querySelectorAll('[data-view]')];
const signOut = document.querySelector('#sign-out');
let current;

function navigate(view, focus = false) {
  if (!getSession()) return;
  current?.dispose();
  current = ({ overview, jobs, access, activity })[view]();
  main.replaceChildren(current.element);
  for (const item of nav) {
    if (item.dataset.view === view) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  }
  if (focus) main.focus();
}
for (const item of nav) item.addEventListener('click', () => navigate(item.dataset.view, true));

function locked(message = 'Open this console with the FICC command line to start an authenticated session.') {
  current?.dispose(); current = null;
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  setSession(null);
  document.querySelector('#account').textContent = 'Session required';
  document.querySelector('#connection').textContent = 'Console locked';
  document.querySelector('#mode-banner').hidden = true;
  signOut.hidden = true;
  for (const item of nav) item.disabled = true;
  main.replaceChildren(el('div', { class: 'login-panel' }, el('p', { class: 'eyebrow' }, 'LOCAL OWNER ACCESS'),
    el('h1', {}, 'Console locked'), el('p', {}, message),
    el('div', { class: 'command-well' }, el('span', {}, 'Run in your local terminal'), el('code', {}, 'ficc open')),
    el('p', { class: 'muted' }, 'The command opens a one-use sign-in link. Keep that link private.'),
    button('Check session', start)));
}
window.addEventListener('session-expired', () => locked('Your session expired or was revoked. Run ficc open to sign in again.'));
signOut.addEventListener('click', async () => {
  signOut.disabled = true;
  try { await request('/session', { method: 'DELETE' }); locked('You signed out. Run ficc open to start a new session.'); }
  catch (error) { if (getSession()) main.prepend(errorPanel(error)); }
  finally { signOut.disabled = false; }
});

async function start() {
  const hasBootstrap = new URLSearchParams(location.hash.slice(1)).has('bootstrap');
  main.replaceChildren(state('Opening console', 'Checking the authenticated session.'));
  try {
    const session = await connect();
    document.querySelector('#account').textContent = session.principal.label;
    document.querySelector('#version').textContent = `FICC / ${session.version}`;
    signOut.hidden = false;
    for (const item of nav) item.disabled = false;
    const banner = document.querySelector('#mode-banner');
    banner.hidden = session.mode !== 'demo';
    banner.textContent = 'SIMULATION MODE / All machines and resource values are simulated. Live SSH adapters are disabled.';
    navigate('overview');
  } catch (error) {
    if ([401, 403].includes(error.status)) locked(hasBootstrap ?
      'This sign-in link is invalid, expired or already used. Run ficc open for a new link.' : undefined);
    else main.replaceChildren(errorPanel(error, start));
  }
}
start();
