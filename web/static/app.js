// SPDX-License-Identifier: Apache-2.0
// Manage the local browser session and console navigation.
import { allowed, connect, getSession, request, setSession } from './api.js';
import { button, el, errorPanel, state } from './components.js';
import { jobs } from './jobs.js';
import { terminals } from './terminals.js';
import { files } from './files.js';
import { overview } from './overview.js';
import { access, activity } from './access.js';
import { agents } from './agents.js';
import { bus } from './bus.js';
import { workspaces } from './workspaces.js';
import { remoteLogin } from './remote-login.js';
import { contributors } from './contributors.js';
import { workloads } from './workloads.js';
import { sources } from './sources.js';
import { operations } from './operations.js';
import { initializeAppearance } from './theme.js';
import { openAppearance } from './theme-controls.js';

void initializeAppearance();
document.querySelector('#appearance-open').addEventListener('click', openAppearance);

const main = document.querySelector('#main');
const nav = [...document.querySelectorAll('[data-view]')];
const signOut = document.querySelector('#sign-out');
const projectSelect = document.querySelector('#project-select');
let current, currentView, navigating = false, changingProject = false;

function updateNavigation() {
  const scopes = { overview: 'nodes:read', jobs: 'jobs:read', files: 'files:read', terminals: 'terminals:read',
    agents: 'agents:read', bus: 'bus:read', activity: 'audit:read', workspaces: 'workspaces:read', contributors: 'contributors:read', workloads: 'jobs:read', sources: 'data:read', operations: 'audit:read' };
  for (const item of nav) item.disabled = !getSession() || changingProject ||
    (scopes[item.dataset.view] ? !allowed(scopes[item.dataset.view]) : false);
}

async function navigate(view, focus = false) {
  if (!getSession()) return;
  if (navigating || current && currentView === view) return;
  navigating = true;
  try {
  if (current?.prepareLeave && !await current.prepareLeave()) return;
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  current?.dispose();
  current = ({ overview, jobs, files, terminals, agents, bus, access, activity, workspaces, contributors, workloads, sources, operations })[view]();
  currentView = view;
  main.replaceChildren(current.element);
  for (const item of nav) {
    if (item.dataset.view === view) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  }
  if (focus) main.focus();
  } finally { navigating = false; }
}
for (const item of nav) item.addEventListener('click', () => navigate(item.dataset.view, true));
window.addEventListener('ficc-open-terminal', async event => {
  if (!getSession() || typeof event.detail?.terminalId !== 'string') return;
  await navigate('terminals', true);
  if (currentView === 'terminals') current.openTerminal(event.detail.terminalId);
});

function locked(message = 'Open this console with the FICC command line to start an authenticated session.') {
  current?.dispose(); current = null; currentView = null;
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  setSession(null);
  document.querySelector('#account').textContent = 'Session required';
  document.querySelector('#connection').textContent = 'Console locked';
  document.querySelector('#mode-banner').hidden = true;
  signOut.hidden = true;
  projectSelect.hidden = true;
  for (const item of nav) item.disabled = true;
  const login = el('div', { class: 'login-panel' }, el('p', { class: 'eyebrow' }, 'LOCAL OWNER ACCESS'),
    el('h1', {}, 'Console locked'), el('p', {}, message),
    el('div', { class: 'command-well' }, el('span', {}, 'Run in your local terminal'), el('code', {}, 'ficc open')),
    el('p', { class: 'muted' }, 'The command opens a one-use sign-in link. Keep that link private.'),
    button('Check session', start));
  main.replaceChildren(login);
  void remoteLogin(login, getSession);
}
window.addEventListener('session-expired', () => locked('Your session expired or was revoked. Run ficc open to sign in again.'));
signOut.addEventListener('click', async () => {
  signOut.disabled = true;
  try {
    if (current?.prepareLeave && !await current.prepareLeave()) return;
    await request('/session', { method: 'DELETE' }); locked('You signed out. Run ficc open to start a new session.');
  }
  catch (error) { if (getSession()) main.prepend(errorPanel(error)); }
  finally { signOut.disabled = false; }
});

async function refreshProjects() {
  const session = getSession(); if (!session) return;
  const { projects } = await request('/projects');
  if (getSession() !== session) return;
  projectSelect.replaceChildren(...projects.filter(project => !project.disabled).map(project => el('option', { value: project.id }, project.label)));
  projectSelect.value = session.principal.project_id; projectSelect.hidden = false;
}
window.addEventListener('ficc-projects-changed', () => { void refreshProjects().catch(error => main.prepend(errorPanel(error))); });

async function start() {
  const hasBootstrap = new URLSearchParams(location.hash.slice(1)).has('bootstrap');
  main.replaceChildren(state('Opening console', 'Checking the authenticated session.'));
  try {
    const session = await connect();
    document.querySelector('#account').textContent = session.identity?.label || session.principal.label;
    document.querySelector('#version').textContent = `FICC / ${session.version}`;
    document.querySelector('#connection').textContent = session.mode === 'demo' ? 'Simulation service connected' :
      session.remote ? 'Secure remote service connected' : 'Local service connected';
    document.querySelector('.owner .eyebrow').textContent = session.remote ? 'SECURE REMOTE INTERFACE' : 'LOCAL CONTROL INTERFACE';
    document.querySelector('.rail-note p').replaceChildren(session.principal.local_owner ? 'Local owner console.' : 'Project workspace.',
      el('br'), session.principal.local_owner ? 'Verified SSH transport.' : session.remote ? 'Individual remote access.' : 'Local authenticated access.');
    signOut.hidden = false;
    updateNavigation();
    await refreshProjects();
    const banner = document.querySelector('#mode-banner');
    banner.hidden = session.mode !== 'demo';
    banner.textContent = 'SIMULATION MODE / All machines and resource values are simulated. Live SSH adapters are disabled.';
    const query = new URLSearchParams(location.search);
    document.body.classList.toggle('workspace-window', query.get('window') === '1');
    await navigate((query.has('surface') || query.has('workspace') || !allowed('nodes:read')) && allowed('workspaces:read') ? 'workspaces' : allowed('nodes:read') ? 'overview' : 'access');
  } catch (error) {
    if ([401, 403].includes(error.status)) locked(hasBootstrap ?
      'This sign-in link is invalid, expired or already used. Run ficc open for a new link.' : undefined);
    else main.replaceChildren(errorPanel(error, start));
  }
}
projectSelect.addEventListener('change', async () => {
  if (changingProject) return;
  const previous = getSession()?.principal.project_id;
  changingProject = true; projectSelect.disabled = true; signOut.disabled = true;
  updateNavigation();
  main.inert = true;
  try {
    if (current?.prepareLeave && !await current.prepareLeave()) { projectSelect.value = previous; return; }
    const session = await request('/session/project', { method: 'POST', body: { project_id: projectSelect.value } });
    current?.dispose(); current = null; currentView = null;
    setSession(session);
    history.replaceState(null, '', '/');
    await start();
  } catch (error) { projectSelect.value = previous; main.prepend(errorPanel(error)); }
  finally {
    changingProject = false; projectSelect.disabled = false; signOut.disabled = false;
    main.inert = false; updateNavigation();
  }
});
start();
