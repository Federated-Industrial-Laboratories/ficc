// SPDX-License-Identifier: Apache-2.0
// Present external sign-in without exposing identity-provider credentials to the browser.
import { button, el, errorPanel } from './components.js';

export async function remoteLogin(container, current) {
  try {
    const response = await fetch('/api/v1/login', { credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok) return;
    const status = await response.json();
    if (!status.remote || !container.isConnected || current()) return;
    document.querySelector('.owner .eyebrow').textContent = 'SECURE REMOTE INTERFACE';
    document.querySelector('.rail-note p').replaceChildren('Organisation sign-in.', el('br'), 'Individual remote access.');
    const query = new URLSearchParams(location.search), result = query.get('login');
    query.delete('login');
    history.replaceState(null, '', location.pathname + (query.size ? '?' + query : '') + location.hash);
    const message = el('div', { role: 'status' });
    if (result) message.textContent = result === 'unapproved' ?
      'An administrator must approve your identity and project membership before you can sign in.' :
      'Sign-in could not be completed. Start a new sign-in to try again.';
    const signIn = button('Sign in with organisation account', async () => {
      signIn.disabled = true;
      try {
        const started = await fetch('/auth/start', { method: 'POST', credentials: 'same-origin', cache: 'no-store' });
        const value = await started.json();
        if (!started.ok) throw new Error(value.error?.message || 'Sign-in is unavailable.');
        const target = new URL(value.url);
        if (target.protocol !== 'https:') throw new Error('The sign-in address is invalid.');
        location.assign(target.href);
      } catch (error) { if (container.isConnected) message.replaceChildren(errorPanel(error)); signIn.disabled = false; }
    }, { disabled: !status.configured });
    container.replaceChildren(el('p', { class: 'eyebrow' }, 'ORGANISATION ACCESS'),
      el('h1', {}, 'Sign in to FICC'),
      el('p', {}, 'Use your organisation account and its required authentication factors.'),
      signIn, message,
      ...(!status.ready ? [el('p', { class: 'muted' }, status.configured ?
        'The identity service is unavailable. Sign in again when it is ready.' :
        'The installation administrator must configure external sign-in.')] : []),
      el('p', { class: 'muted' }, 'Local recovery remains available to the administrator on the controller host.'));
  } catch { /* The existing local recovery instructions remain available. */ }
}
