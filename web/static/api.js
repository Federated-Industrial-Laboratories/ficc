// SPDX-License-Identifier: Apache-2.0
// Exchange authenticated requests without persistent browser credentials.
let session = null;
export function getSession() { return session; }
export function setSession(value) { session = value; }
export function allowed(scope) { return session?.principal.scopes.includes(scope); }

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export async function request(path, { method = 'GET', body, signal, idempotencyKey } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 35000);
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  const headers = { Accept: 'application/json' };
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && session) headers['X-CSRF-Token'] = session.csrf;
  try {
    const response = await fetch(`/api/v1${path}`, {
      method, headers, credentials: 'same-origin', cache: 'no-store',
      body: body === undefined ? undefined : JSON.stringify(body), signal: controller.signal,
    });
    const result = await response.json();
    if (!response.ok) {
      if (response.status === 401 && session) {
        session = null;
        window.dispatchEvent(new Event('session-expired'));
      }
      throw new ApiError(response.status, result.error?.code ?? 'request_failed',
        result.error?.message ?? 'The service could not complete this request.');
    }
    return result;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(0, 'disconnected', 'The local service is unavailable. Check that FICC is running, then retry.');
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}

export async function connect() {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const bootstrap = fragment.get('bootstrap');
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  session = await request('/session', bootstrap ? { method: 'POST', body: { bootstrap } } : {});
  return session;
}
