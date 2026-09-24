// SPDX-License-Identifier: Apache-2.0
// Attach one bounded terminal stream without recording or replaying input.
import { Terminal } from './vendor/xterm/xterm.mjs';
import { FitAddon } from './vendor/addon-fit/addon-fit.mjs';
import { request } from './api.js';
import { button, el, notice } from './components.js';

const INPUT_FRAME = 16384, INPUT_BUFFER = 65536, OUTPUT_BUFFER = 262144;

export function terminalStream(record, changed, select = () => {}) {
  let active = true, ended = false, attached = false, socket, pending = 0, resizeTimer, opened = false;
  let visible = false, selected = false, focusRequested = false;
  const status = el('div', {}, notice('Connecting. Keyboard input is disabled.'));
  const host = el('div', { class: 'terminal-well', role: 'region', 'aria-label': `${record.node_name} terminal output` });
  const focus = button('Focus terminal', () => { select(true); focusInput(); }, { disabled: true });
  const detach = button('Detach', () => finish('detached', record.mode === 'tmux' ?
    'Detached. The remote tmux session can continue. Reattach explicitly to continue.' :
    'Detached. The ephemeral shell closes with its connection. Input was not replayed.'));
  const element = el('section', { class: 'terminal-session' },
    el('div', { class: 'terminal-identity' }, el('strong', {}, `${record.node_name} / ${record.account}`),
      el('span', {}, record.mode === 'tmux' ? 'TMUX SESSION' : 'EPHEMERAL SHELL')),
    status, el('div', { class: 'actions terminal-actions' }, focus, detach), host,
    el('p', { class: 'terminal-help muted' }, 'Ctrl+Shift+Escape: toolbar. Output is not recorded.'));
  const term = new Terminal({ cols: 80, rows: 24, scrollback: 2000, fontSize: 14,
    fontFamily: 'JetBrains, monospace', minimumContrastRatio: 4.5, screenReaderMode: true,
    cursorBlink: false, smoothScrollDuration: 0, allowProposedApi: false,
    windowOptions: {}, disableStdin: true, logLevel: 'off',
    linkHandler: { activate() {} }, theme: { background: '#242a31', foreground: '#f6f4ef', cursor: '#f3a94e' } });
  for (const code of [0, 1, 2, 8, 52]) term.parser.registerOscHandler(code, () => true);
  const fit = new FitAddon(); term.loadAddon(fit);
  host.addEventListener('pointerdown', () => { if (visible) select(false); });
  host.addEventListener('focusin', () => { if (visible) select(false); });
  term.attachCustomKeyEventHandler(event => {
    if (event.ctrlKey && event.shiftKey && event.key === 'Escape') {
      if (event.type === 'keydown') focus.focus();
      event.preventDefault(); return false;
    }
    return true;
  });
  term.onData(data => sendInput(new TextEncoder().encode(data)));
  term.onBinary(data => sendInput(Uint8Array.from(data, character => character.charCodeAt(0) & 255)));
  function sendInput(bytes) {
    if (!active || ended || !attached || !visible || !selected || !host.contains(document.activeElement) || socket?.readyState !== WebSocket.OPEN) return;
    if (bytes.length > INPUT_FRAME || socket.bufferedAmount + bytes.length > INPUT_BUFFER) {
      status.replaceChildren(notice('Input was refused: a paste must fit within 16 KiB and the connection must have space. Input is never queued for retry.', 'warning'));
      return;
    }
    socket.send(bytes);
  }
  function sendControl(value) {
    if (active && socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify(value));
  }
  function resize() {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (!active || ended || !opened || !visible || !host.isConnected || host.clientWidth < 20 || host.clientHeight < 20) return;
      const size = fit.proposeDimensions();
      if (!size) return;
      const cols = Math.min(300, Math.max(2, size.cols)), rows = Math.min(120, Math.max(2, size.rows));
      if (cols === term.cols && rows === term.rows) return;
      term.resize(cols, rows);
      if (attached) sendControl({ type: 'resize', cols, rows });
    }, 100);
  }
  const observer = new ResizeObserver(resize);
  function focusInput() {
    if (active && !ended && attached && visible && selected) term.focus();
  }
  function presentation(nextVisible, nextSelected, requestFocus = false) {
    visible = nextVisible; selected = nextSelected;
    if (!visible || !selected) { focusRequested = false; term.blur(); }
    else if (requestFocus) { focusRequested = true; focusInput(); }
    term.options.disableStdin = !active || ended || !attached || !visible || !selected;
    if (visible) resize();
  }
  function finish(state, message) {
    if (!active || ended) return;
    ended = true; focusRequested = false;
    attached = false; term.options.disableStdin = true; focus.disabled = true; detach.disabled = true;
    status.replaceChildren(notice(message, ['error', 'denied', 'output_gap'].includes(state) ? 'error' : 'warning'));
    if (socket && socket.readyState < WebSocket.CLOSING) socket.close();
    changed(state);
  }
  async function open() {
    if (!active || ended || opened) return;
    opened = true; term.open(host); observer.observe(host);
    await document.fonts.ready;
    if (!active || ended) return;
    resize();
    try {
      const value = await request(`/terminals/${encodeURIComponent(record.id)}/tickets`, { method: 'POST', body: {} });
      if (!active || ended) return;
      const url = new URL(value.websocket_path, location.href);
      if (url.origin !== location.origin || url.search || url.hash ||
          url.pathname !== `/api/v1/terminals/${encodeURIComponent(record.id)}/stream`) throw new Error('The terminal connection address is invalid.');
      url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      socket = new WebSocket(url); socket.binaryType = 'arraybuffer';
      socket.addEventListener('open', () => { if (active && !ended) socket.send(JSON.stringify({ type: 'auth', ticket: value.ticket })); });
      socket.addEventListener('message', event => {
        if (!active || ended) return;
        if (event.data instanceof ArrayBuffer) {
          const bytes = new Uint8Array(event.data);
          if (!attached || bytes.length > 32768 || pending + bytes.length > OUTPUT_BUFFER) {
            finish('output_gap', 'Output exceeded the bounded connection. This view has an output gap. Reattach explicitly; input will not be replayed.'); return;
          }
          pending += bytes.length;
          term.write(bytes, () => {
            pending -= bytes.length;
            if (attached && active && bytes.length) sendControl({ type: 'ack', bytes: bytes.length });
          });
          return;
        }
        try {
          if (typeof event.data !== 'string' || event.data.length > 4096) throw new Error();
          const message = JSON.parse(event.data);
          if (message.type !== 'status' || !['attached', 'detached', 'exited', 'denied', 'output_gap', 'error'].includes(message.state)) throw new Error();
          if (message.state === 'attached') {
            attached = true; term.options.disableStdin = !visible || !selected; focus.disabled = false;
            status.replaceChildren(notice('Attached. Input goes only to the machine and account shown above.'));
            if (visible) sendControl({ type: 'resize', cols: term.cols, rows: term.rows });
            if (focusRequested && (document.activeElement === document.body || element.contains(document.activeElement))) focusInput();
            changed('attached');
          } else {
            if (message.state === 'denied') { term.reset(); host.replaceChildren(); }
            finish(message.state, typeof message.message === 'string' ? message.message : `Terminal ${message.state.replaceAll('_', ' ')}. Input is disabled.`);
          }
        } catch { finish('error', 'The terminal sent an invalid status. Input is disabled.'); }
      });
      socket.addEventListener('close', () => {
        if (active && !detach.disabled) finish('detached', 'Connection closed. The last input outcome may be unknown. Reattach explicitly; input is never replayed.');
      });
      socket.addEventListener('error', () => finish('error', 'Terminal connection failed. Check its recorded state before attaching again.'));
    } catch (error) {
      if (!active || ended) return;
      if ([401, 403].includes(error.status)) { term.reset(); host.replaceChildren(); }
      finish([401, 403].includes(error.status) ? 'denied' : 'error', error.message);
    }
  }
  return { element, open, presentation, focus: focusInput, refit: resize, get ended() { return ended; }, dispose() {
    if (!active) return;
    active = false; ended = true; attached = false; clearTimeout(resizeTimer); observer.disconnect();
    if (socket && socket.readyState < WebSocket.CLOSING) socket.close();
    term.dispose();
  } };
}
