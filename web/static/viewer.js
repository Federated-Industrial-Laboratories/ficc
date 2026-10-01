// SPDX-License-Identifier: Apache-2.0
// Own one display connection with explicit input capture and safe release controls.
import { request } from './api.js';
import { button, el } from './components.js';
import { fullscreen } from './fullscreen.js';

let assets;
function loadAssets() {
  if (globalThis.Guacamole) return Promise.resolve(globalThis.Guacamole);
  if (!assets) assets = new Promise((resolve, reject) => {
    const script = el('script', { src: '/static/vendor/guacamole/all.js' });
    script.onload = () => globalThis.Guacamole ? resolve(globalThis.Guacamole) : reject(Error('The display library is unavailable.'));
    script.onerror = () => { assets = null; script.remove(); reject(Error('The display library could not load.')); };
    document.head.append(script);
  });
  return assets;
}

export function viewer(reference) {
  let disposed = false, ended = false, captured = false, connected = false, socket, client, keyboard, display;
  let acknowledgements = 0, ackTimer, resizeTimer, pointerTimer, lastPointer = { x: 0, y: 0, mask: 0 };
  let previousMode = { expanded: false, fullscreen: false };
  const abort = new AbortController(), events = { signal: abort.signal }, keys = new Set();
  const identity = el('strong', {}, 'Checking display identity'), status = el('span', { role: 'status' }, 'Connecting. Input is released.');
  const well = el('div', { class: 'viewer-well', tabindex: '-1', role: 'application', 'aria-label': 'Remote display. Press Control Alt Shift to release input.' });
  const capture = button('Capture input', () => {
    if (!connected || ended) return;
    captured = true; well.tabIndex = 0; well.focus();
    keyboard.onkeydown = key => { if (captured) { keys.add(key); client.sendKeyEvent(1, key); } return false; };
    keyboard.onkeyup = key => { if (keys.delete(key)) client.sendKeyEvent(0, key); };
    updateStatus();
  }, { disabled: true });
  const releaseButton = button('Release input', () => { release(); capture.focus(); }, { disabled: true });
  const expand = button('Expand display', () => { release(); screen.expand(); });
  const full = button('Fullscreen display', async () => {
    release();
    try { await screen.toggle(); } catch { status.textContent = 'Fullscreen was refused. Use Expand display.'; }
  });
  const disconnect = button('Disconnect display', () => finish('Disconnected. Open a new display from the module panel.'));
  const element = el('section', { class: 'viewer-panel', 'aria-label': 'FICC remote display' },
    el('div', { class: 'viewer-identity' }, identity), el('div', { class: 'actions' }, capture, releaseButton, expand, full, disconnect),
    status, well, el('p', { class: 'muted' }, 'Control + Alt + Shift releases all input. Clipboard, file transfer and console audio are disabled.'));
  const screen = fullscreen(element, value => {
    release(); expand.textContent = value.expanded ? 'Restore display' : 'Expand display';
    full.textContent = value.fullscreen ? 'Exit display fullscreen' : 'Fullscreen display'; scheduleResize();
    const restored = previousMode.expanded && !value.expanded || previousMode.fullscreen && !value.fullscreen;
    previousMode = value;
    if (restored) requestAnimationFrame(() => requestAnimationFrame(reveal));
  });

  function reveal() {
    if (disposed) return;
    // Scroll content without moving Dockview's internal panel containers.
    const content = element.closest('.module-view');
    if (content) content.scrollTop += element.getBoundingClientRect().top - content.getBoundingClientRect().top;
    const anchor = element.closest('.workspace-surface') || element;
    const expanded = element.closest('.workspaces.workspace-expanded, .workspaces:fullscreen');
    const top = anchor.getBoundingClientRect().top - (expanded?.getBoundingClientRect().top || 0) - 12;
    if (expanded) expanded.scrollBy(0, top);
    else window.scrollBy(0, top);
  }

  function updateStatus() {
    capture.disabled = ended || !connected || captured;
    releaseButton.disabled = !captured;
    status.textContent = captured ? 'Input captured. Control + Alt + Shift releases input.' : 'Connected. Input is released.';
    element.dataset.input = captured ? 'captured' : 'released';
  }
  function send(value) {
    if (socket?.readyState !== WebSocket.OPEN || ended) return;
    const text = JSON.stringify(value);
    if (text.length > 8192 || socket.bufferedAmount + text.length > 65536) {
      finish('The display input buffer reached its limit. Input was released.'); return;
    }
    socket.send(text);
  }
  function release() {
    if (!captured) return;
    clearTimeout(pointerTimer); pointerTimer = null;
    keyboard?.reset();
    for (const key of keys) client?.sendKeyEvent(0, key);
    keys.clear();
    lastPointer.mask = 0;
    if (connected) send({ type: 'input', instruction: encode('mouse', lastPointer.x, lastPointer.y, 0) });
    captured = false; well.tabIndex = -1;
    keyboard.onkeydown = keyboard.onkeyup = null;
    updateStatus();
  }
  function encode(...values) {
    return values.map(value => { const text = String(value); return `${text.length}.${text}`; }).join(',') + ';';
  }
  function pointer(event, mask) {
    if (!captured || !display?.getWidth() || !display?.getHeight()) return;
    const rect = display.getElement().getBoundingClientRect(), scale = display.getScale();
    lastPointer = { x: Math.max(0, Math.min(4095, display.getWidth() - 1, Math.floor((event.clientX - rect.left) / scale))),
      y: Math.max(0, Math.min(2159, display.getHeight() - 1, Math.floor((event.clientY - rect.top) / scale))), mask };
    if (event.type === 'pointermove') {
      if (!pointerTimer) pointerTimer = setTimeout(() => { pointerTimer = null; sendPointer(); }, 16);
    } else { clearTimeout(pointerTimer); pointerTimer = null; sendPointer(); }
    event.preventDefault();
  }
  function sendPointer() { if (captured) send({ type: 'input', instruction: encode('mouse', lastPointer.x, lastPointer.y, lastPointer.mask) }); }
  function resize() {
    if (!display || ended || !well.clientWidth || !well.clientHeight) return;
    const width = Math.max(64, Math.min(4096, well.clientWidth)), height = Math.max(64, Math.min(2160, well.clientHeight));
    if (display.getWidth() && display.getHeight()) display.scale(Math.min(width / display.getWidth(), height / display.getHeight()));
    if (connected) client.sendSize(width, height);
  }
  function scheduleResize() { clearTimeout(resizeTimer); resizeTimer = setTimeout(resize, 80); }
  function finish(message) {
    if (ended) return;
    release(); ended = true; connected = false; capture.disabled = releaseButton.disabled = disconnect.disabled = true;
    clearTimeout(ackTimer); clearTimeout(resizeTimer); clearTimeout(pointerTimer);
    client?.disconnect(); socket?.close(); observer.disconnect();
    status.textContent = message;
  }
  well.addEventListener('keydown', event => {
    if (event.ctrlKey && event.altKey && event.shiftKey) {
      event.preventDefault(); event.stopImmediatePropagation(); release(); capture.focus();
    }
  }, { ...events, capture: true });
  well.addEventListener('blur', release, events);
  well.addEventListener('pointerdown', event => {
    if (captured) { well.setPointerCapture(event.pointerId); well.focus(); }
    pointer(event, (event.buttons & 1) | (event.buttons & 2 ? 4 : 0) | (event.buttons & 4 ? 2 : 0));
  }, events);
  for (const name of ['pointerup', 'pointermove']) well.addEventListener(name, event =>
    pointer(event, (event.buttons & 1) | (event.buttons & 2 ? 4 : 0) | (event.buttons & 4 ? 2 : 0)), events);
  well.addEventListener('pointercancel', release, events);
  well.addEventListener('wheel', event => { if (captured) { pointer(event, event.deltaY < 0 ? 8 : 16); pointer(event, 0); } }, { ...events, passive: false });
  well.addEventListener('contextmenu', event => { if (captured) event.preventDefault(); }, events);
  window.addEventListener('blur', release, events);
  window.addEventListener('ficc-release-input', release, events);
  window.addEventListener('session-expired', () => finish('Access expired. The display is closed.'), events);
  window.addEventListener('pagehide', () => finish('The display is closed.'), events);
  document.addEventListener('visibilitychange', () => { if (document.hidden) release(); }, events);
  const observer = new ResizeObserver(scheduleResize); observer.observe(well);

  async function connect() {
    try {
      const G = await loadAssets();
      if (disposed || ended) return;
      const grant = await request(`/viewers/${reference}/tickets`, { method: 'POST', signal: abort.signal });
      if (disposed || ended) return;
      identity.textContent = `${grant.system} / ${grant.vm_id}`;
      const tunnel = new G.Tunnel();
      const parser = new G.Parser(), decoder = new TextDecoder('utf-8', { fatal: true });
      parser.oninstruction = (opcode, values) => tunnel.oninstruction?.(opcode, values);
      tunnel.sendMessage = (...values) => send({ type: 'input', instruction: encode(...values) });
      tunnel.disconnect = () => { socket?.close(); tunnel.setState(G.Tunnel.State.CLOSED); };
      tunnel.connect = () => {
        socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/v1/viewers/${reference}/stream`);
        socket.binaryType = 'arraybuffer';
        socket.onopen = () => { send({ type: 'auth', ticket: grant.ticket }); grant.ticket = ''; tunnel.setState(G.Tunnel.State.OPEN); };
        socket.onmessage = event => {
          if (ended) return;
          try {
            if (typeof event.data === 'string') {
              const value = JSON.parse(event.data);
              finish(value.type === 'error' ? String(value.message).slice(0, 240) : 'Invalid display response.'); return;
            }
            if (!event.data.byteLength || event.data.byteLength > 65536) throw Error('Invalid display frame.');
            parser.receive(decoder.decode(event.data));
            acknowledgements += event.data.byteLength;
            if (!ackTimer) ackTimer = setTimeout(() => {
              ackTimer = null; send({ type: 'ack', bytes: acknowledgements }); acknowledgements = 0;
            }, 16);
          } catch { finish('The display response was invalid. Input was released.'); }
        };
        socket.onerror = () => finish('The display connection failed. Open a new display to retry.');
        socket.onclose = () => finish('The display connection closed. Input was released.');
      };
      client = new G.Client(tunnel); display = client.getDisplay();
      keyboard = new G.Keyboard(well); keyboard.onkeydown = keyboard.onkeyup = null;
      client.onerror = () => finish('The remote display reported an error. Input was released.');
      client.onstatechange = state => {
        if (state === G.Client.State.CONNECTED) { connected = true; updateStatus(); scheduleResize(); }
      };
      display.onresize = scheduleResize;
      well.append(display.getElement()); client.connect();
    } catch (error) { if (!disposed) finish(error.message); }
  }
  void connect();
  return { element, release, dispose() {
    if (disposed) return;
    finish('The display is closed.'); disposed = true; abort.abort(); observer.disconnect(); screen.dispose(); element.remove();
  } };
}
