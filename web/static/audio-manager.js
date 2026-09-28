// SPDX-License-Identifier: Apache-2.0
// Route host media through bounded gain controls and revocable playback leases.
import { button, el } from './components.js';

const managers = new WeakMap();
const level = value => Math.max(0, Math.min(1, Number(value) || 0));

export function getAudioManager({ document: doc = document, authority = null, preview = false, heartbeatMs = 5000 } = {}) {
  const existing = managers.get(doc);
  if (existing) return existing;
  const win = doc.defaultView, sources = new Map(), listeners = new Set();
  let context, masterGain, outputReady, disposed = false, heartbeatBusy = false, message = '';
  let preferences = { revision: 0, volume: .5, muted: false }, preferenceWork = Promise.resolve(), change = 0;
  const hooks = ['loadPreferences', 'savePreferences', 'acquire', 'heartbeat', 'release'];
  if (authority && hooks.some(name => typeof authority[name] !== 'function')) throw Error('The sound service is incomplete.');
  const channel = authority && win.BroadcastChannel ? new win.BroadcastChannel('ficc-audio-preferences') : null;
  function notify() { for (const listener of listeners) listener(); }
  function applyMaster() {
    if (masterGain) masterGain.gain.setValueAtTime(preferences.muted ? 0 : preferences.volume, context.currentTime);
    notify();
  }
  function validatePreferences(value) {
    if (!value || !Number.isInteger(value.revision) || value.revision < 0 || !Number.isFinite(value.volume)
      || value.volume < 0 || value.volume > 1 || typeof value.muted !== 'boolean') throw Error('Invalid sound settings.');
    return { revision: value.revision, volume: value.volume, muted: value.muted };
  }
  function failAuthority() {
    message = 'Sound access could not be checked. Select Play to try again.';
    for (const source of sources.values()) source.release(message);
    notify();
  }
  function refreshPreferences() {
    if (!authority || disposed) return Promise.resolve();
    const version = change;
    preferenceWork = preferenceWork.catch(() => {}).then(async () => {
      const value = validatePreferences(await authority.loadPreferences());
      if (!disposed) {
        preferences = version === change ? value : { ...preferences, revision: value.revision };
        applyMaster();
      }
    });
    return preferenceWork.catch(() => { if (!disposed) failAuthority(); });
  }
  function setMaster(value) {
    if (disposed) return Promise.resolve();
    preferences = { ...preferences, volume: value.volume == null ? preferences.volume : level(value.volume),
      muted: value.muted == null ? preferences.muted : Boolean(value.muted) };
    const desired = { volume: preferences.volume, muted: preferences.muted }, version = ++change;
    applyMaster();
    if (!authority) return Promise.resolve();
    preferenceWork = preferenceWork.catch(() => {}).then(async () => {
      if (disposed) return;
      const saved = validatePreferences(await authority.savePreferences({ revision: preferences.revision, ...desired }));
      if (disposed) return;
      preferences = version === change ? saved : { ...preferences, revision: saved.revision };
      message = ''; applyMaster(); channel?.postMessage({ type: 'changed' });
    });
    return preferenceWork.catch(() => {
      if (disposed) return;
      preferences.muted = true; applyMaster(); failAuthority();
    });
  }
  function ensureContext() {
    if (disposed) throw Error('Sound is closed.');
    if (!context) {
      const Audio = win.AudioContext || win.webkitAudioContext;
      if (!Audio) throw Error('Audio is unavailable in this browser.');
      context = new Audio(); masterGain = context.createGain();
      const audio = context, master = masterGain;
      outputReady = Promise.resolve().then(async () => {
        if (!audio.audioWorklet || !win.AudioWorkletNode) throw Error('Audio processing is unavailable.');
        await audio.audioWorklet.addModule(new URL('./audio-peak-processor.js', import.meta.url));
        if (disposed || context !== audio) return;
        const limiter = new win.AudioWorkletNode(audio, 'ficc-peak', {
          numberOfInputs: 1, numberOfOutputs: 1, outputChannelCount: [2],
          channelCount: 2, channelCountMode: 'explicit', channelInterpretation: 'speakers',
        });
        limiter.addEventListener('processorerror', () => {
          if (context === audio) { master.disconnect(); releaseAll('Sound processing failed. Reload this window to resume.'); }
        });
        master.connect(limiter).connect(audio.destination);
      });
      outputReady.catch(() => {});
      context.addEventListener('statechange', contextState); applyMaster();
    }
    return context;
  }
  function contextState() {
    if (!disposed && context.state !== 'running') {
      for (const source of sources.values()) {
        if (['playing', 'buffering'].includes(source.snapshot().status)) source.release('Sound is paused. Select Play to resume.');
      }
    }
    notify();
  }
  function attachMedia(instanceId, media, { onState = () => {}, volume = 1, muted = false } = {}) {
    if (disposed || typeof instanceId !== 'string' || !instanceId || instanceId.length > 128) throw Error('Invalid sound instance.');
    if (sources.has(instanceId) || sources.size >= 16) throw Error('The sound instance limit was reached.');
    if (media.ownerDocument !== doc || !(media instanceof win.HTMLMediaElement)) throw Error('Invalid media element.');
    media.pause(); media.autoplay = false; media.controls = false;
    let gain, input, lease, expiry, closed = false, visible = true, epoch = 0, pending = false;
    let instanceVolume = level(volume), instanceMuted = Boolean(muted), status = 'paused', error = '';
    let releasing = Promise.resolve(), acquisition = Promise.resolve();
    function snapshot() {
      return { status, error, volume: instanceVolume, muted: instanceMuted,
        currentTime: Number.isFinite(media.currentTime) ? media.currentTime : 0,
        duration: Number.isFinite(media.duration) ? media.duration : 0, pending };
    }
    function emit() { if (!closed) { onState(snapshot()); notify(); } }
    function applyGain() { if (gain) gain.gain.setValueAtTime(instanceMuted ? 0 : instanceVolume, context.currentTime); }
    function dropLease(value) {
      if (!authority || !value) return Promise.resolve();
      return Promise.resolve().then(() => authority.release(instanceId, value)).catch(() => {});
    }
    function releaseLease() {
      win.clearTimeout(expiry); const previous = lease; lease = null;
      releasing = releasing.then(() => dropLease(previous));
    }
    function pause(reason = '') {
      epoch++; pending = false; media.pause(); releaseLease();
      status = reason ? 'error' : 'paused'; error = reason; emit();
    }
    function validateLease(value) {
      if (!value || typeof value.id !== 'string' || !value.id || !Number.isFinite(value.expires_at)
        || value.expires_at * 1000 <= Date.now()) throw Error('Playback access has expired.');
      return value;
    }
    function armExpiry() {
      win.clearTimeout(expiry);
      if (lease) expiry = win.setTimeout(() => pause('Playback access has expired.'), Math.max(0, lease.expires_at * 1000 - Date.now()));
    }
    async function play() {
      if (closed || disposed || pending || !visible || doc.hidden) return;
      if (!media.paused && status === 'playing') return;
      if (!authority && !preview) { pause('A sound service is required.'); return; }
      const attempt = ++epoch; pending = true; status = 'starting'; error = ''; emit();
      try {
        const audio = ensureContext();
        if (!gain) {
          gain = audio.createGain(); input = audio.createMediaElementSource(media);
          input.connect(gain).connect(masterGain); media.volume = 1; media.muted = false; applyGain();
        }
        const resume = audio.resume(); resume.catch(() => {});
        await releasing;
        if (authority) {
          await refreshPreferences();
          if (attempt !== epoch || closed || disposed) return;
          acquisition = acquisition.catch(() => {}).then(async () => {
            if (attempt !== epoch || closed || disposed) return null;
            const acquired = validateLease(await authority.acquire(instanceId));
            if (attempt !== epoch || closed || disposed) { await dropLease(acquired); return null; }
            lease = acquired; armExpiry();
            return acquired;
          });
          const acquired = await acquisition;
          if (!acquired || attempt !== epoch || closed || disposed) return;
        }
        await Promise.all([resume, outputReady]);
        if (attempt !== epoch || closed || disposed) return;
        if (audio.state !== 'running') throw Error('Sound is paused by the browser. Select Play to resume.');
        await media.play();
        if (attempt !== epoch || closed || disposed) { media.pause(); return; }
        pending = false; status = media.paused ? 'paused' : 'playing'; emit();
      } catch (failure) {
        if (attempt !== epoch || closed || disposed) return;
        pause(failure?.name === 'NotAllowedError' ? 'The browser blocked playback. Select Play to retry.'
          : failure?.status === 409 ? 'This source is playing in another window. Stop it there first.' : 'Audio could not start. Check sound access and the selected file.');
      }
    }
    async function heartbeat() {
      if (!authority || !lease || closed) return;
      const current = lease, attempt = epoch;
      try {
        const renewed = validateLease(await authority.heartbeat(instanceId, current));
        if (!closed && attempt === epoch && lease === current) { lease = renewed; armExpiry(); }
      } catch { if (!closed && attempt === epoch && lease === current) pause('Playback access was lost. Select Play to retry.'); }
    }
    function stop() { pause(); if (Number.isFinite(media.duration)) media.currentTime = 0; emit(); }
    const events = new Map([
      ['playing', () => { if (!closed && (preview || lease)) { status = 'playing'; error = ''; emit(); } else media.pause(); }],
      ['waiting', () => { if (!media.paused) { status = 'buffering'; emit(); } }],
      ['pause', () => { if (['playing', 'buffering'].includes(status) || pending) pause(); }],
      ['ended', () => { pause(); status = 'ended'; emit(); }],
      ['error', () => pause('The selected audio could not be decoded or read.')],
      ['timeupdate', emit], ['durationchange', emit], ['loadedmetadata', emit],
    ]);
    for (const [name, handler] of events) media.addEventListener(name, handler);
    const handle = { play, pause, stop, release: pause, heartbeat, snapshot,
      seek(seconds) {
        if (!closed && Number.isFinite(seconds) && Number.isFinite(media.duration)) {
          media.currentTime = Math.max(0, Math.min(media.duration, seconds)); emit();
        }
      },
      setVolume(value) { instanceVolume = level(value); applyGain(); emit(); },
      setMuted(value) { instanceMuted = Boolean(value); applyGain(); emit(); },
      setVisible(value) { visible = Boolean(value); if (!visible) pause(); },
      dispose() {
        if (closed) return;
        pause(); closed = true;
        for (const [name, handler] of events) media.removeEventListener(name, handler);
        input?.disconnect(); gain?.disconnect(); sources.delete(instanceId); notify();
        if (!sources.size && context) {
          const previous = context; context = null; masterGain = null;
          previous.removeEventListener('statechange', contextState); previous.close().catch(() => {});
        }
      },
    };
    sources.set(instanceId, handle); emit(); return handle;
  }
  async function heartbeat() {
    if (heartbeatBusy || disposed) return;
    heartbeatBusy = true;
    try { await refreshPreferences(); await Promise.all([...sources.values()].map(source => source.heartbeat())); }
    finally { heartbeatBusy = false; }
  }
  function releaseAll(reason = '') { for (const source of sources.values()) source.release(reason); }
  function visibility() { if (doc.hidden) releaseAll(); }
  function pagehide() { releaseAll(); context?.suspend().catch(() => {}); }
  function expired() { releaseAll('The session ended.'); }
  function controls() {
    const output = el('output'), range = el('input', { type: 'range', min: 0, max: 100, step: 1, 'aria-label': 'Master volume' });
    const mute = button('Mute all', () => { void setMaster({ muted: !preferences.muted }); }, { 'aria-pressed': 'false' });
    const status = el('span', { class: 'audio-status', role: 'status' });
    const element = el('section', { class: 'audio-master', 'aria-label': 'Sound controls' }, el('strong', {}, 'Sound'),
      el('label', { class: 'audio-level' }, el('span', {}, 'Master'), range, output), mute, status);
    function render() {
      range.value = Math.round(preferences.volume * 100); output.value = `${range.value}%`;
      mute.setAttribute('aria-pressed', String(preferences.muted)); mute.textContent = preferences.muted ? 'Unmute all' : 'Mute all';
      status.textContent = message || (preview ? 'Local preview / no shared playback control' : `${[...sources.values()].filter(source => source.snapshot().status === 'playing').length} playing`);
    }
    range.addEventListener('input', () => { void setMaster({ volume: Number(range.value) / 100 }); });
    listeners.add(render); render();
    return { element, dispose() { listeners.delete(render); element.remove(); } };
  }
  const timer = authority ? win.setInterval(heartbeat, Math.max(1000, Math.min(5000, heartbeatMs))) : null;
  const invalidated = event => { if (event.data?.type === 'changed') void refreshPreferences(); };
  channel?.addEventListener('message', invalidated);
  doc.addEventListener('visibilitychange', visibility); win.addEventListener('pagehide', pagehide);
  win.addEventListener('session-expired', expired);
  const manager = { attachMedia, controls, setMaster, releaseAll, refreshPreferences,
    get preferences() { return { ...preferences }; },
    dispose() {
      if (disposed) return;
      disposed = true; win.clearInterval(timer);
      for (const source of [...sources.values()]) source.dispose();
      doc.removeEventListener('visibilitychange', visibility); win.removeEventListener('pagehide', pagehide);
      win.removeEventListener('session-expired', expired); channel?.close(); listeners.clear();
      context?.removeEventListener('statechange', contextState); context?.close().catch(() => {}); managers.delete(doc);
    },
  };
  managers.set(doc, manager); void refreshPreferences(); return manager;
}
