// SPDX-License-Identifier: Apache-2.0
// Play an explicitly selected local audio file through the host sound service.
import { button, el } from './components.js';

const MAX_FILE_BYTES = 128 * 1024 * 1024;
const formats = { wav: 'audio/wav', ogg: 'audio/ogg', opus: 'audio/ogg; codecs="opus"',
  mp3: 'audio/mpeg', flac: 'audio/flac', m4a: 'audio/mp4', aac: 'audio/aac' };
const clock = seconds => `${Math.floor(seconds / 60)}:${String(Math.floor(seconds % 60)).padStart(2, '0')}`;

export function audioPlayer({ instanceId, manager, onState = () => {}, volume = 1, muted = false }) {
  const media = document.createElement('audio'); media.preload = 'metadata';
  let active = true, sourceUrl = null, ready = false, last, stream, fileError = '';
  const file = el('input', { type: 'file', accept: 'audio/*,.wav,.ogg,.opus,.mp3,.flac,.m4a,.aac', 'aria-label': 'Select audio file' });
  const name = el('strong', {}, 'No file selected'), status = el('div', { class: 'audio-status', role: 'status' });
  const play = button('Play', () => { void stream.play(); }, { disabled: true });
  const pause = button('Pause', () => stream.pause(), { disabled: true });
  const stop = button('Stop', () => stream.stop(), { disabled: true });
  const mute = button('Mute source', () => stream.setMuted(!last.muted), { 'aria-pressed': 'false' });
  const seek = el('input', { type: 'range', min: 0, max: 1, step: .1, value: 0, disabled: true, 'aria-label': 'Playback position' });
  const elapsed = el('output', {}, '0:00 / 0:00');
  const level = el('input', { type: 'range', min: 0, max: 100, step: 1, 'aria-label': 'Source volume' });
  const value = el('output');
  const element = el('section', { class: 'audio-player', 'aria-label': 'Audio player' },
    el('div', { class: 'audio-file' }, name, el('label', {}, 'Open local audio', file)),
    el('p', { class: 'muted' }, 'Select a local audio file up to 128 MiB. Playback starts only when you select Play.'),
    el('div', { class: 'audio-transport' }, play, pause, stop, mute),
    el('label', { class: 'audio-position' }, el('span', {}, 'Position'), seek, elapsed),
    el('label', { class: 'audio-level' }, el('span', {}, 'Volume'), level, value), status);
  function render(state) {
    if (!active) return;
    last = state;
    const playing = ['playing', 'buffering', 'starting'].includes(state.status);
    play.disabled = !ready || playing; pause.disabled = !playing; stop.disabled = !ready;
    status.textContent = fileError || state.error || ({ paused: 'Paused', starting: 'Starting audio', playing: 'Playing', buffering: 'Loading audio', ended: 'Playback ended' }[state.status] || 'Audio error');
    seek.disabled = !ready || state.duration <= 0; seek.max = Math.max(1, state.duration); seek.value = state.currentTime;
    elapsed.value = `${clock(state.currentTime)} / ${clock(state.duration)}`;
    level.value = Math.round(state.volume * 100); value.value = `${level.value}%`;
    mute.textContent = state.muted ? 'Unmute source' : 'Mute source'; mute.setAttribute('aria-pressed', String(state.muted));
    onState(state);
  }
  stream = manager.attachMedia(instanceId, media, { onState: render, volume, muted });
  function clearFile() {
    ready = false; stream.stop(); media.removeAttribute('src'); media.load();
    if (sourceUrl) URL.revokeObjectURL(sourceUrl);
    sourceUrl = null;
  }
  file.addEventListener('change', () => {
    const selected = file.files?.[0];
    if (!selected || !active) return;
    fileError = ''; clearFile(); name.textContent = selected.name;
    const extension = selected.name.split('.').at(-1).toLowerCase();
    const type = formats[extension] || (/^audio\/[a-z0-9.+-]+$/i.test(selected.type) ? selected.type : '');
    if (!selected.size || selected.size > MAX_FILE_BYTES) {
      fileError = 'Select a non-empty audio file no larger than 128 MiB.'; render(stream.snapshot()); return;
    }
    if (!type || !media.canPlayType(type)) { fileError = 'This browser does not support the selected audio format.'; render(stream.snapshot()); return; }
    sourceUrl = URL.createObjectURL(selected); media.src = sourceUrl; ready = true;
    render(stream.snapshot()); media.load();
  });
  seek.addEventListener('input', () => stream.seek(Number(seek.value)));
  level.addEventListener('input', () => stream.setVolume(Number(level.value) / 100));
  return { element, release: () => stream.release(), stop: () => stream.stop(),
    setVisible: value => stream.setVisible(value),
    dispose() { if (!active) return; clearFile(); active = false; stream.dispose(); file.value = ''; element.remove(); },
  };
}
