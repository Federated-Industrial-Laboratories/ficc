// SPDX-License-Identifier: Apache-2.0
// Check real local audio, gain routing, lease loss and source disposal.
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { capture } from './support.mjs';

let server, origin;
const files = new Set(['audio-manager.js', 'audio-peak-processor.js', 'ui-audio-player.js', 'components.js', 'audio.css', 'console.css']);
const wave = (seconds = 8) => {
  const count = seconds * 8000, bytes = Buffer.alloc(44 + count * 2);
  bytes.write('RIFF'); bytes.writeUInt32LE(bytes.length - 8, 4); bytes.write('WAVEfmt ', 8);
  bytes.writeUInt32LE(16, 16); bytes.writeUInt16LE(1, 20); bytes.writeUInt16LE(1, 22);
  bytes.writeUInt32LE(8000, 24); bytes.writeUInt32LE(16000, 28); bytes.writeUInt16LE(2, 32);
  bytes.writeUInt16LE(16, 34); bytes.write('data', 36); bytes.writeUInt32LE(count * 2, 40);
  for (let i = 0; i < count; i++) bytes.writeInt16LE(Math.round(Math.sin(i * Math.PI * 440 / 4000) * 8192), 44 + i * 2);
  return bytes;
};
test.beforeAll(async () => {
  server = createServer(async (request, response) => {
    const name = request.url.slice(1);
    if (!name) {
      response.setHeader('Content-Type', 'text/html');
      response.end('<!doctype html><title>Sound controls</title><link rel="stylesheet" href="/console.css"><link rel="stylesheet" href="/audio.css"><main id="test"></main>'); return;
    }
    if (!files.has(name)) { response.writeHead(404); response.end(); return; }
    response.setHeader('Content-Type', name.endsWith('.js') ? 'text/javascript' : 'text/css');
    response.end(await readFile(new URL(`../../web/static/${name}`, import.meta.url)));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise(resolve => server.close(resolve)); });

async function setup(page, { preview = false, authority = true, count = 1 } = {}) {
  await page.addInitScript(() => {
    window.audioContexts = []; window.audioOutputs = []; window.objectUrls = []; window.revokedUrls = [];
    const Audio = window.AudioContext;
    window.AudioContext = class extends Audio {
      constructor(...args) { super(...args); this.testGains = []; window.audioContexts.push(this); }
      createGain() { const gain = super.createGain(); this.testGains.push(gain); return gain; }
    };
    const Worklet = window.AudioWorkletNode;
    window.AudioWorkletNode = class extends Worklet {
      constructor(...args) { super(...args); window.audioOutputs.push(this); }
    };
    const create = URL.createObjectURL, revoke = URL.revokeObjectURL;
    URL.createObjectURL = source => { const url = create(source); window.objectUrls.push(url); return url; };
    URL.revokeObjectURL = url => { window.revokedUrls.push(url); return revoke(url); };
  });
  await page.goto(origin);
  await page.evaluate(async options => {
    const { getAudioManager } = await import('/audio-manager.js');
    const { audioPlayer } = await import('/ui-audio-player.js');
    const state = window.audioTest = { acquire: [], release: [], heartbeat: [], prefs: { revision: 0, volume: .5, muted: false }, last: [] };
    const hooks = {
      async loadPreferences() { if (state.failLoad) throw Error('Offline'); return { ...state.prefs }; },
      async savePreferences(value) { state.prefs = { ...value, revision: value.revision + 1 }; return { ...state.prefs }; },
      async acquire(id) {
        state.acquire.push(id);
        if (state.conflict) throw Object.assign(Error('In use'), { status: 409 });
        if (state.defer) await new Promise(resolve => { state.resolveAcquire = resolve; });
        return { id: `${id}-lease`, expires_at: Date.now() / 1000 + 15 };
      },
      async heartbeat(id, lease) { state.heartbeat.push(id); if (state.failHeartbeat) throw Error('Revoked'); return { ...lease, expires_at: Date.now() / 1000 + 15 }; },
      async release(id, lease) { state.release.push([id, lease.id]); },
    };
    const manager = window.sound = getAudioManager({ authority: options.authority ? hooks : null, preview: options.preview, heartbeatMs: 1000 });
    document.querySelector('#test').append(manager.controls().element);
    window.players = Array.from({ length: options.count }, (_, index) => {
      const player = audioPlayer({ manager, instanceId: `sound-${index}`, onState: value => { state.last[index] = value; } });
      document.querySelector('#test').append(player.element); return player;
    });
  }, { preview, authority, count });
}
async function select(page, index = 0, name = 'tone.wav', buffer = wave()) {
  await page.getByLabel('Select audio file', { exact: true }).nth(index).setInputFiles({ name, mimeType: 'audio/wav', buffer });
}
const player = (page, index = 0) => page.getByRole('region', { name: 'Audio player' }).nth(index);
async function rms(page) {
  return page.evaluate(() => {
    const context = window.audioContexts[0];
    if (!context) return 0;
    if (!context.testAnalyser) { context.testAnalyser = context.createAnalyser(); context.testGains[0].connect(context.testAnalyser); }
    const bytes = new Float32Array(context.testAnalyser.fftSize); context.testAnalyser.getFloatTimeDomainData(bytes);
    return Math.sqrt(bytes.reduce((total, value) => total + value * value, 0) / bytes.length);
  });
}

test('real WAV playback uses one context and master and source gain controls', async ({ page }) => {
  await setup(page, { count: 2 }); await select(page); await select(page, 1);
  expect(await page.evaluate(() => window.audioContexts.length)).toBe(0);
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  await expect(player(page).getByText('Playing', { exact: true })).toBeVisible();
  await expect.poll(() => rms(page)).toBeGreaterThan(.05);
  await player(page).getByLabel('Source volume').fill('25');
  await expect.poll(() => page.evaluate(() => window.audioContexts[0].testGains[1].gain.value)).toBe(.25);
  await player(page).getByRole('button', { name: 'Mute source', exact: true }).click();
  await expect.poll(() => rms(page)).toBeLessThan(.0001);
  await player(page, 1).getByRole('button', { name: 'Play', exact: true }).click();
  await expect.poll(() => rms(page)).toBeGreaterThan(.05);
  expect(await page.evaluate(() => window.audioContexts.length)).toBe(1);
  await capture(page, 'audio-two-sources');
  await page.getByRole('button', { name: 'Mute all', exact: true }).click();
  await expect.poll(() => rms(page)).toBeLessThan(.0001);
  await expect.poll(() => page.evaluate(() => window.audioTest.prefs.muted)).toBe(true);
  await page.getByRole('button', { name: 'Unmute all', exact: true }).click();
  await player(page, 1).getByLabel('Playback position').fill('4');
  await expect.poll(() => page.evaluate(() => window.audioTest.last[1].currentTime)).toBeGreaterThanOrEqual(4);
  await player(page, 1).getByRole('button', { name: 'Pause', exact: true }).click();
  await expect(player(page, 1).getByText('Paused', { exact: true })).toBeVisible();
  await player(page, 1).getByRole('button', { name: 'Stop', exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.audioTest.last[1].currentTime)).toBe(0);
});

test('lease refusal and loss disable playback and never resume without a click', async ({ page }) => {
  await setup(page); await select(page); await page.evaluate(() => { window.audioTest.conflict = true; });
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  await expect(player(page).getByText('This source is playing in another window. Stop it there first.')).toBeVisible();
  await page.evaluate(() => { window.audioTest.conflict = false; });
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  await expect(player(page).getByText('Playing', { exact: true })).toBeVisible();
  await page.evaluate(() => { window.audioTest.failHeartbeat = true; });
  await expect(player(page).getByText('Playback access was lost. Select Play to retry.')).toBeVisible();
  expect(await page.evaluate(() => window.audioTest.acquire.length)).toBe(2);
  await expect.poll(() => page.evaluate(() => window.audioTest.release.length)).toBe(1);
  await expect.poll(() => rms(page)).toBeLessThan(.0001);
});

test('file replacement, hidden views, pagehide and disposal release resources', async ({ page }) => {
  await setup(page); await select(page);
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  await expect(player(page).getByText('Playing', { exact: true })).toBeVisible();
  await select(page, 0, 'replacement.wav');
  await expect(player(page).getByText('Paused', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.revokedUrls.length)).toBe(1);
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  await expect(player(page).getByText('Playing', { exact: true })).toBeVisible();
  await page.evaluate(() => window.players[0].setVisible(false));
  await expect(player(page).getByText('Paused', { exact: true })).toBeVisible();
  await page.evaluate(() => window.players[0].setVisible(true));
  expect(await page.evaluate(() => window.audioTest.acquire.length)).toBe(2);
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  await expect(player(page).getByText('Playing', { exact: true })).toBeVisible();
  await page.evaluate(() => window.dispatchEvent(new Event('pagehide')));
  await expect(player(page).getByText('Paused', { exact: true })).toBeVisible();
  await page.evaluate(() => { window.players[0].dispose(); window.sound.dispose(); });
  expect(await page.evaluate(() => window.revokedUrls.length)).toBe(2);
  await expect.poll(() => page.evaluate(() => window.audioContexts[0].state)).toBe('closed');
});

test('pending leases cannot restart a disposed source', async ({ page }) => {
  await setup(page); await select(page); await page.evaluate(() => { window.audioTest.defer = true; });
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  await expect.poll(() => page.evaluate(() => Boolean(window.audioTest.resolveAcquire))).toBe(true);
  await page.evaluate(() => { window.players[0].dispose(); window.audioTest.resolveAcquire(); });
  await expect.poll(() => page.evaluate(() => window.audioTest.release.length)).toBe(1);
  await expect.poll(() => rms(page)).toBeLessThan(.0001);
});

test('a cancelled lease request settles before a new playback attempt acquires access', async ({ page }) => {
  await setup(page); await select(page); await page.evaluate(() => { window.audioTest.defer = true; });
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  await expect.poll(() => page.evaluate(() => Boolean(window.audioTest.resolveAcquire))).toBe(true);
  await player(page).getByRole('button', { name: 'Pause', exact: true }).click();
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  expect(await page.evaluate(() => window.audioTest.acquire.length)).toBe(1);
  await page.evaluate(() => { window.audioTest.defer = false; window.audioTest.resolveAcquire(); });
  await expect(player(page).getByText('Playing', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.audioTest.acquire.length)).toBe(2);
  expect(await page.evaluate(() => window.audioTest.release.length)).toBe(1);
  await expect.poll(() => rms(page)).toBeGreaterThan(.05);
});

test('preference loss and signout stop all sources without replay', async ({ page }) => {
  await setup(page, { count: 2 }); await select(page); await select(page, 1);
  for (const index of [0, 1]) {
    await player(page, index).getByRole('button', { name: 'Play', exact: true }).click();
    await expect(player(page, index).getByText('Playing', { exact: true })).toBeVisible();
  }
  await page.evaluate(() => { window.audioTest.failLoad = true; return window.sound.refreshPreferences(); });
  for (const index of [0, 1]) await expect(player(page, index).getByText('Sound access could not be checked. Select Play to try again.')).toBeVisible();
  await expect.poll(() => rms(page)).toBeLessThan(.0001);
  await page.evaluate(() => { window.audioTest.failLoad = false; window.dispatchEvent(new Event('session-expired')); });
  for (const index of [0, 1]) await expect(player(page, index).getByText('The session ended.')).toBeVisible();
  expect(await page.evaluate(() => window.audioTest.acquire.length)).toBe(2);
});

test('absent authority, browser autoplay rejection, invalid files and ended state are visible', async ({ page }) => {
  await setup(page, { authority: false }); await select(page);
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  await expect(player(page).getByText('A sound service is required.')).toBeVisible();
  await setup(page, { authority: false, preview: true }); await select(page, 0, 'short.wav', wave(1));
  await expect(page.getByText('Local preview / no shared playback control')).toBeVisible();
  await page.evaluate(() => {
    window.originalPlay = HTMLMediaElement.prototype.play;
    HTMLMediaElement.prototype.play = () => Promise.reject(new DOMException('Blocked', 'NotAllowedError'));
  });
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  await expect(player(page).getByText('The browser blocked playback. Select Play to retry.')).toBeVisible();
  await page.evaluate(() => { HTMLMediaElement.prototype.play = window.originalPlay; });
  await player(page).getByRole('button', { name: 'Play', exact: true }).click();
  await expect(player(page).getByText('Playback ended')).toBeVisible();
  await select(page, 0, 'empty.wav', Buffer.alloc(0));
  await expect(player(page).getByText('Select a non-empty audio file no larger than 128 MiB.')).toBeVisible();
  await expect(player(page).getByRole('button', { name: 'Play', exact: true })).toBeDisabled();
  await select(page, 0, 'broken.wav', Buffer.from('Invalid WAV data'));
  await expect(player(page).getByText('The selected audio could not be decoded or read.')).toBeVisible();
});


test('the shared stereo output limits simultaneous loud sources and retains mute', async ({ page }) => {
  await setup(page, { count: 2 });
  const loud = wave();
  for (let i = 44; i < loud.length; i += 2) loud.writeInt16LE(30000, i);
  await select(page, 0, 'loud-a.wav', loud); await select(page, 1, 'loud-b.wav', loud);
  await page.getByLabel('Master volume').fill('100');
  for (const index of [0, 1]) {
    await player(page, index).getByRole('button', { name: 'Play', exact: true }).click();
    await expect(player(page, index).getByText('Playing', { exact: true })).toBeVisible();
  }
  const peak = () => page.evaluate(() => {
    const output = window.audioOutputs[0];
    if (!output.testAnalyser) { output.testAnalyser = output.context.createAnalyser(); output.connect(output.testAnalyser); }
    const samples = new Float32Array(output.testAnalyser.fftSize);
    output.testAnalyser.getFloatTimeDomainData(samples);
    return Math.max(...samples.map(Math.abs));
  });
  await expect.poll(peak).toBeGreaterThan(.8);
  expect(await peak()).toBeLessThanOrEqual(.98001);
  expect(await page.evaluate(() => window.audioOutputs.length)).toBe(1);
  await page.getByRole('button', { name: 'Mute all', exact: true }).click();
  await expect.poll(peak).toBeLessThan(.0001);
});

for (const count of [1, 64]) test(`output blocks stay finite and bounded at N=${count}`, async ({ page }) => {
  await page.goto(origin);
  const result = await page.evaluate(async blocks => {
    const context = new OfflineAudioContext(2, blocks * 128, 48000);
    await context.audioWorklet.addModule('/audio-peak-processor.js');
    const input = context.createBuffer(2, blocks * 128, 48000);
    for (let channel = 0; channel < 2; channel++) {
      const samples = input.getChannelData(channel);
      for (let i = 0; i < samples.length; i++) samples[i] = (channel ? -1 : 1) * (1 + Math.floor(i / 128));
    }
    const source = context.createBufferSource(); source.buffer = input;
    const output = new AudioWorkletNode(context, 'ficc-peak', { outputChannelCount: [2], channelCount: 2 });
    source.connect(output).connect(context.destination); source.start();
    const rendered = await context.startRendering();
    const left = rendered.getChannelData(0), right = rendered.getChannelData(1);
    return { finite: [...left, ...right].every(Number.isFinite), peak: Math.max(...left.map(Math.abs)),
      difference: Math.max(...left.map((value, index) => Math.abs(value + right[index]))),
      quietest: Math.min(...left) };
  }, count);
  expect(result.finite).toBe(true); expect(result.peak).toBeLessThanOrEqual(.98001);
  expect(result.quietest).toBeGreaterThan(.979); expect(result.difference).toBeLessThan(.00001);
});
