// SPDX-License-Identifier: Apache-2.0
// Exercise model setup and explicitly enabled real inference workflows through the console.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture, cli, login } from './support.mjs';

async function trackCompletion(page) {
  await page.evaluate(() => {
    window.ficcInferenceCompletion = { state: 'waiting', bytes: 0 };
    const fetch = window.fetch.bind(window);
    window.fetch = async (...args) => {
      const response = await fetch(...args);
      if (String(args[0]).includes('/v1/chat/completions') && response.body) {
        const getReader = response.body.getReader.bind(response.body);
        response.body.getReader = (...options) => {
          const reader = getReader(...options), read = reader.read.bind(reader);
          reader.read = async () => {
            try {
              const result = await read();
              window.ficcInferenceCompletion.bytes += result.value?.byteLength || 0;
              if (result.done) window.ficcInferenceCompletion.state = 'complete';
              return result;
            } catch (error) { window.ficcInferenceCompletion.state = 'failed'; throw error; }
          };
          return reader;
        };
      }
      return response;
    };
  });
}

async function completed(page) {
  // Observe the same reader used by the console, including its actual EOF.
  await expect.poll(() => page.evaluate(() => window.ficcInferenceCompletion.state), { timeout: 120000 }).toBe('complete');
  expect(await page.evaluate(() => window.ficcInferenceCompletion.bytes)).toBeGreaterThan(0);
}

test('register and upload an immutable model, then inspect inference setup', async ({ page }) => {
  const faults = [];
  page.on('pageerror', error => faults.push(error.message));
  await login(page);
  await page.locator('[data-view=models]').click();
  await expect(page.getByRole('heading', { name: 'Models', exact: true })).toBeVisible();
  const data = Buffer.from('GGUF test transfer bytes; this is not an inference model.');
  const manifest = { name: 'Browser transfer fixture', revision: 'fixture-1', licence: 'Apache-2.0', format: 'gguf', entrypoint: 'model.gguf',
    files: [{ name: 'model.gguf', digest: `sha256:${createHash('sha256').update(data).digest('hex')}`, bytes: data.length }] };
  await page.getByRole('button', { name: 'Register model', exact: true }).click();
  let dialog = page.getByRole('dialog');
  await dialog.getByLabel('Immutable model manifest', { exact: true }).setInputFiles({ name: 'model.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(manifest)) });
  await dialog.getByRole('button', { name: 'Register', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  const row = page.getByRole('table', { name: 'Model catalogue', exact: true }).getByRole('row').filter({ hasText: manifest.name });
  await expect(row).toContainText('Awaiting weights');
  await row.getByRole('button', { name: 'Upload files', exact: true }).click();
  dialog = page.getByRole('dialog');
  await dialog.getByLabel('Model weight and configuration files', { exact: true }).setInputFiles({ name: 'model.gguf', mimeType: 'application/octet-stream', buffer: data });
  await dialog.getByRole('button', { name: 'Upload', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(row).toContainText('Ready');
  await capture(page, 'models-verified-upload');
  await page.locator('[data-view=inference]').click();
  await expect(page.getByRole('heading', { name: 'Inference', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'New service', exact: true }).click();
  dialog = page.getByRole('dialog');
  await expect(dialog.getByLabel('Model revision', { exact: true })).toContainText(manifest.name);
  await dialog.getByRole('button', { name: 'Preview resources', exact: true }).click();
  await expect(dialog).toContainText('Choose a ready model and compatible connected contributors.');
  await expect(dialog.getByRole('button', { name: 'Start service', exact: true })).toBeDisabled();
  await capture(page, 'inference-no-unqualified-fallback');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.locator('[data-view=models]').click();
  await page.getByRole('table', { name: 'Model catalogue', exact: true }).getByRole('row').filter({ hasText: manifest.name }).getByRole('button', { name: 'Remove revision', exact: true }).click();
  await expect(page.getByRole('table', { name: 'Model catalogue', exact: true })).not.toContainText(manifest.name);
  expect(faults).toEqual([]);
});

test('resolve a public model revision and register its selected weights', async ({ page }) => {
  test.skip(!process.env.FICC_TEST_HUB, 'Enable the explicit public-Hub integration check.');
  await login(page);
  await page.locator('[data-view=models]').click();
  await page.getByRole('button', { name: 'Import from Hugging Face', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Hugging Face repository', { exact: true }).fill('Qwen/Qwen3-0.6B-GGUF');
  await dialog.getByLabel('Exact GGUF filename (optional)', { exact: true }).fill('Qwen3-0.6B-Q8_0.gguf');
  await dialog.getByRole('button', { name: 'Find available weights', exact: true }).click();
  await expect(dialog.getByLabel('Model quantization and size', { exact: true })).toContainText('Qwen3-0.6B-Q8_0.gguf');
  await expect(dialog).toContainText('apache-2.0 / commit');
  await capture(page, 'models-public-hub-preview');
  await dialog.getByRole('button', { name: 'Register selected revision', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  const row = page.getByRole('table', { name: 'Model catalogue', exact: true }).getByRole('row').filter({ hasText: 'Qwen3-0.6B-GGUF / Qwen3-0.6B-Q8_0.gguf' });
  await expect(row).toContainText('Awaiting weights');
  await row.getByRole('button', { name: 'Remove revision', exact: true }).click();
  await expect(row).toHaveCount(0);
});

test('a ready managed service streams through the local console', async ({ page }) => {
  const alias = process.env.FICC_TEST_INFERENCE_ALIAS;
  test.skip(!alias, 'Supply an explicitly selected ready service for the real engine check.');
  test.setTimeout(180000);
  page.setDefaultTimeout(10000);
  const faults = [];
  page.on('pageerror', error => faults.push(error.message));
  await login(page);
  await page.locator('[data-view=inference]').click();
  await trackCompletion(page);
  const row = page.getByRole('table', { name: 'Inference services', exact: true }).getByRole('row').filter({ hasText: alias });
  await expect(row).toContainText('ready');
  await row.getByRole('button', { name: alias, exact: true }).click();
  console.log(JSON.stringify({ console_stage: 'selected', alias }));
  await page.getByLabel('Test prompt', { exact: true }).fill('Reply with one sentence about a cat. /no_think');
  const response = page.waitForResponse(value => value.url().includes('/v1/chat/completions') && value.request().method() === 'POST', { timeout: 120000 });
  await page.getByRole('button', { name: 'Send prompt', exact: true }).click();
  const delivered = await response;
  expect(delivered.ok()).toBeTruthy();
  console.log(JSON.stringify({ console_stage: 'headers', status: delivered.status() }));
  await completed(page);
  console.log(JSON.stringify({ console_stage: 'complete' }));
  await expect(page.locator('pre[aria-live=polite]')).not.toBeEmpty({ timeout: 90000 });
  await capture(page, 'inference-real-answer');
  await page.setViewportSize({ width: 430, height: 932 });
  await expect(page.getByRole('button', { name: 'Cancel request', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(430);
  await capture(page, 'inference-real-answer-narrow');
  await page.getByRole('button', { name: 'Cancel request', exact: true }).click();
  expect(faults).toEqual([]);
});

test('create real replicas through the console and stop their admitted resources', async ({ page }) => {
  const path = process.env.FICC_TEST_INFERENCE_SPEC;
  test.skip(!path, 'Supply an explicit public service specification for bounded real deployments.');
  test.setTimeout(900000);
  page.setDefaultTimeout(10000);
  const spec = JSON.parse(readFileSync(path, 'utf8'));
  const hold = Number(process.env.FICC_TEST_READY_HOLD || '0');
  expect(Number.isInteger(hold) && hold >= 0 && hold <= 180).toBeTruthy();
  const faults = [];
  page.on('pageerror', error => faults.push(error.message));
  let identity;
  try {
    await login(page);
    await page.locator('[data-view=inference]').click();
    await page.getByRole('button', { name: 'New service', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Service name', { exact: true }).fill(spec.alias);
    await dialog.getByLabel('Model revision', { exact: true }).selectOption(spec.model_id);
    await dialog.getByLabel('Engine adapter', { exact: true }).selectOption(spec.engine);
    await dialog.getByLabel('Engine executable in approved image', { exact: true }).fill(spec.executable);
    await dialog.getByLabel('Context tokens', { exact: true }).fill(String(spec.context));
    await dialog.getByLabel('Concurrent requests per replica', { exact: true }).fill(String(spec.concurrency));
    for (const placement of spec.placements) {
      const field = dialog.locator('fieldset').filter({ has: page.locator(`input[value="${placement.limits.gpu_devices[0]}"]`) });
      await field.locator('legend input').check();
      for (const device of await field.locator('input[value]').all()) {
        await device.setChecked(placement.limits.gpu_devices.includes(await device.getAttribute('value')));
      }
    }
    await dialog.getByLabel('Approved runtime image', { exact: true }).selectOption({ label: `${spec.runtime.provider} / ${spec.runtime.image_digest.slice(0, 28)}` });
    await dialog.getByRole('button', { name: 'Preview resources', exact: true }).click();
    await expect(dialog).toContainText(`${spec.placements.length} independent replicas.`);
    await capture(page, 'inference-replicas-preview');
    const created = page.waitForResponse(value => new URL(value.url()).pathname === '/api/v1/inference' && value.request().method() === 'POST');
    await dialog.getByRole('button', { name: 'Start service', exact: true }).click();
    const result = await created;
    expect(result.ok()).toBeTruthy();
    identity = (await result.json()).id;
    await expect(dialog).toHaveCount(0);
    const row = page.getByRole('table', { name: 'Inference services', exact: true }).getByRole('row').filter({ hasText: spec.alias });
    await expect(row.getByRole('cell').nth(1)).toHaveText('ready', { timeout: 600000 });
    console.log(JSON.stringify({ ready_service: identity, alias: spec.alias, hold_seconds: hold }));
    if (hold) await page.waitForTimeout(hold * 1000);
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(row.getByRole('cell').nth(1)).toHaveText('ready');
    const answer = JSON.parse(cli(['inference-chat', identity, '--prompt', 'Reply with the word cat. /no_think', '--max-tokens', '32']));
    expect(answer.choices.length).toBeGreaterThan(0);
    console.log(JSON.stringify({ inference_cli: 'passed', service: identity }));
    await row.getByRole('button', { name: spec.alias, exact: true }).click();
    console.log(JSON.stringify({ console_stage: 'selected', service: identity }));
    await trackCompletion(page);
    await page.getByLabel('Test prompt', { exact: true }).fill('Reply with one sentence about a cat. /no_think');
    const reply = page.waitForResponse(value => value.url().includes('/v1/chat/completions') && value.request().method() === 'POST', { timeout: 120000 });
    await page.getByRole('button', { name: 'Send prompt', exact: true }).click();
    const delivered = await reply;
    expect(delivered.ok()).toBeTruthy();
    console.log(JSON.stringify({ console_stage: 'headers', status: delivered.status() }));
  await completed(page);
  console.log(JSON.stringify({ console_stage: 'complete' }));
    await expect(page.locator('pre[aria-live=polite]')).not.toBeEmpty();
    await capture(page, 'inference-replicas-answer');
    await page.setViewportSize({ width: 430, height: 932 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(430);
    await capture(page, 'inference-replicas-answer-narrow');
    await row.getByRole('button', { name: 'Stop', exact: true }).click();
    await expect(row.getByRole('cell').nth(1)).toHaveText('stopped', { timeout: 90000 });
    console.log(JSON.stringify({ stopped_service: identity }));
    expect(faults).toEqual([]);
  } catch (error) {
    await capture(page, 'inference-replicas-failure');
    throw error;
  } finally {
    if (identity) {
      const value = JSON.parse(cli(['inference-get', identity]));
      if (value.state !== 'stopped') cli(['inference-stop', identity, '--revision', String(value.revision)]);
    }
  }
});
