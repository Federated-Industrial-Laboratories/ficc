// SPDX-License-Identifier: Apache-2.0
// Run browser checks against an isolated local service; retain no credentials.
import { defineConfig } from '../../web/node_modules/@playwright/test/index.mjs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export default defineConfig({
  testDir: '.', testMatch: '*.spec.mjs', fullyParallel: false, workers: 1,
  timeout: 30000, expect: { timeout: 10000 }, reporter: 'list',
  outputDir: process.env.FICC_BROWSER_OUTPUT || join(tmpdir(), 'ficc-browser-results'),
  use: {
    browserName: 'chromium', headless: process.env.FICC_HEADED !== '1',
    launchOptions: { executablePath: process.env.FICC_BROWSER || '/opt/google/chrome/chrome', args: ['--no-sandbox'] },
    viewport: { width: 1280, height: 1000 }, trace: 'off', screenshot: 'off', video: 'off',
  },
});
