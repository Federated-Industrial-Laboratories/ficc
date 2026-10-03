// SPDX-License-Identifier: Apache-2.0
// Pin the two disposable fixture keys and use a private isolated-display profile.
import { defineConfig } from '../../web/node_modules/@playwright/test/index.mjs';

const pins = process.env.FICC_BROWSER_SPKI;
if (!/^[A-Za-z0-9+/]{43}=,[A-Za-z0-9+/]{43}=$/.test(pins || '')) throw new Error('Two exact fixture keys are required.');
export default defineConfig({
  testDir: '.', testMatch: 'remote-streams.spec.mjs', workers: 1, fullyParallel: false,
  timeout: 120000, expect: { timeout: 12000 }, reporter: 'list',
  outputDir: process.env.FICC_BROWSER_OUTPUT,
  use: {
    browserName: 'chromium', headless: false, ignoreHTTPSErrors: false,
    launchOptions: { executablePath: '/opt/google/chrome/chrome',
      args: ['--no-sandbox', `--ignore-certificate-errors-spki-list=${pins}`] },
    viewport: { width: 1280, height: 1000 }, trace: 'off', screenshot: 'off', video: 'off',
  },
});
