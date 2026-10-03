// SPDX-License-Identifier: Apache-2.0
// Exercise a real, explicitly selected remote identity service without retaining credentials in reports.
import { execFileSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { readFile, writeFile, stat } from 'node:fs/promises';
import { test, expect } from '../../web/node_modules/@playwright/test/index.mjs';
import { capture } from './support.mjs';

function totp(secret) {
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const hash = createHmac('sha1', Buffer.from(secret, 'utf8')).update(counter).digest();
  return String((hash.readUInt32BE(hash[hash.length - 1] & 15) & 0x7fffffff) % 1000000).padStart(6, '0');
}

test('remote MFA, approval, project rights, refresh and external revocation', async ({ browser }) => {
  const seedPath = process.env.FICC_TEST_REMOTE_SEED, control = process.env.FICC_TEST_REMOTE_CONTROL;
  test.skip(!seedPath || !control, 'Requires private disposable identity fixtures and the live remote control helper.');
  test.setTimeout(600000);
  const info = await stat(seedPath);
  expect(info.isFile() && info.uid === process.getuid() && (info.mode & 0o077) === 0).toBe(true);
  const seed = JSON.parse(await readFile(seedPath, 'utf8'));
  const contexts = [], errors = [];
  let page, stage = 'start';
  function command(operation) {
    try { return JSON.parse(execFileSync(control, [], {input: JSON.stringify({operation}), encoding:'utf8',
      stdio:['pipe','pipe','pipe'], timeout:30000})); }
    catch { throw new Error('The private remote fixture command failed.'); }
  }
  async function profile(user) {
    if(await page.locator('#email').count()) {
      stage=`${user.name} profile completion`;
      await page.locator('#email').fill(user.username+'@example.invalid');
      await page.locator('form [type=submit]').last().click();
    }
  }
  async function signIn(name) {
    const user = seed.users.find(value => value.name === name);
    const context = await browser.newContext({extraHTTPHeaders:{'X-FICC-Qualification':seed.qualification_header}});
    contexts.push(context); page = await context.newPage();
    page.on('pageerror', error => errors.push(error.name));
    stage=`${name} sign-in page`;await page.goto(seed.origin);
    await page.getByRole('button',{name:'Sign in with organisation account',exact:true}).click();
    stage=`${name} password`;await page.locator('#username').fill(user.username); await page.locator('#password').fill(user.password);
    await page.locator('#kc-login').click();
    stage=`${name} authenticator`;let input = page.locator('#totp, #otp'); await expect(input).toBeVisible();
    if (await page.locator('#totpSecret').count()) {
      user.otp_secret = await page.locator('#totpSecret').inputValue();
      await writeFile(seedPath, JSON.stringify(seed), {mode:0o600});
      await page.locator('#userLabel').fill('Disposable qualification authenticator');
      await input.fill('000000');
      await page.locator('#kc-totp-settings-form [type=submit]').click();
      await expect(input).toBeVisible();
      expect((await context.request.get(seed.origin+'/api/v1/session')).status()).toBe(401);
      await input.fill(totp(user.otp_secret));
      user.last_counter=Math.floor(Date.now()/30000);await writeFile(seedPath,JSON.stringify(seed),{mode:0o600});
      stage=`${name} authenticator enrollment`;await page.locator('#kc-totp-settings-form [type=submit]').click();
      await page.waitForFunction(origin=>(location.origin===origin && location.pathname==='/') || document.querySelector('#otp, #email'),seed.origin);
      await profile(user);
      await page.waitForFunction(origin=>(location.origin===origin && location.pathname==='/') || document.querySelector('#otp'),seed.origin);
      if(new URL(page.url()).pathname==='/') return context;
      input=page.locator('#otp');
    }
    if (user.last_counter === Math.floor(Date.now()/30000)) {
      await new Promise(resolve=>setTimeout(resolve, 30050-Date.now()%30000));
    }
    expect(typeof user.otp_secret).toBe('string');
    await input.fill(totp(user.otp_secret));
    user.last_counter=Math.floor(Date.now()/30000);await writeFile(seedPath,JSON.stringify(seed),{mode:0o600});
    stage=`${name} authenticator verification`;await page.locator('form [type=submit]').last().click();
    await page.waitForFunction(origin=>(location.origin===origin && location.pathname==='/') || document.querySelector('#email'),seed.origin);
    await profile(user);
    await page.waitForURL(url=>url.origin===seed.origin && url.pathname==='/',{timeout:30000});
    return context;
  }
  async function session(context) {
    const response=await context.request.get(seed.origin+'/api/v1/session');
    expect(response.status()).toBe(200);return response.json();
  }
  try {
    stage='unapproved MFA identity'; const unapproved=await signIn('unapproved');
    stage='unapproved identity refusal';
    await expect(page.getByRole('status').filter({hasText:'An administrator must approve your identity'})).toBeVisible();
    expect((await unapproved.request.get(seed.origin+'/api/v1/session')).status()).toBe(401);
    await capture(page,'remote-unapproved');
    stage='approved MFA identity'; let approved=await signIn('approved');
    await expect(page.locator('#account')).toHaveText(seed.ficc.identity.label);
    let value=await session(approved);
    expect(value.remote).toBe(true);expect(value.principal.local_owner).toBe(false);
    expect(value.principal.subject_id).toBe(seed.ficc.identity.id);
    const cookies=await approved.cookies(seed.origin);
    const cookie=cookies.find(item=>item.name==='__Host-ficc_session');
    expect(Boolean(cookie?.secure && cookie?.httpOnly && cookie?.sameSite==='Strict')).toBe(true);
    expect((await approved.request.get(seed.origin+'/api/v1/external-identities')).status()).toBe(403);
    const [operations,inspection]=seed.ficc.projects;
    stage='project rights and workspace';
    await page.getByLabel('Current project').selectOption(operations.id);
    await expect(page.getByLabel('Current project')).toBeEnabled();
    await expect.poll(async()=> (await session(approved)).principal.project_id).toBe(operations.id);
    await page.getByLabel('Workspace name',{exact:true}).fill('Remote operations runbook');
    await page.getByRole('button',{name:'New workspace',exact:true}).click();
    await expect(page.getByLabel('Saved workspace')).toContainText('Remote operations runbook');
    await capture(page,'remote-operations-workspace');
    await page.getByLabel('Current project').selectOption(inspection.id);
    await expect(page.getByLabel('Current project')).toBeEnabled();
    await expect.poll(async()=> (await session(approved)).principal.project_id).toBe(inspection.id);
    value=await session(approved);expect(value.principal.scopes).not.toContain('workspaces:write');
    expect((await approved.request.get(seed.origin+'/api/v1/workspaces')).ok()).toBe(true);
    expect((await (await approved.request.get(seed.origin+'/api/v1/workspaces')).json()).workspaces).toHaveLength(0);
    await page.locator('[data-view=access]').click();
    await expect(page.getByText('Session expires',{exact:true})).toBeVisible();
    await capture(page,'remote-project-access');
    stage='real refresh';
    console.log(JSON.stringify({stage,approvalAndProjectChecks:true}));
    const ends=Date.now()+310000;
    while(Date.now()<ends){ await new Promise(resolve=>setTimeout(resolve,10000)); await session(approved); }
    console.log(JSON.stringify({stage,complete:true}));
    stage='external revocation';const revoked=Date.now();command('identity-logout');
    await expect.poll(async()=> (await approved.request.get(seed.origin+'/api/v1/session')).status(),
      {timeout:35000,intervals:[500,1000]}).toBe(401);
    expect(Date.now()-revoked).toBeLessThan(35000);
    stage='mapping revocation';approved=await signIn('approved');await session(approved);
    command('mapping-disable');expect((await approved.request.get(seed.origin+'/api/v1/session')).status()).toBe(401);
    command('mapping-enable');expect((await approved.request.get(seed.origin+'/api/v1/session')).status()).toBe(401);
    stage='local sign-out';approved=await signIn('approved');await session(approved);
    await page.locator('#sign-out').click();
    await expect(page.getByRole('heading',{name:'Sign in to FICC',exact:true})).toBeVisible();
    expect((await approved.request.get(seed.origin+'/api/v1/session')).status()).toBe(401);
    stage='same-context second factor after sign-out';
    await page.getByRole('button',{name:'Sign in with organisation account',exact:true}).click();
    await expect(page.locator('#otp')).toBeVisible();
    expect((await approved.request.get(seed.origin+'/api/v1/session')).status()).toBe(401);
    const user=seed.users.find(value=>value.name==='approved');
    if(user.last_counter===Math.floor(Date.now()/30000)) {
      await new Promise(resolve=>setTimeout(resolve,30050-Date.now()%30000));
    }
    await page.locator('#otp').fill(totp(user.otp_secret));
    user.last_counter=Math.floor(Date.now()/30000);await writeFile(seedPath,JSON.stringify(seed),{mode:0o600});
    await page.locator('form [type=submit]').last().click();
    await page.waitForURL(url=>url.origin===seed.origin && url.pathname==='/',{timeout:30000});
    await session(approved);await expect(page.locator('#account')).toHaveText(seed.ficc.identity.label);
    await page.locator('#sign-out').click();
    await expect(page.getByRole('heading',{name:'Sign in to FICC',exact:true})).toBeVisible();
    expect((await approved.request.get(seed.origin+'/api/v1/session')).status()).toBe(401);
    expect(errors).toEqual([]);
  } catch {
    if(page) console.log(JSON.stringify({stage,path:new URL(page.url()).pathname,
      inputs:await page.locator('input').evaluateAll(nodes=>nodes.map(node=>({id:node.id,type:node.type}))).catch(()=>[]),
      status:new URL(page.url()).pathname==='/' ? await page.getByRole('status').allTextContents().catch(()=>[]) : []}));
    await page?.goto('about:blank').catch(()=>{});
    throw new Error(`The real remote workflow failed during ${stage}. Credentials and authentication URLs are omitted.`);
  } finally {
    command('mapping-enable');
    for(const context of contexts) await context.close();
  }
});
