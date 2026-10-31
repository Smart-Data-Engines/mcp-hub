import { test, expect } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { signIn, navigate, request, tools, noHorizontalOverflow } from './helpers';

test('company sign-in, live catalog and mobile navigation', async ({ page }) => {
  const errors: string[] = [];
  const assets: string[] = [];
  page.on('request', (r) => {
    if (/\/admin\/assets\/.*\.js$/.test(r.url())) assets.push(new URL(r.url()).pathname);
  });
  page.on('pageerror', (error) => errors.push(error.message));
  await signIn(page);
  await expect(page.getByText('demo-directory.search', { exact: true })).toBeVisible();
  expect(assets.some((url) => /\/editor-/.test(url))).toBe(false);
  await mkdir('../.local/verification/ux', { recursive: true });
  await writeFile('../.local/verification/ux/initial-assets.json', JSON.stringify(assets, null, 2));
  await navigate(page, 'My credentials');
  await expect(page.getByRole('heading', { name: 'My credentials', exact: true })).toBeVisible();
  await navigate(page, 'Groups');
  await expect(page.getByRole('heading', { name: 'Groups', exact: true })).toBeVisible();
  await navigate(page, 'Overview');
  await expect(page.getByText('demo-directory.search', { exact: true })).toBeVisible();
  await mkdir('../.local/screenshots/ux', { recursive: true });
  await page.screenshot({ path: '../.local/screenshots/ux/overview-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Menu', exact: true }).click();
  await expect(page.getByRole('link', { name: 'MCP servers', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  await noHorizontalOverflow(page);
  await page.screenshot({ path: '../.local/screenshots/ux/mobile-menu.png', fullPage: true });
  await page.getByRole('button', { name: 'Close menu', exact: true }).click();
  await page.screenshot({ path: '../.local/screenshots/ux/overview-mobile.png', fullPage: true });
  expect(errors).toEqual([]);
});

test('publish a private adapter, give a colleague access, connect credentials and revoke access', async ({
  page,
  browser,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  const colleagueContext = await browser.newContext();
  const colleague = await colleagueContext.newPage();
  colleague.on('pageerror', (error) => errors.push(error.message));
  await signIn(colleague, 'Analyst');
  const identity = await request<{ principal: { id: string; username: string } }>(
    colleague,
    '/admin/api/whoami',
  );
  await signIn(page);
  const name = 'ui-' + Date.now().toString(36);
  await navigate(page, 'MCP servers');
  await page.getByRole('button', { name: 'Create server', exact: true }).click();
  await page.getByLabel('Unique server name', { exact: true }).fill(name);
  await page.getByLabel('Description', { exact: true }).fill('Browser acceptance adapter');
  await page.getByRole('button', { name: 'Create private server', exact: true }).click();
  await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
  try {
    await page.getByText('Browse source files', { exact: false }).click();
    await page.getByRole('button', { name: 'Edit source in console', exact: true }).click();
    const editor = page.locator('.cm-content');
    await expect(editor).toBeVisible();
    const source = await request<{ files: Record<string, string> }>(
      page,
      `/admin/api/servers-dynamic/${name}/files`,
    );
    const original = source.data.files['server.py'];
    await editor.fill(original.replace('Hello {name}', 'Hello from browser {name}'));
    await page.getByLabel('Source file', { exact: true }).selectOption('requirements.txt');
    await page.locator('.cm-content').fill('mcp>=1.30,<2\n# edited with server.py in one commit\n');
    await page.getByLabel('Source file', { exact: true }).selectOption('env.yaml');
    await page
      .locator('.cm-content')
      .fill('env: [API_TOKEN, WORKSPACE]\nuser_env: [api_key, workspace]\n');
    await page.getByRole('button', { name: 'Commit 3 changed files', exact: true }).click();
    await expect(page.locator('.notice.success')).toContainText('Files committed together');
    const committed = await request<{ files: Record<string, string> }>(
      page,
      `/admin/api/servers-dynamic/${name}/files`,
    );
    expect(committed.data.files['server.py']).toContain('Hello from browser {name}');
    expect(committed.data.files['server.py']).toContain('serve(mcp)');
    await page.getByRole('link', { name: 'Connection', exact: true }).click();
    await page.getByLabel('API Token', { exact: true }).fill('browser-shared-token');
    await page.getByLabel('Workspace', { exact: true }).fill('workspace-before-restart');
    await page.getByRole('button', { name: 'Save connection', exact: true }).click();
    await expect(page.locator('.notice.success')).toContainText('Connection saved');
    await page.getByText('Change connection mode', { exact: true }).click();
    await page.getByRole('radio', { name: /^Personal connections/ }).check();
    await page.getByRole('button', { name: 'Save connection mode', exact: true }).click();
    await expect(page.locator('.notice.success')).toContainText('Connection mode saved');
    await page.getByRole('link', { name: 'Source', exact: true }).click();
    const start = page.waitForResponse(
      (response) =>
        response.url().endsWith(`/${name}/start`) && response.request().method() === 'POST',
      // A cold worker can install dependencies before registering (up to 60s).
      { timeout: 90_000 },
    );
    await page.getByRole('button', { name: 'Start', exact: true }).click();
    expect((await start).ok()).toBe(true);
    await expect(page.locator('.badge.running')).toBeVisible({ timeout: 90_000 });
    await expect.poll(() => tools(page)).toContain(name + '.hello');
    expect(await tools(colleague)).not.toContain(name + '.hello');
    await page.getByRole('link', { name: 'Connection', exact: true }).click();
    await page.getByLabel('Workspace', { exact: true }).fill('workspace-after-restart');
    await page.getByRole('button', { name: 'Save connection', exact: true }).click();
    await expect(
      page.getByText('Saved changes are waiting for a restart', { exact: true }),
    ).toBeVisible();
    await page.getByRole('button', { name: 'Restart to apply', exact: true }).click();
    await expect(
      page.getByText('Saved changes are waiting for a restart', { exact: true }),
    ).toHaveCount(0);
    await expect(page.locator('.badge.running')).toBeVisible({ timeout: 90_000 });
    await page.getByRole('link', { name: 'Logs', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Container logs', exact: true })).toBeVisible();
    await page.getByRole('link', { name: 'Access', exact: true }).click();
    await page
      .getByRole('button', {
        name: new RegExp(identity.data.principal.username.replace('.', '\\.')),
      })
      .click();
    await expect(page.getByRole('checkbox', { name: /^Read/ })).toBeChecked();
    await page.getByRole('button', { name: 'Save access', exact: true }).click();
    await expect(page.locator('.notice.success')).toContainText('Access updated');
    await expect.poll(() => tools(colleague)).toContain(name + '.hello');
    const shared = await request<{ visibility: string; shared_with: string[] }>(
      page,
      '/admin/api/servers-dynamic/' + name,
    );
    expect(shared.data.visibility).toBe('shared');
    expect(shared.data.shared_with).toEqual([identity.data.principal.id]);
    await page.screenshot({ path: '../.local/screenshots/ux/server-access.png', fullPage: true });
    const args = {
      jsonrpc: '2.0',
      id: 'credential-required',
      method: 'tools/call',
      params: { name: name + '.hello', arguments: { name: 'UX' } },
    };
    const missing = await request<{ result: { isError: boolean } }>(
      colleague,
      '/mcp',
      'POST',
      args,
    );
    expect(missing.data.result.isError).toBe(true);
    await navigate(colleague, 'My credentials');
    await colleague.getByLabel('MCP server', { exact: true }).selectOption(name);
    await colleague.getByLabel('api_key', { exact: true }).fill('browser-test-personal-key');
    await colleague.getByLabel('workspace', { exact: true }).fill('ux-test');
    await colleague.getByRole('checkbox', { name: 'Use only my credentials', exact: true }).check();
    await colleague.getByRole('button', { name: 'Save personal connection', exact: true }).click();
    await expect(colleague.locator('.notice.success')).toContainText('Personal connection saved');
    await expect(colleague.getByLabel('api_key', { exact: true })).toHaveValue('');
    const allowed = await request<{ result: { isError: boolean; content: { text: string }[] } }>(
      colleague,
      '/mcp',
      'POST',
      { ...args, id: 'allowed' },
    );
    expect(allowed.data.result.isError).toBe(false);
    expect(JSON.stringify(allowed.data)).toContain('Hello from browser UX');
    await page.getByRole('radio', { name: /^Block access/ }).check();
    await page.getByRole('button', { name: 'Save access', exact: true }).click();
    await expect(page.locator('.notice.success')).toContainText('Access updated');
    expect(await tools(colleague)).not.toContain(name + '.hello');
    const blocked = await request<{ result: { isError: boolean } }>(colleague, '/mcp', 'POST', {
      ...args,
      id: 'blocked',
    });
    expect(blocked.data.result.isError).toBe(true);
    expect(errors).toEqual([]);
  } finally {
    await request(
      page,
      `/admin/api/users/${encodeURIComponent(identity.data.principal.id)}/access/${name}`,
      'PUT',
      { mode: 'inherit', caps: [] },
    );
    await request(colleague, '/credentials/' + name, 'DELETE');
    await request(colleague, '/credentials/mode', 'POST', { service: name, only_mine: false });
    expect((await request(page, '/admin/api/servers-dynamic/' + name, 'DELETE')).status).toBe(204);
    await colleagueContext.close();
  }
});
