import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdir } from 'node:fs/promises';
import { signIn, navigate, request, tools, noHorizontalOverflow } from './helpers';

test('included Demo is a working first tool without an external account or source editing', async ({
  page,
}) => {
  test.setTimeout(180_000);
  await signIn(page);
  await navigate(page, 'MCP servers');
  await page.getByRole('button', { name: 'Create server', exact: true }).click();
  await expect(page.getByRole('radio', { name: /^Demo/ })).toBeChecked();
  const name = 'ui-starter-demo-' + Date.now().toString(36);
  await page.getByLabel('Unique server name', { exact: true }).fill(name);
  const created = page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname === '/admin/api/servers-dynamic' && r.request().method() === 'POST',
  );
  await page.getByRole('button', { name: 'Create and start Demo', exact: true }).click();
  expect((await created).status()).toBe(201);
  try {
    await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
    await expect(page.locator('.badge.running')).toBeVisible({ timeout: 90_000 });
    await expect.poll(() => tools(page)).toContain(name + '.who_am_i');
    const called = await request<{ result: { isError: boolean; content: { text: string }[] } }>(
      page,
      '/mcp',
      'POST',
      {
        jsonrpc: '2.0',
        id: 'starter-demo-check',
        method: 'tools/call',
        params: { name: name + '.who_am_i', arguments: {} },
      },
    );
    expect(called.status).toBe(200);
    expect(called.data.result.isError).toBeFalsy();
    expect(JSON.stringify(called.data.result)).toContain('admin@example.test');
    await page.getByRole('link', { name: 'Source', exact: true }).click();
    await expect(page.getByText('Included starter', { exact: true })).toBeVisible();
    await expect(page.getByText('1.0.0', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Edit source in console' })).toHaveCount(0);
    const downloaded = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download complete starter', exact: true }).click();
    expect((await downloaded).suggestedFilename()).toBe('demo-starter-1.0.0.zip');
  } finally {
    await request(page, '/admin/api/servers-dynamic/' + name, 'DELETE');
  }
});

test('GitHub starter connects with clear fields, preserves hidden tokens and keeps failed drafts', async ({
  page,
}) => {
  await signIn(page);
  await navigate(page, 'MCP servers');
  await page.getByRole('button', { name: 'Create server', exact: true }).click();
  await page.getByRole('radio', { name: /^GitHub/ }).check();
  const name = 'ui-starter-github-' + Date.now().toString(36);
  const base = '/admin/api/servers-dynamic/' + name;
  await page.getByLabel('Unique server name', { exact: true }).fill(name);
  await page.getByRole('button', { name: 'Create private server', exact: true }).click();
  await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
  try {
    await expect(
      page.getByRole('heading', { name: 'GitHub connection', exact: true }),
    ).toBeVisible();
    await expect(page.getByRole('link', { name: 'Create a GitHub token' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Test GitHub connection' })).toBeDisabled();
    await page.getByLabel('GitHub repository', { exact: true }).fill('sample/project');
    await page.getByLabel('GitHub token', { exact: true }).fill('synthetic-browser-token');
    await page.getByRole('button', { name: 'Save GitHub connection' }).click();
    await expect(page.getByLabel('GitHub token', { exact: true })).toHaveValue('');
    await expect(page.getByLabel('GitHub token', { exact: true })).toHaveAttribute(
      'placeholder',
      'Saved — leave blank to keep',
    );
    const status = await request<{ personal: { repository: string; configured: string[] } }>(
      page,
      base + '/starter-connection',
    );
    expect(status.data.personal.repository).toBe('sample/project');
    expect(JSON.stringify(status.data)).not.toContain('synthetic-browser-token');
    await page.route('**/starter-connection/test', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          account: 'sample-user',
          repository: 'sample/project',
          message: 'Connected as sample-user to sample/project',
          note: 'Account and read permissions verified.',
        }),
      });
    });
    await page.getByRole('button', { name: 'Test GitHub connection' }).click();
    await expect(
      page.getByText('Connected as sample-user to sample/project', { exact: true }),
    ).toBeVisible();
    await page.route('**/starter-connection', async (route) => {
      if (route.request().method() === 'PATCH')
        await route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Try again shortly' }),
        });
      else await route.continue();
    });
    await page.getByLabel('GitHub repository', { exact: true }).fill('sample/updated');
    await page.getByRole('button', { name: 'Save GitHub connection' }).click();
    await expect(page.getByLabel('GitHub repository', { exact: true })).toHaveValue(
      'sample/updated',
    );
    await expect(page.locator('.form-error')).toContainText('Try again shortly');
    await page.unroute('**/starter-connection');
    await page.getByRole('button', { name: 'Save GitHub connection' }).click();
    await expect
      .poll(
        async () =>
          (await request<{ personal: { repository: string } }>(page, base + '/starter-connection'))
            .data.personal.repository,
      )
      .toBe('sample/updated');
    await page.getByRole('radio', { name: /^Use a shared account/ }).check();
    await expect(page.getByLabel('GitHub token', { exact: true })).toHaveAttribute(
      'placeholder',
      'Paste your GitHub token',
    );
    await page.getByLabel('GitHub repository', { exact: true }).fill('shared/project');
    await page.getByLabel('GitHub token', { exact: true }).fill('synthetic-shared-browser-token');
    await page.getByRole('button', { name: 'Save GitHub connection' }).click();
    await expect
      .poll(async () => (await request<{ policy: string }>(page, base)).data.policy)
      .toBe('global_only');
  } finally {
    await page.unroute('**/starter-connection');
    await page.unroute('**/starter-connection/test');
    await request(page, '/credentials/' + name, 'DELETE');
    await request(page, base, 'DELETE');
  }
});

test('starter selection and GitHub setup fit mobile and pass accessibility checks', async ({
  page,
}) => {
  await signIn(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await navigate(page, 'MCP servers');
  await page.getByRole('button', { name: 'Create server', exact: true }).click();
  await expect(page.getByRole('radio', { name: /^Demo/ })).toBeVisible();
  await expect(page.getByRole('radio', { name: /^GitHub/ })).toBeVisible();
  await expect(page.getByRole('radio', { name: /^Custom Python server/ })).toBeVisible();
  await noHorizontalOverflow(page);
  await mkdir('../.local/starter-work/screenshots', { recursive: true });
  await page.screenshot({
    path: '../.local/starter-work/screenshots/create-mobile.png',
    fullPage: true,
  });
  const check = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
    .analyze();
  expect(check.violations).toEqual([]);
  await page.getByRole('radio', { name: /^GitHub/ }).check();
  const name = 'ui-starter-mobile-' + Date.now().toString(36),
    base = '/admin/api/servers-dynamic/' + name;
  await page.getByLabel('Unique server name', { exact: true }).fill(name);
  await page.getByRole('button', { name: 'Create private server', exact: true }).click();
  try {
    await expect(
      page.getByRole('heading', { name: 'GitHub connection', exact: true }),
    ).toBeVisible();
    await noHorizontalOverflow(page);
    await page.screenshot({
      path: '../.local/starter-work/screenshots/github-mobile.png',
      fullPage: true,
    });
    const result = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
      .analyze();
    expect(result.violations).toEqual([]);
  } finally {
    await request(page, base, 'DELETE');
  }
});

test('a colleague configures only their own GitHub account after receiving read access', async ({
  page,
  browser,
}) => {
  const context = await browser.newContext(),
    colleague = await context.newPage();
  await signIn(colleague, 'Analyst');
  const person = await request<{ principal: { id: string } }>(colleague, '/admin/api/whoami');
  await signIn(page);
  const name = 'ui-starter-person-' + Date.now().toString(36),
    base = '/admin/api/servers-dynamic/' + name;
  expect(
    (await request(page, '/admin/api/servers-dynamic', 'POST', { name, starter_id: 'github' }))
      .status,
  ).toBe(201);
  try {
    expect(
      (
        await request(page, base + '/starter-connection', 'PATCH', {
          values: { token: 'synthetic-owner-token', repository: 'owner/project' },
        })
      ).status,
    ).toBe(204);
    expect(
      (
        await request(page, `/admin/api/users/${person.data.principal.id}/access/${name}`, 'PUT', {
          mode: 'grant',
          caps: ['read'],
        })
      ).status,
    ).toBe(200);
    await colleague.goto(new URL('/admin/#credentials/' + name, colleague.url()).toString());
    await expect(
      colleague.getByRole('heading', { name: 'GitHub connection', exact: true }),
    ).toBeVisible();
    await expect(colleague.getByLabel('GitHub repository', { exact: true })).toHaveValue('');
    await expect(colleague.getByRole('radio', { name: /Use a shared account/ })).toHaveCount(0);
    await colleague.getByLabel('GitHub repository', { exact: true }).fill('colleague/project');
    await colleague.getByLabel('GitHub token', { exact: true }).fill('synthetic-colleague-token');
    await colleague.getByRole('button', { name: 'Save GitHub connection' }).click();
    await expect(colleague.getByLabel('GitHub token', { exact: true })).toHaveValue('');
    const own = await request<{ personal: { repository: string } }>(
      colleague,
      base + '/starter-connection',
    );
    const original = await request<{ personal: { repository: string } }>(
      page,
      base + '/starter-connection',
    );
    expect(own.data.personal.repository).toBe('colleague/project');
    expect(original.data.personal.repository).toBe('owner/project');
    expect(JSON.stringify(own.data)).not.toContain('synthetic-owner-token');
  } finally {
    await request(colleague, '/credentials/' + name, 'DELETE');
    await request(page, '/credentials/' + name, 'DELETE');
    await request(page, base, 'DELETE');
    await context.close();
  }
});
