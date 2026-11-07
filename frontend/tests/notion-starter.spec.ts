import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdir } from 'node:fs/promises';
import { signIn, navigate, request, noHorizontalOverflow } from './helpers';

test('Notion has token-only setup, preserves failed drafts and explains missing shared pages', async ({
  page,
}) => {
  await signIn(page);
  await navigate(page, 'MCP servers');
  await page.getByRole('button', { name: 'Create server', exact: true }).click();
  await page.getByRole('radio', { name: /^Notion/ }).check();
  const name = 'ui-notion-' + Date.now().toString(36),
    base = '/admin/api/servers-dynamic/' + name;
  await page.getByLabel('Unique server name', { exact: true }).fill(name);
  await page.getByRole('button', { name: 'Create private server', exact: true }).click();
  try {
    await expect(
      page.getByRole('heading', { name: 'Notion connection', exact: true }),
    ).toBeVisible();
    await expect(page.getByLabel('GitHub repository', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Create a Notion connection' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Test Notion connection' })).toBeDisabled();
    await page.getByLabel('Notion token', { exact: true }).fill('synthetic-notion-browser');
    await page.getByRole('button', { name: 'Save Notion connection' }).click();
    await expect(page.getByLabel('Notion token', { exact: true })).toHaveValue('');
    await expect(page.getByLabel('Notion token', { exact: true })).toHaveAttribute(
      'placeholder',
      'Saved — leave blank to keep',
    );
    const info = await request<{ personal: { configured: string[] } }>(
      page,
      base + '/starter-connection',
    );
    expect(info.data.personal.configured).toEqual(['token']);
    expect(JSON.stringify(info.data)).not.toContain('synthetic-notion-browser');
    await page.route('**/starter-connection/test', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          account: 'Sample connection',
          message: 'Connected as Sample connection',
          shared_content_found: false,
          note: 'Share a page with this connection in Notion and allow time for search indexing.',
        }),
      }),
    );
    await page.getByRole('button', { name: 'Test Notion connection' }).click();
    await expect(
      page.getByText('Next: share a page with this connection in Notion, then test again.', {
        exact: true,
      }),
    ).toBeVisible();
    await expect(page.locator('.callout.success')).toHaveCount(0);
    await page.route('**/starter-connection', async (route) => {
      if (route.request().method() === 'PATCH')
        await route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Retry your saved draft' }),
        });
      else await route.continue();
    });
    await page.getByLabel('Notion token', { exact: true }).fill('synthetic-notion-updated');
    await page.getByRole('button', { name: 'Save Notion connection' }).click();
    await expect(page.locator('.form-error')).toContainText('Retry your saved draft');
    await expect(page.getByLabel('Notion token', { exact: true })).toHaveValue(
      'synthetic-notion-updated',
    );
    await page.unroute('**/starter-connection');
    await page.getByRole('button', { name: 'Save Notion connection' }).click();
    await expect(page.getByLabel('Notion token', { exact: true })).toHaveValue('');
    await page.getByRole('radio', { name: /^Use a shared connection/ }).check();
    await page.getByLabel('Notion token', { exact: true }).fill('synthetic-notion-shared');
    await page.getByRole('button', { name: 'Save Notion connection' }).click();
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

test('Notion connection fits mobile and passes accessibility checks', async ({ page }) => {
  await signIn(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await navigate(page, 'MCP servers');
  await page.getByRole('button', { name: 'Create server', exact: true }).click();
  await expect(page.getByRole('radio', { name: /^Notion/ })).toBeVisible();
  await noHorizontalOverflow(page);
  await page.getByRole('radio', { name: /^Notion/ }).check();
  const name = 'ui-notion-mobile-' + Date.now().toString(36),
    base = '/admin/api/servers-dynamic/' + name;
  await page.getByLabel('Unique server name', { exact: true }).fill(name);
  await page.getByRole('button', { name: 'Create private server', exact: true }).click();
  try {
    await expect(
      page.getByRole('heading', { name: 'Notion connection', exact: true }),
    ).toBeVisible();
    await noHorizontalOverflow(page);
    await mkdir('../.local/notion-starter-work/screenshots', { recursive: true });
    await page.screenshot({
      path: '../.local/notion-starter-work/screenshots/notion-mobile.png',
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

test('a colleague saves only their own Notion connection from My credentials', async ({
  page,
  browser,
}) => {
  const context = await browser.newContext(),
    colleague = await context.newPage();
  await signIn(colleague, 'Analyst');
  const person = await request<{ principal: { id: string } }>(colleague, '/admin/api/whoami');
  await signIn(page);
  const name = 'ui-notion-colleague-' + Date.now().toString(36),
    base = '/admin/api/servers-dynamic/' + name;
  expect(
    (await request(page, '/admin/api/servers-dynamic', 'POST', { name, starter_id: 'notion' }))
      .status,
  ).toBe(201);
  try {
    expect(
      (
        await request(page, base + '/starter-connection', 'PATCH', {
          values: { token: 'synthetic-notion-owner' },
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
      colleague.getByRole('heading', { name: 'Notion connection', exact: true }),
    ).toBeVisible();
    await expect(colleague.getByRole('radio', { name: /Use a shared connection/ })).toHaveCount(0);
    await colleague.getByLabel('Notion token', { exact: true }).fill('synthetic-notion-colleague');
    await colleague.getByRole('button', { name: 'Save Notion connection' }).click();
    await expect(colleague.getByLabel('Notion token', { exact: true })).toHaveValue('');
    const own = await request<{ personal: { configured: string[] } }>(
      colleague,
      base + '/starter-connection',
    );
    expect(own.data.personal.configured).toEqual(['token']);
    expect(JSON.stringify(own.data)).not.toContain('synthetic-notion-owner');
  } finally {
    await request(colleague, '/credentials/' + name, 'DELETE');
    await request(page, '/credentials/' + name, 'DELETE');
    await request(page, base, 'DELETE');
    await context.close();
  }
});
