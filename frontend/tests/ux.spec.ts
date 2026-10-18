import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { signIn, navigate, request, noHorizontalOverflow } from './helpers';

test('deep links, refresh, back navigation, search recovery and copying the MCP endpoint', async ({
  page,
  context,
}) => {
  await signIn(page);
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.getByRole('button', { name: 'Copy endpoint', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: /^Copied$/ })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    new URL('/mcp', page.url()).href,
  );
  await page.getByLabel('Search tools', { exact: true }).fill('no-such-tool-ux');
  await expect(
    page.getByRole('heading', { name: 'No tools match these filters', exact: true }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Clear filters', exact: true }).click();
  await expect(page.getByText('demo-directory.search', { exact: true })).toBeVisible();
  await navigate(page, 'MCP servers');
  await page.locator('.server-row').filter({ hasText: 'demo-directory' }).click();
  await expect(page.getByRole('link', { name: 'Access', exact: true })).toHaveAttribute(
    'aria-current',
    'page',
  );
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(page).toHaveURL(/#servers\/demo-directory\/settings$/);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Server settings', exact: true })).toBeVisible();
  await page.goBack();
  await expect(
    page.getByRole('heading', { name: 'Who can use this server?', exact: true }),
  ).toBeVisible();
});

test('unsaved changes survive cancelling navigation and keyboard focus stays inside the dialog', async ({
  page,
}) => {
  await signIn(page);
  await navigate(page, 'MCP servers');
  await page.locator('.server-row').filter({ hasText: 'demo-directory' }).click();
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  const field = page.getByLabel('Description', { exact: true });
  const original = await field.inputValue();
  await field.fill('Draft that must survive cancellation');
  await navigate(page, 'Overview');
  const dialog = page.getByRole('dialog', { name: 'Leave without saving?', exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Cancel', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(dialog.getByRole('button', { name: 'Discard changes', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(dialog.getByRole('button', { name: 'Close dialog', exact: true })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(field).toHaveValue('Draft that must survive cancellation');
  await navigate(page, 'Overview');
  await dialog.getByRole('button', { name: 'Discard changes', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'One place for your tools.' })).toBeVisible();
  await page.goBack();
  await expect(page.getByLabel('Description', { exact: true })).toHaveValue(original);
});

test('group permissions use server and capability controls, then assign to a person', async ({
  page,
}) => {
  await signIn(page);
  const name = 'ux-group-' + Date.now().toString(36);
  const directory = await request<{ users: { id: string; username: string; group: string }[] }>(
    page,
    '/admin/api/access',
  );
  const person = directory.data.users.find((u) => u.username === 'analyst@example.test')!;
  expect(person).toBeTruthy();
  try {
    await navigate(page, 'Groups');
    await page.getByRole('button', { name: 'Create group', exact: true }).click();
    await page.getByLabel('Group name', { exact: true }).fill(name);
    const server = page
      .locator('.group-server')
      .filter({ has: page.locator('strong', { hasText: /^demo-directory$/ }) });
    await server.getByRole('checkbox', { name: /^demo-directory/ }).check();
    await server.getByRole('checkbox', { name: /^Create & update/ }).check();
    await page.getByRole('button', { name: 'Save group', exact: true }).click();
    await expect(page.locator('.notice.success')).toContainText('Group permissions saved');
    await expect(page).toHaveURL(new RegExp('#groups/' + name + '$'));
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await navigate(page, 'Users & access');
    await page.locator('.person-row').filter({ hasText: person.username }).click();
    await page.getByLabel('Permission group', { exact: true }).selectOption(name);
    await page.getByRole('button', { name: 'Save group assignment', exact: true }).click();
    await expect(page.locator('.notice.success')).toContainText('Permission group updated');
    const result = await request<{ servers: Record<string, { effective_caps: string[] }> }>(
      page,
      `/admin/api/users/${encodeURIComponent(person.id)}/servers`,
    );
    expect(result.data.servers['demo-directory'].effective_caps).toEqual(['read', 'write']);
    await page.screenshot({ path: '../.local/screenshots/ux/user-access.png', fullPage: true });
    await navigate(page, 'Groups');
    await page.locator('.person-row').filter({ hasText: name }).click();
    await page.screenshot({ path: '../.local/screenshots/ux/group-editor.png', fullPage: true });
  } finally {
    await request(page, `/admin/api/users/${encodeURIComponent(person.id)}/group`, 'PUT', {
      group: person.group,
    });
    await request(page, '/admin/api/groups/' + name, 'DELETE');
  }
});

test('a failed save keeps the draft and a retry succeeds without duplicate submissions', async ({
  page,
}) => {
  await signIn(page);
  const name = 'ux-retry-' + Date.now().toString(36);
  let attempts = 0;
  await page.route('**/admin/api/groups', async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    attempts++;
    if (attempts === 1) {
      await new Promise((resolve) => setTimeout(resolve, 300));
      return route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Connection interrupted. Your changes were not saved. Try again.',
        }),
      });
    }
    return route.continue();
  });
  try {
    await navigate(page, 'Groups');
    await page.getByRole('button', { name: 'Create group', exact: true }).click();
    await page.getByLabel('Group name', { exact: true }).fill(name);
    await page.getByRole('button', { name: 'Save group', exact: true }).dblclick();
    await expect(page.locator('.form-error')).toContainText('Connection interrupted');
    expect(attempts).toBe(1);
    await expect(page.getByLabel('Group name', { exact: true })).toHaveValue(name);
    await page.getByRole('button', { name: 'Save group', exact: true }).click();
    await expect(page.locator('.notice.success')).toContainText('Group permissions saved');
    expect(attempts).toBe(2);
  } finally {
    await request(page, '/admin/api/groups/' + name, 'DELETE');
  }
});

test('desktop views and selected controls pass automated accessibility checks', async ({
  page,
}) => {
  test.setTimeout(240_000);
  await page.goto('/admin/');
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
        .analyze()
    ).violations,
  ).toEqual([]);
  await signIn(page);
  const labels = [
    'Overview',
    'MCP servers',
    'Users & access',
    'Groups',
    'Workspace roles',
    'Service clients',
    'Approvals',
    'Audit outbox',
    'My credentials',
  ];
  for (const label of labels) {
    await navigate(page, label);
    await expect.poll(() => page.locator('.loading-state').count()).toBe(0);
    const result = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
      .analyze();
    expect(
      result.violations,
      `${label}: ${JSON.stringify(result.violations.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => ({ target: n.target, summary: n.failureSummary })) })))}`,
    ).toEqual([]);
  }
  await navigate(page, 'MCP servers');
  await page.locator('.server-row').filter({ hasText: 'demo-directory' }).click();
  await page.getByRole('button', { name: /analyst@example/ }).click();
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
        .analyze()
    ).violations,
  ).toEqual([]);
});

test('mobile layouts keep primary actions and sign-out usable without horizontal page scrolling', async ({
  page,
}) => {
  test.setTimeout(240_000);
  await signIn(page);
  for (const width of [390, 320, 768]) {
    await page.setViewportSize({ width, height: 844 });
    for (const label of [
      'Overview',
      'MCP servers',
      'Users & access',
      'Groups',
      'Workspace roles',
      'Service clients',
      'Approvals',
      'Audit outbox',
      'My credentials',
    ]) {
      await navigate(page, label);
      await expect.poll(() => page.locator('.loading-state').count()).toBe(0);
      await noHorizontalOverflow(page);
    }
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
});

test('company sign-in returns to the requested section', async ({ page }) => {
  await signIn(page, 'Admin', '#groups');
  await expect(page.getByRole('heading', { name: 'Groups', exact: true })).toBeVisible();
  await expect(page).toHaveURL(/\/admin\/#groups$/);
});

test('an interrupted enhanced editor still allows editing and saving without a page reload', async ({
  page,
}) => {
  await page.route('**/admin/assets/editor-*.js', (route) => route.abort());
  await signIn(page);
  const name = 'ux-basic-' + Date.now().toString(36);
  expect((await request(page, '/admin/api/servers-dynamic', 'POST', { name })).status).toBe(201);
  const base = '/admin/api/servers-dynamic/' + name;
  try {
    await page.goto('/admin/#servers/' + name + '/source');
    await page.getByText('Browse source files', { exact: false }).click();
    await page.getByRole('button', { name: 'Edit source in console', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Using the basic editor', exact: true }),
    ).toBeVisible();
    const editor = page.getByLabel('File contents', { exact: true });
    const original = await editor.inputValue();
    await editor.fill(original + '\n# saved through the basic editor\n');
    await page.getByRole('button', { name: 'Commit 1 changed files', exact: true }).click();
    await expect(page.locator('.notice.success')).toContainText('Files committed together');
    const stored = await request<{ files: Record<string, string> }>(page, base + '/files');
    expect(stored.data.files['server.py']).toContain('# saved through the basic editor');
    await expect(page.getByRole('link', { name: 'Overview', exact: true })).toBeVisible();
  } finally {
    await request(page, base, 'DELETE');
  }
});
