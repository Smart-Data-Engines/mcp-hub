import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdir } from 'node:fs/promises';
import { noHorizontalOverflow, request, signIn } from './helpers';

test('connection fields preserve hidden secrets, retain failed drafts, and remove only explicitly chosen values', async ({
  page,
}) => {
  await signIn(page);
  const name = 'ux-connection-' + Date.now().toString(36),
    base = '/admin/api/servers-dynamic/' + name;
  expect((await request(page, '/admin/api/servers-dynamic', 'POST', { name })).status).toBe(201);
  let attempts = 0;
  try {
    expect(
      (
        await request(page, base + '/commit', 'POST', {
          files: { 'env.yaml': 'env: [API_TOKEN, WORKSPACE]\nuser_env: []\n' },
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await request(page, base + '/env', 'POST', {
          values: { API_TOKEN: 'qa-hidden-original-token', WORKSPACE: 'original-workspace' },
        })
      ).status,
    ).toBe(204);
    await page.goto('/admin/#servers/' + name + '/environment');
    await expect(page.getByText('2 of 2 saved', { exact: true })).toBeVisible();
    const token = page.getByLabel('API Token', { exact: true }),
      workspace = page.getByLabel('Workspace', { exact: true });
    await expect(token).toHaveValue('');
    await expect(token).toHaveAttribute('type', 'password');
    await expect(page.getByRole('button', { name: 'Save connection', exact: true })).toBeDisabled();
    await expect(page.locator('textarea')).toHaveCount(0);
    expect(await page.locator('body').textContent()).not.toContain('qa-hidden-original-token');
    await page.route('**' + base + '/env', (route) => {
      if (route.request().method() !== 'PATCH') return route.continue();
      attempts++;
      if (attempts === 1)
        return route.fulfill({
          status: 503,
          json: { error: 'Temporary save failure. Try again.' },
        });
      return route.continue();
    });
    await workspace.fill('replacement-workspace');
    await page.getByRole('button', { name: 'Save connection', exact: true }).click();
    await expect(page.locator('.form-error')).toBeVisible();
    await expect(workspace).toHaveValue('replacement-workspace');
    await page.getByRole('button', { name: 'Save connection', exact: true }).click();
    await expect(page.locator('.notice.success')).toContainText('Connection saved');
    await expect(workspace).toHaveValue('');
    const saved = await request<{ values: Record<string, string> }>(page, base + '/env/values');
    expect(saved.data.values).toEqual({
      API_TOKEN: 'qa-hidden-original-token',
      WORKSPACE: 'replacement-workspace',
    });
    expect(attempts).toBe(2);
    await workspace.fill('draft-that-must-survive');
    await page.getByRole('link', { name: 'Source', exact: true }).click();
    await page
      .getByRole('dialog', { name: 'Leave without saving?', exact: true })
      .getByRole('button', { name: 'Cancel', exact: true })
      .click();
    await expect(workspace).toHaveValue('draft-that-must-survive');
    await workspace.fill('');
    await page.getByRole('button', { name: 'Remove API_TOKEN', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Save connection', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: 'Remove API_TOKEN', exact: true }).click();
    await page.getByRole('button', { name: 'Mark for removal', exact: true }).click();
    await expect(page.getByText('Will be removed', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Save connection', exact: true }).click();
    await expect(page.getByText('1 of 2 saved', { exact: true })).toBeVisible();
    const removed = await request<{ values: Record<string, string> }>(page, base + '/env/values');
    expect(removed.data.values).toEqual({ WORKSPACE: 'replacement-workspace' });
  } finally {
    await request(page, base, 'DELETE');
  }
});

test('source and connection screens are clear and accessible on desktop and narrow phones', async ({
  page,
}) => {
  await signIn(page);
  const name = 'ux-layout-' + Date.now().toString(36),
    base = '/admin/api/servers-dynamic/' + name;
  expect((await request(page, '/admin/api/servers-dynamic', 'POST', { name })).status).toBe(201);
  try {
    await request(page, base + '/commit', 'POST', {
      files: { 'env.yaml': 'env: [SERVICE_TOKEN]\nuser_env: []\n' },
    });
    await request(page, base + '/env', 'POST', {
      values: { SERVICE_TOKEN: 'qa-layout-only-secret' },
    });
    await mkdir('../.local/screenshots/connection-layout', { recursive: true });
    for (const tab of ['source', 'environment']) {
      await page.goto('/admin/#servers/' + name + '/' + tab);
      await expect(
        page.getByRole('heading', {
          name: tab === 'source' ? 'Source & updates' : 'Connection & environment',
          exact: true,
        }),
      ).toBeVisible();
      await expect.poll(() => page.locator('.loading-state').count()).toBe(0);
      if (tab === 'environment') {
        await page.getByText('Change connection mode', { exact: true }).click();
        await page
          .getByText('People with access use the connection saved for this server.', {
            exact: true,
          })
          .click();
        const shared = page.getByRole('radio', { name: /^Shared connection/ });
        await expect(shared).toBeChecked();
        await shared.focus();
        await page.keyboard.press('ArrowDown');
        await expect(page.getByRole('radio', { name: /^Personal connections/ })).toBeChecked();
        await page.keyboard.press('ArrowUp');
        await expect(shared).toBeChecked();
      }
      for (const width of [1440, 1024, 768, 390, 320]) {
        await page.setViewportSize({ width, height: 1000 });
        await page.screenshot({
          path: `../.local/screenshots/connection-layout/${tab}-${width}.png`,
          fullPage: true,
        });
        if (tab === 'environment') {
          await expect(page.getByRole('radio')).toHaveCount(3);
          for (const choice of await page.locator('.connection-mode').all()) {
            const bounds = await choice.evaluate((card) => {
              const rect = (element: Element) => {
                const box = element.getBoundingClientRect();
                return { left: box.left, right: box.right, width: box.width, height: box.height };
              };
              return {
                card: rect(card),
                radio: rect(card.querySelector('input')!),
                text: rect(card.querySelector('span')!),
              };
            });
            expect(bounds.radio.width).toBeLessThanOrEqual(24);
            expect(bounds.radio.height).toBeLessThanOrEqual(24);
            expect(bounds.radio.width).toBeGreaterThanOrEqual(12);
            expect(bounds.text.left).toBeGreaterThan(bounds.radio.right + 6);
            expect(bounds.text.right).toBeLessThanOrEqual(bounds.card.right - 8);
          }
        }
        await noHorizontalOverflow(page);
        expect(
          (await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze())
            .violations,
        ).toEqual([]);
      }
    }
  } finally {
    await request(page, base, 'DELETE');
  }
});
