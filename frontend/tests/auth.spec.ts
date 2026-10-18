import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { createServer } from 'node:http';
import { noHorizontalOverflow, navigate, signIn } from './helpers';

for (const decision of ['allow', 'deny'] as const) {
  test(`external client consent is accessible on mobile and returns ${decision} to its application`, async ({
    page,
  }) => {
    const origin = new URL(process.env.MCP_HUB_UI_URL || 'http://localhost:8000').origin;
    const callbacks: string[] = [];
    const receiver = createServer((request, response) => {
      if (!request.url?.startsWith('/callback?')) {
        response.writeHead(404).end();
        return;
      }
      callbacks.push(request.url);
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      response.end(
        '<!doctype html><title>Desktop application</title><h1>Application callback</h1>',
      );
    });
    await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
    const address = receiver.address();
    if (!address || typeof address === 'string') throw new Error('Callback receiver did not bind');
    const callback = `http://127.0.0.1:${address.port}/callback`;
    try {
      const registration = await page.request.post(origin + '/oauth/register', {
        data: { client_name: 'Desktop application', redirect_uris: [callback] },
      });
      expect(registration.status()).toBe(201);
      const client = await registration.json();
      const verifier = 'browser-verifier-'.repeat(4);
      const challenge = Buffer.from(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)),
      ).toString('base64url');
      await page.goto(
        origin +
          '/authorize?' +
          new URLSearchParams({
            response_type: 'code',
            client_id: client.client_id,
            redirect_uri: callback,
            scope: 'mcp',
            resource: origin + '/mcp',
            code_challenge: challenge,
            code_challenge_method: 'S256',
            state: 'desktop-connection',
          }),
      );
      await page.getByRole('button', { name: 'Admin', exact: true }).click();
      await expect(
        page.getByRole('heading', { name: 'Connect Desktop application?' }),
      ).toBeVisible();
      for (const width of [390, 320]) {
        await page.setViewportSize({ width, height: 844 });
        await noHorizontalOverflow(page);
      }
      const accessibility = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
        .analyze();
      expect(accessibility.violations).toEqual([]);
      const errors: string[] = [];
      page.on('console', (message) => {
        if (message.type() === 'error') errors.push(message.text());
      });
      await page
        .getByRole('button', {
          name: decision === 'allow' ? 'Allow access' : 'Cancel',
          exact: true,
        })
        .click();
      await expect(page, errors.join('\n')).toHaveURL(
        new RegExp('^' + callback.replaceAll('.', '\\.') + '\\?'),
      );
      await expect(
        page.getByRole('heading', { name: 'Application callback', exact: true }),
      ).toBeVisible();
      expect(callbacks).toHaveLength(1);
      expect(new URL(callbacks[0], callback).search).toBe(new URL(page.url()).search);
      const result = new URL(page.url()).searchParams;
      expect(result.get('state')).toBe('desktop-connection');
      if (decision === 'deny') {
        expect(result.get('error')).toBe('access_denied');
        expect(result.has('code')).toBe(false);
      } else {
        const token = await page.request.post(origin + '/token', {
          form: {
            grant_type: 'authorization_code',
            client_id: client.client_id,
            redirect_uri: callback,
            code_verifier: verifier,
            code: result.get('code')!,
          },
        });
        expect(token.status()).toBe(200);
        const headers = { Authorization: 'Bearer ' + (await token.json()).access_token };
        expect((await page.request.get(origin + '/admin/api/users', { headers })).status()).toBe(
          403,
        );
      }
    } finally {
      receiver.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        receiver.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });
}

test('source opens repository information without downloading files or an editor; browsing is optional', async ({
  page,
}) => {
  let fileRequests = 0;
  const editors: string[] = [];
  page.on('request', (request) => {
    if (request.url().endsWith('/demo-directory/files')) fileRequests++;
    if (/\/admin\/assets\/editor-.*\.js$/.test(request.url())) editors.push(request.url());
  });
  await page.route('**/admin/api/whoami', async (route) => {
    const response = await route.fetch();
    const data = await response.json();
    await route.fulfill({ response, json: { ...data, source_editing_enabled: false } });
  });
  await signIn(page);
  await navigate(page, 'MCP servers');
  await page.locator('.server-row').filter({ hasText: 'demo-directory' }).click();
  await page.getByRole('link', { name: 'Source', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Source & updates', exact: true })).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'How to update this server', exact: true }),
  ).toBeVisible();
  expect(fileRequests).toBe(0);
  expect(editors).toEqual([]);
  await expect(page.getByRole('button', { name: /Commit .*changed files/ })).toHaveCount(0);
  await page.getByText('Browse source files', { exact: false }).click();
  await expect(page.getByLabel('Source file', { exact: true })).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Edit source in console', exact: true }),
  ).toHaveCount(0);
  await expect(page.locator('.cm-content')).toHaveCount(0);
  expect(editors).toEqual([]);
});
