import { expect, type Page, type Response } from '@playwright/test';

async function authenticationBackoff(response: Response) {
  if (response.status() !== 429) return false;
  const seconds = Number(response.headers()['retry-after']);
  expect(Number.isFinite(seconds) && seconds > 0 && seconds <= 60).toBe(true);
  console.info(
    `Authentication ${new URL(response.url()).pathname} throttled; retrying in ${seconds}s`,
  );
  // Start a fresh OIDC flow after the server's authentication window expires.
  await new Promise((resolve) => setTimeout(resolve, seconds * 1000));
  return true;
}

export async function signIn(page: Page, account = 'Admin', returnTo = '') {
  const base = process.env.MCP_HUB_UI_URL || 'http://localhost:8000';
  const origin = new URL(base).origin;
  const responseAt = (match: (path: string) => boolean) =>
    page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.origin === origin && match(url.pathname);
    });
  for (let attempt = 0; attempt < 5; attempt++) {
    await page.goto(base + '/admin/' + returnTo);
    const [authorization] = await Promise.all([
      responseAt((path) => path === '/authorize'),
      page.getByRole('button', { name: /Continue with company sign-in/ }).click(),
    ]);
    if (await authenticationBackoff(authorization)) continue;
    expect(authorization.status()).toBe(302);
    const tokenResponse = responseAt((path) => path === '/token').catch(() => null);
    const [callback] = await Promise.all([
      responseAt((path) => path.startsWith('/oauth/') && path.endsWith('/callback')),
      page.getByRole('button', { name: account, exact: true }).click(),
    ]);
    if (await authenticationBackoff(callback)) continue;
    expect(callback.status()).toBe(302);
    const token = await tokenResponse;
    if (!token) throw new Error('Console sign-in did not exchange its authorization code.');
    if (await authenticationBackoff(token)) continue;
    expect(token.status()).toBe(200);
    await expect(page.getByRole('navigation', { name: 'Workspace navigation' })).toBeVisible();
    if (!returnTo)
      await expect(page.getByRole('heading', { name: 'One place for your tools.' })).toBeVisible();
    return;
  }
  throw new Error('Company sign-in remained rate limited after five server-directed retries.');
}
export async function navigate(page: Page, label: string) {
  const menu = page.getByRole('button', { name: 'Menu', exact: true });
  if (await menu.isVisible()) await menu.click();
  await page
    .getByRole('navigation', { name: 'Workspace navigation' })
    .getByRole('link', { name: label, exact: true })
    .click();
}
export async function request<T = Record<string, unknown>>(
  page: Page,
  path: string,
  method = 'GET',
  body?: unknown,
): Promise<{ status: number; data: T }> {
  return page.evaluate(
    async ({ path, method, body }) => {
      const token = JSON.parse(sessionStorage.getItem('mcp-hub.session') || 'null')?.access_token;
      const response = await fetch(path, {
        method,
        headers: {
          Authorization: 'Bearer ' + token,
          ...(body === undefined
            ? {}
            : {
                'Content-Type': 'application/json',
                Accept: 'application/json, text/event-stream',
              }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      return {
        status: response.status,
        data: response.status === 204 ? null : await response.json(),
      };
    },
    { path, method, body },
  );
}
export async function tools(page: Page) {
  const result = await request<{ result: { tools: { name: string }[] } }>(page, '/mcp', 'POST', {
    jsonrpc: '2.0',
    id: crypto.randomUUID(),
    method: 'tools/list',
    params: {},
  });
  expect(result.status).toBe(200);
  return result.data.result.tools.map((t) => t.name);
}
export async function noHorizontalOverflow(page: Page) {
  expect(
    await page.evaluate(() => ({
      content: document.documentElement.scrollWidth,
      viewport: innerWidth,
    })),
  ).toEqual(expect.objectContaining({ viewport: expect.any(Number) }));
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
}
