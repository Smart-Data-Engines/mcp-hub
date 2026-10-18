export type Json = Record<string, unknown>;
export interface Principal {
  id: string;
  username: string;
  kind: 'human' | 'bot' | 'anonymous';
  client_id: string;
}
export interface Me {
  principal: Principal;
  admin: boolean;
  manager: boolean;
  group: string;
  permissions: Record<
    string,
    {
      group: string;
      group_caps: string[];
      personal_grant: string[] | null;
      personal_deny: boolean;
      owner: boolean;
      admin: boolean;
      effective_caps: string[];
      visibility?: string;
      visible?: boolean;
      available?: boolean;
    }
  >;
  runtime_enabled: boolean;
  source_editing_enabled: boolean;
  idp_provider: string;
  interaction_csrf: string | null;
}
export type PermissionSource = Me['permissions'][string];
export type Capability = 'read' | 'write' | 'destructive';
export interface AccessServer {
  name: string;
  description: string;
  owner: string;
  visibility: Server['visibility'];
  status: string;
  available: boolean;
  managed: boolean;
}
export interface AccessDirectory {
  users: (User & { admin: boolean; manager: boolean })[];
  groups: Record<string, Group>;
  servers: AccessServer[];
  members: Record<string, PermissionSource>;
}
export interface UserAccess {
  user: User;
  servers: Record<string, PermissionSource>;
}
export interface Server {
  name: string;
  owner: string;
  description: string;
  visibility: 'private' | 'shared' | 'public';
  shared_with: string[];
  autostart: boolean;
  status: string;
  code_version: string;
  pinned_ref: string;
  memory_mb: number;
  cpus: number;
  policy: string;
  idempotency: boolean;
  approval_required: boolean;
  approval_four_eyes: boolean;
  error: string;
}
export interface User extends Principal {
  group: string;
  grants: Record<string, string[]>;
  denies: string[];
}
export interface Group {
  servers: Record<string, string[]>;
  approval_required: boolean;
}
export interface Tool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

let refreshing: Promise<void> | null = null;
const TOKEN = 'mcp-hub.session';
export function session(): { access_token: string; refresh_token: string } | null {
  try {
    return JSON.parse(sessionStorage.getItem(TOKEN) || 'null');
  } catch {
    return null;
  }
}
function remember(tokens: unknown) {
  sessionStorage.setItem(TOKEN, JSON.stringify(tokens));
}
export function clearSession() {
  sessionStorage.removeItem(TOKEN);
}

export async function api<T = Json>(
  path: string,
  init: RequestInit = {},
  retry = true,
): Promise<T> {
  const headers = new Headers(init.headers);
  if (session()) headers.set('Authorization', `Bearer ${session()!.access_token}`);
  if (init.body) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, { ...init, headers, credentials: 'same-origin' });
  if (response.status === 401 && retry && session()?.refresh_token) {
    if (!refreshing)
      refreshing = (async () => {
        const refreshed = await fetch('/token', {
          method: 'POST',
          body: new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: session()!.refresh_token,
            client_id: 'mcp-hub-admin',
          }),
        });
        if (!refreshed.ok) {
          clearSession();
          throw new Error('Your session expired. Sign in again.');
        }
        remember(await refreshed.json());
      })().finally(() => {
        refreshing = null;
      });
    await refreshing;
    return api<T>(path, init, false);
  }
  if (!response.ok) {
    const data = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
    throw new Error(data.error_description || data.error || `HTTP ${response.status}`);
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}
export function send<T = Json>(
  path: string,
  data: unknown,
  method = 'POST',
  headers?: HeadersInit,
) {
  return api<T>(path, { method, body: JSON.stringify(data), headers });
}
export async function rpc<T>(method: string, params: unknown = {}): Promise<T> {
  const data = await send<{ result: T; error?: { message: string } }>(
    '/mcp',
    { jsonrpc: '2.0', id: crypto.randomUUID(), method, params },
    'POST',
    { Accept: 'application/json, text/event-stream' },
  );
  if (data.error) throw new Error(data.error.message);
  return data.result;
}
function b64(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
export async function login() {
  const verifier = b64(crypto.getRandomValues(new Uint8Array(48))),
    state = b64(crypto.getRandomValues(new Uint8Array(24)));
  const challenge = b64(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))),
  );
  sessionStorage.setItem(
    'mcp-hub.pkce',
    JSON.stringify({ verifier, state, returnTo: location.hash }),
  );
  location.assign(
    '/authorize?' +
      new URLSearchParams({
        response_type: 'code',
        client_id: 'mcp-hub-admin',
        redirect_uri: location.origin + '/admin/',
        scope: 'mcp',
        resource: location.origin + '/mcp',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state,
      }),
  );
}
export async function callback() {
  const params = new URLSearchParams(location.search);
  if (params.has('error')) {
    history.replaceState({}, '', location.pathname);
    throw new Error(
      params.get('error_description') || 'Company sign-in was declined. You can try again.',
    );
  }
  if (!params.has('code')) return;
  const stored = JSON.parse(sessionStorage.getItem('mcp-hub.pkce') || 'null') as {
    verifier: string;
    state: string;
    returnTo?: string;
  } | null;
  if (!stored || stored.state !== params.get('state'))
    throw new Error('Login state did not match. Start sign-in again.');
  history.replaceState(
    {},
    '',
    location.pathname + (stored.returnTo?.startsWith('#') ? stored.returnTo : ''),
  );
  window.dispatchEvent(new HashChangeEvent('hashchange'));
  sessionStorage.removeItem('mcp-hub.pkce');
  const response = await fetch('/token', {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: 'mcp-hub-admin',
      code: params.get('code')!,
      redirect_uri: location.origin + '/admin/',
      code_verifier: stored.verifier,
    }),
  });
  if (!response.ok) throw new Error('Sign-in could not be completed. Please try again.');
  remember(await response.json());
}
export async function logout() {
  const current = session();
  clearSession();
  if (current)
    await fetch('/oauth/revoke', {
      method: 'POST',
      body: new URLSearchParams({ client_id: 'mcp-hub-admin', token: current.refresh_token }),
    }).catch(() => undefined);
}
