import { useCallback, useEffect, useState } from 'react';
import { api, rpc, type Me, type Tool } from './api';
import { Badge, Code, CopyButton, Empty, Field, Loading, type Run } from './ui';
import { AccessExplanation } from './access';
import { href, type Navigate } from './navigation';

export function Overview({ run, navigate }: { run: Run; navigate: Navigate }) {
  const [access, setAccess] = useState<Me>(),
    [tools, setTools] = useState<Tool[]>([]),
    [search, setSearch] = useState(''),
    [server, setServer] = useState(''),
    [loading, setLoading] = useState(true);
  const reload = useCallback(async () => {
    setLoading(true);
    await run(async () => {
      const [catalog, me] = await Promise.all([
        rpc<{ tools: Tool[] }>('tools/list'),
        api<Me>('/admin/api/whoami'),
      ]);
      setTools(catalog.tools);
      setAccess(me);
    });
    setLoading(false);
  }, [run]);
  useEffect(() => {
    void reload();
  }, [reload]);
  const endpoint = location.origin + '/mcp',
    actualTools = tools.filter((t) => !t.name.startsWith('hub.')),
    servers = [...new Set(actualTools.map((t) => t.name.split('.')[0]))].sort();
  const filtered = tools.filter(
    (t) =>
      (!server || t.name.startsWith(server + '.')) &&
      `${t.name} ${t.description || ''}`.toLowerCase().includes(search.toLowerCase()),
  );
  return (
    <>
      <div className="eyebrow">WORKSPACE / OVERVIEW</div>
      <div className="page-title">
        <div>
          <h1>One place for your tools.</h1>
          <p>Connect your AI client, then use the tools available to your account.</p>
        </div>
        <button disabled={loading} onClick={() => void reload()}>
          {loading ? 'Refreshing…' : 'Refresh catalog'}
        </button>
      </div>
      <section className="connect-card">
        <div>
          <span className="eyebrow">START HERE</span>
          <h2>Connect your AI client</h2>
          <p>One MCP endpoint for all your permitted servers.</p>
          <div className="endpoint">
            <code>{endpoint}</code>
            <CopyButton value={endpoint} />
          </div>
          <details>
            <summary>How do I connect?</summary>
            <ol className="setup-steps">
              <li>Open the MCP server settings in your IDE or AI client.</li>
              <li>Add a remote server using the endpoint above.</li>
              <li>
                Sign in with your company account and allow access. Your permitted tools appear
                automatically.
              </li>
            </ol>
            <p className="hint">
              After an administrator changes your access, refresh the client’s tool list or
              reconnect.
            </p>
          </details>
        </div>
        {access?.admin || access?.manager ? (
          <div className="next-action">
            <span className="step-marker" aria-hidden="true">
              ◎
            </span>
            <h3>Set up your team</h3>
            <p>Choose who can use each server and what they can do.</p>
            <a
              className="button-link"
              href={href({ view: 'users' })}
              onClick={(e) => {
                e.preventDefault();
                void navigate({ view: 'users' });
              }}
            >
              Manage people & access →
            </a>
          </div>
        ) : (
          <div className="next-action">
            <h3>Need another tool?</h3>
            <p>Ask an administrator to give your account access to its server.</p>
            <a
              className="button-link"
              href={href({ view: 'credentials' })}
              onClick={(e) => {
                e.preventDefault();
                void navigate({ view: 'credentials' });
              }}
            >
              Manage personal connections →
            </a>
          </div>
        )}
      </section>
      <div className="stats">
        <article>
          <span>TOOLS YOU CAN USE</span>
          <strong>{access ? actualTools.length : '—'}</strong>
          <small>Based on your current permissions</small>
        </article>
        <article>
          <span>SERVERS AVAILABLE</span>
          <strong>{access ? servers.length : '—'}</strong>
          <small>Connected and accessible to you</small>
        </article>
        <article>
          <span>YOUR ACCESS</span>
          <strong className="text-stat">
            {access
              ? access.admin
                ? 'Administrator'
                : access.manager
                  ? 'Manager'
                  : access.group
              : '—'}
          </strong>
          <small>
            {access?.admin
              ? 'All servers and administration'
              : `Permission group: ${access?.group || '…'}`}
          </small>
        </article>
      </div>
      <section>
        <div className="section-title">
          <div>
            <h2>Your tool catalog</h2>
            <small className="muted" role="status">
              {access
                ? `${filtered.length} ${filtered.length === 1 ? 'tool' : 'tools'} shown`
                : 'Loading your catalog'}
            </small>
          </div>
          <div className="catalog-filters">
            <Field label="Search tools">
              <input
                type="search"
                placeholder="Name or description…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </Field>
            <Field label="Filter by server">
              <select value={server} onChange={(e) => setServer(e.target.value)}>
                <option value="">All servers</option>
                {servers.map((name) => (
                  <option key={name}>{name}</option>
                ))}
              </select>
            </Field>
          </div>
        </div>
        {loading && !access ? (
          <Loading label="Loading your tools…" />
        ) : !access ? (
          <Empty title="Your catalog could not be loaded">
            <button onClick={() => void reload()}>Try again</button>
          </Empty>
        ) : filtered.length ? (
          <div className="tool-list">
            {filtered.map((tool) => (
              <details key={tool.name}>
                <summary>
                  <span className="tool-icon" aria-hidden="true">
                    ↗
                  </span>
                  <div>
                    <strong>{tool.name}</strong>
                    <p>{tool.description}</p>
                  </div>
                  {tool.name.startsWith('hub.') && <Badge value="hub" label="Hub utility" />}
                  <span className="muted">Details ↓</span>
                </summary>
                <h3>Tool input schema</h3>
                <Code value={tool.inputSchema} />
              </details>
            ))}
          </div>
        ) : search || server ? (
          <Empty title="No tools match these filters">
            <button
              onClick={() => {
                setSearch('');
                setServer('');
              }}
            >
              Clear filters
            </button>
          </Empty>
        ) : (
          <Empty title="No tools available yet">
            Ask an administrator for server access, or create your own server.
          </Empty>
        )}
      </section>
      {access && (
        <section>
          <details>
            <summary>Why do I have this access? · {access.group}</summary>
            <p>
              Your effective permissions include your group, personal rules and server audience.
            </p>
            {Object.entries(access.permissions).map(([name, source]) => (
              <div className="access-server-row" key={name}>
                <div>
                  <strong>{name}</strong>
                  <AccessExplanation source={source} />
                </div>
              </div>
            ))}
            {!Object.keys(access.permissions).length && (
              <p>No server permissions have been assigned to your account yet.</p>
            )}
          </details>
        </section>
      )}
    </>
  );
}
