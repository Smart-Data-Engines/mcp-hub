import React, { useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  api,
  send,
  login,
  logout,
  callback,
  session,
  type Me,
  type Server,
  type User,
} from './api';
import {
  Badge,
  Empty,
  Code,
  Field,
  Loading,
  Modal,
  ConfirmProvider,
  DraftProvider,
  useConfirm,
  useDraftGuard,
  useTask,
  useUnsavedChanges,
  FormError,
  type Run,
} from './ui';
import { ServerAccess, UsersAccess, GroupsEditor } from './access';
import { PersonalCredentials } from './credentials';
import { ServerSource } from './server-source';
import { ServerEnvironment } from './server-environment';
import { Overview } from './overview';
import { useRouter, href, type View, type Route, type Navigate } from './navigation';
import './style.css';

const ROOT = '/admin/api/servers-dynamic';
type Notice = { message: string; error: boolean };

function ServerDetail({
  server,
  me,
  run,
  onBack,
  onUpdate,
  route,
  navigate,
}: {
  server: Server;
  me: Me;
  run: Run;
  onBack: () => void;
  onUpdate: () => Promise<void>;
  route: Route;
  navigate: Navigate;
}) {
  const [sourceDirty, setSourceDirty] = useState(false),
    [environmentDirty, setEnvironmentDirty] = useState(false),
    [logs, setLogs] = useState<string>(),
    [config, setConfig] = useState(server),
    [busy, setBusy] = useState(false);
  const confirm = useConfirm(),
    task = useTask(run);
  const base = ROOT + '/' + encodeURIComponent(server.name),
    editable = me.admin || server.owner === me.principal.id;
  const tabs = [
    ...(me.admin || me.manager ? ['access'] : []),
    ...(editable ? ['source', 'settings', 'environment', 'logs'] : []),
  ];
  const tab = route.tab && tabs.includes(route.tab) ? route.tab : tabs[0];
  const settingsKeys = [
    'description',
    'autostart',
    'pinned_ref',
    'idempotency',
    'approval_required',
    'approval_four_eyes',
    ...(me.admin ? ['memory_mb', 'cpus'] : ['visibility', 'shared_with']),
  ] as (keyof Server)[];
  const settingsDirty = settingsKeys.some(
    (key) => JSON.stringify(config[key]) !== JSON.stringify(server[key]),
  );
  const hasDraft = sourceDirty || settingsDirty || environmentDirty;
  const markSaved = useUnsavedChanges(hasDraft);
  useEffect(() => {
    setConfig(server);
  }, [server]);
  useEffect(() => {
    if (!editable) return;
    if (tab === 'logs')
      void run(async () => setLogs((await api<{ logs: string }>(base + '/logs')).logs));
  }, [base, editable, run, tab]);
  const act = async (action: string): Promise<boolean> => {
    if (busy) return false;
    setBusy(true);
    try {
      if (
        action === 'stop' &&
        !(await confirm({
          title: `Stop ${server.name}?`,
          description:
            'Its tools will be unavailable to everyone until you start the server again.',
          confirmLabel: 'Stop server',
          danger: true,
        }))
      )
        return false;
      return await run(
        async () => {
          try {
            await send(base + '/' + action, {});
          } catch (error) {
            if (error instanceof Error && error.message.length > 300)
              throw new Error(
                'The server could not complete this operation. Open Logs for details.',
              );
            throw error;
          } finally {
            await onUpdate();
          }
        },
        action === 'start'
          ? 'Server started. Its tools will appear when connected.'
          : action === 'stop'
            ? 'Server stopped'
            : 'Server restarted with the latest saved source',
      );
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <button className="back" onClick={onBack}>
        ← All servers
      </button>
      <div className="page-title">
        <div>
          <h1>{server.name}</h1>
          <p>{server.description || 'Your MCP server'}</p>
        </div>
        <Badge value={server.status} />
      </div>
      {server.error && (
        <div className="server-error">
          <h2>This server needs attention</h2>
          <p>
            The last operation failed. Open Logs to check what happened, then correct the source or
            configuration and try again.
          </p>
          <button
            onClick={() => void navigate({ view: 'servers', item: server.name, tab: 'logs' })}
          >
            Open logs
          </button>
          <details>
            <summary>Technical details</summary>
            <Code value={server.error} />
          </details>
        </div>
      )}
      <div className="server-bar">
        <span>
          Code snapshot <code>{server.code_version.slice(0, 12) || 'not started'}</code>
        </span>
        <span>
          <Badge value={server.visibility} />
        </span>
        {editable && (
          <div className="actions">
            {(server.status === 'running' ? ['restart', 'stop'] : ['start']).map((action) => (
              <button
                key={action}
                disabled={
                  busy ||
                  task.busy ||
                  !me.runtime_enabled ||
                  server.status === 'starting' ||
                  server.status === 'stopping' ||
                  hasDraft
                }
                onClick={() => void act(action)}
              >
                {busy ? 'Working…' : action[0].toUpperCase() + action.slice(1)}
              </button>
            ))}
          </div>
        )}
      </div>
      {hasDraft && (
        <div className="callout">
          You have unsaved changes. Save them before starting or restarting this server.
        </div>
      )}
      {!me.runtime_enabled && (
        <div className="callout">
          Server hosting is not enabled in this workspace. Ask your workspace operator to enable it.
        </div>
      )}
      {server.status === 'stopped' && (
        <div className="callout">
          This server is stopped. Start it to make its permitted tools available.
        </div>
      )}
      <p className="hint">
        Start and Restart fetch fresh source from Git. Saving files does not change a running
        container.
      </p>
      {tabs.length ? (
        <>
          <nav className="tabs" aria-label="Server sections">
            {tabs.map((t) => (
              <a
                href={href({ view: 'servers', item: server.name, tab: t })}
                className={tab === t ? 'active' : ''}
                aria-current={tab === t ? 'page' : undefined}
                key={t}
                onClick={(e) => {
                  e.preventDefault();
                  void navigate({ view: 'servers', item: server.name, tab: t });
                }}
              >
                {t === 'environment' ? 'Connection' : t[0].toUpperCase() + t.slice(1)}
              </a>
            ))}
          </nav>
          {tab === 'access' && (
            <ServerAccess server={server} me={me} run={run} onUpdate={onUpdate} />
          )}
          {tab === 'source' && (
            <ServerSource
              key={server.name}
              server={server}
              me={me}
              run={run}
              onDirtyChange={setSourceDirty}
              onSaved={markSaved}
            />
          )}
          {tab === 'settings' && (
            <section>
              <h2>Server settings</h2>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const {
                    description,
                    visibility,
                    shared_with,
                    autostart,
                    pinned_ref,
                    idempotency,
                    approval_required,
                    approval_four_eyes,
                    memory_mb,
                    cpus,
                  } = config;
                  void task.execute(async () => {
                    await send(
                      base,
                      {
                        description,
                        ...(!me.admin ? { visibility, shared_with } : {}),
                        autostart,
                        pinned_ref,
                        idempotency,
                        approval_required,
                        approval_four_eyes,
                        ...(me.admin ? { memory_mb, cpus } : {}),
                      },
                      'PUT',
                    );
                    markSaved();
                    await onUpdate();
                  }, 'Settings saved');
                }}
              >
                <Field label="Description">
                  <input
                    value={config.description}
                    onChange={(e) => setConfig({ ...config, description: e.target.value })}
                  />
                </Field>
                <div className="form-grid">
                  {!me.admin && (
                    <Field
                      label="Server audience"
                      hint="Sharing limits who may receive access. An administrator still needs to assign tool permissions."
                    >
                      <select
                        value={config.visibility}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            visibility: e.target.value as Server['visibility'],
                          })
                        }
                      >
                        <option value="private">Private · owner and administrators</option>
                        <option value="shared">Selected people</option>
                        <option value="public">Organization · permissions required</option>
                      </select>
                    </Field>
                  )}
                  <Field label="Pinned tag or commit (optional)">
                    <input
                      value={config.pinned_ref}
                      onChange={(e) => setConfig({ ...config, pinned_ref: e.target.value })}
                    />
                  </Field>
                </div>
                {!me.admin && config.visibility === 'shared' && (
                  <details>
                    <summary>Advanced · shared account identifiers</summary>
                    <p>Ask an administrator to share with a person by name from the Access page.</p>
                    <Field label="Shared account identifiers (comma-separated)">
                      <input
                        value={config.shared_with.join(',')}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            shared_with: e.target.value
                              .split(',')
                              .map((v) => v.trim())
                              .filter(Boolean),
                          })
                        }
                      />
                    </Field>
                  </details>
                )}
                {me.admin && (
                  <div className="form-grid">
                    <Field label="Memory (MiB)">
                      <input
                        type="number"
                        min="64"
                        max="2048"
                        value={config.memory_mb}
                        onChange={(e) =>
                          setConfig({ ...config, memory_mb: Number(e.target.value) })
                        }
                      />
                    </Field>
                    <Field label="CPU cores">
                      <input
                        type="number"
                        min="0.1"
                        max="2"
                        step="0.1"
                        value={config.cpus}
                        onChange={(e) => setConfig({ ...config, cpus: Number(e.target.value) })}
                      />
                    </Field>
                  </div>
                )}
                {(
                  ['autostart', 'idempotency', 'approval_required', 'approval_four_eyes'] as const
                ).map((key) => (
                  <label key={key} className="check">
                    <input
                      type="checkbox"
                      checked={config[key]}
                      onChange={(e) => setConfig({ ...config, [key]: e.target.checked })}
                    />
                    {
                      (
                        {
                          autostart: 'Start automatically when the hub starts',
                          idempotency: 'Deduplicate identical write calls',
                          approval_required: 'Require human approval for destructive calls',
                          approval_four_eyes: 'Require a different human to approve',
                        } as const
                      )[key]
                    }
                  </label>
                ))}
                <div className="actions">
                  <button className="primary" disabled={task.busy || !settingsDirty}>
                    {task.busy ? 'Saving settings…' : 'Save settings'}
                  </button>
                  <button
                    type="button"
                    className="danger"
                    disabled={task.busy}
                    onClick={() => {
                      void (async () => {
                        if (
                          await confirm({
                            title: `Delete ${server.name}?`,
                            description:
                              'This stops the server and removes its source folder from the registry. Everyone will lose access to its tools.',
                            confirmLabel: 'Delete server',
                            danger: true,
                          })
                        )
                          await task.execute(async () => {
                            await api(base, { method: 'DELETE' });
                            markSaved();
                            await onUpdate();
                            onBack();
                          }, 'Server deleted');
                      })();
                    }}
                  >
                    Delete server
                  </button>
                </div>
                <FormError message={task.error} />
              </form>
            </section>
          )}
          {tab === 'environment' && (
            <ServerEnvironment
              key={server.name}
              server={server}
              me={me}
              run={run}
              navigate={navigate}
              onDirtyChange={setEnvironmentDirty}
              onSaved={markSaved}
              onUpdate={onUpdate}
              onRestart={() => act('restart')}
              busy={busy || server.status === 'starting' || server.status === 'stopping'}
            />
          )}
          {tab === 'logs' && (
            <section>
              <div className="section-title">
                <h2>Container logs</h2>
                <button
                  onClick={() =>
                    void run(async () =>
                      setLogs((await api<{ logs: string }>(base + '/logs')).logs),
                    )
                  }
                >
                  Refresh logs
                </button>
              </div>
              {logs === undefined ? (
                <Loading label="Loading server logs…" />
              ) : (
                <Code value={logs || 'No log output yet. Start the server to see its activity.'} />
              )}
            </section>
          )}
        </>
      ) : (
        <Empty title="Shared server">
          You can use this server's permitted tools. Its owner manages source, environment and
          lifecycle.
        </Empty>
      )}
    </>
  );
}

function Servers({
  me,
  run,
  route,
  navigate,
}: {
  me: Me;
  run: Run;
  route: Route;
  navigate: Navigate;
}) {
  const [servers, setServers] = useState<Server[]>(),
    [name, setName] = useState(''),
    [description, setDescription] = useState(''),
    [creating, setCreating] = useState(false),
    [search, setSearch] = useState(''),
    [filter, setFilter] = useState('all');
  const task = useTask(run),
    guard = useDraftGuard();
  const markSaved = useUnsavedChanges(creating && !!(name || description));
  const load = useCallback(
    async () => setServers((await api<{ servers: Server[] }>(ROOT)).servers),
    [],
  );
  useEffect(() => {
    void run(load);
  }, [load, run]);
  const selected = servers?.find((server) => server.name === route.item);
  if (selected)
    return (
      <ServerDetail
        key={selected.name + (route.tab || '')}
        server={selected}
        me={me}
        run={run}
        route={route}
        navigate={navigate}
        onBack={() => void navigate({ view: 'servers' })}
        onUpdate={load}
      />
    );
  if (route.item && servers)
    return (
      <>
        <button className="back" onClick={() => void navigate({ view: 'servers' })}>
          ← All servers
        </button>
        <Empty title="Server unavailable">
          It may have been removed, or your account may not be included in its audience.
        </Empty>
      </>
    );
  const filtered = servers?.filter(
    (s) =>
      `${s.name} ${s.description}`.toLowerCase().includes(search.toLowerCase()) &&
      (filter === 'all' ||
        (filter === 'mine' ? s.owner === me.principal.id : s.owner !== me.principal.id)),
  );
  const closeCreate = async () => {
    if (!task.busy && (await guard())) {
      markSaved();
      setCreating(false);
      setName('');
      setDescription('');
    }
  };
  return (
    <>
      <div className="eyebrow">WORKSPACE / SERVERS</div>
      <div className="page-title">
        <div>
          <h1>MCP servers</h1>
          <p>Manage your servers, share access, and see what is available to your account.</p>
        </div>
        <button
          className="primary"
          disabled={!me.runtime_enabled}
          onClick={() => setCreating(true)}
        >
          Create server
        </button>
      </div>
      {!me.runtime_enabled && (
        <div className="callout">
          Server hosting is not enabled in this workspace. Ask your workspace operator to enable it.
        </div>
      )}
      <section>
        <div className="section-title">
          <h2>
            Your servers <span className="count">{servers?.length ?? '…'}</span>
          </h2>
          <div className="catalog-filters">
            <Field label="Search servers">
              <input
                type="search"
                placeholder="Name or description…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </Field>
            <Field label="Show servers">
              <select value={filter} onChange={(e) => setFilter(e.target.value)}>
                <option value="all">All available servers</option>
                <option value="mine">Owned by me</option>
                <option value="shared">Owned by others</option>
              </select>
            </Field>
          </div>
        </div>
        {!servers ? (
          <>
            <Loading label="Loading servers…" />
            <button onClick={() => void run(load)}>Retry</button>
          </>
        ) : filtered?.length ? (
          filtered.map((server) => (
            <a
              className="server-row"
              key={server.name}
              href={href({ view: 'servers', item: server.name })}
              onClick={(e) => {
                e.preventDefault();
                void navigate({ view: 'servers', item: server.name });
              }}
            >
              <span className="server-symbol" aria-hidden="true">
                {server.name[0].toUpperCase()}
              </span>
              <span>
                <strong>{server.name}</strong>
                <small>
                  {server.description ||
                    (server.owner === me.principal.id ? 'Owned by you' : 'Workspace server')}
                </small>
              </span>
              <Badge value={server.status} />
              <Badge value={server.visibility} />
              <span aria-hidden="true">→</span>
            </a>
          ))
        ) : search || filter !== 'all' ? (
          <Empty title="No servers match these filters">
            <button
              onClick={() => {
                setSearch('');
                setFilter('all');
              }}
            >
              Clear filters
            </button>
          </Empty>
        ) : (
          <Empty title="Create your first MCP server">
            Start with a working example, then give your team access.
          </Empty>
        )}
      </section>
      {creating && (
        <Modal title="Create an MCP server" onClose={() => void closeCreate()}>
          <p>Start with a working Python example. Your new server is private until you share it.</p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void task.execute(async () => {
                const created = await send<Server>(ROOT, { name, description });
                await load();
                markSaved();
                setCreating(false);
                setName('');
                setDescription('');
                await navigate({ view: 'servers', item: created.name, tab: 'source' });
              }, 'Server created. Review the example, then Start to publish its tools.');
            }}
          >
            <Field
              label="Unique server name"
              hint="Lowercase letters, numbers, hyphens and underscores. This name identifies tools in AI clients."
            >
              <input
                required
                autoFocus
                pattern="[a-z0-9_-]{1,64}"
                maxLength={64}
                placeholder="customer-support"
                value={name}
                disabled={task.busy}
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <Field label="Description" hint="Help your team understand what this server provides.">
              <input
                maxLength={1000}
                value={description}
                disabled={task.busy}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Search support tickets and help articles"
              />
            </Field>
            <FormError message={task.error} />
            <div className="dialog-actions">
              <button type="button" disabled={task.busy} onClick={() => void closeCreate()}>
                Cancel
              </button>
              <button className="primary" disabled={task.busy}>
                {task.busy ? 'Creating server…' : 'Create private server'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

function Roles({ run }: { run: Run }) {
  const [roles, setRoles] = useState<{ admins: string[]; managers: string[]; managed?: boolean }>({
      admins: [],
      managers: [],
    }),
    [users, setUsers] = useState<User[]>([]),
    [user, setUser] = useState('');
  const load = useCallback(async () => {
    const [r, u] = await Promise.all([
      api<typeof roles>('/admin/api/admins'),
      api<{ users: User[] }>('/admin/api/users'),
    ]);
    setRoles(r);
    setUsers(u.users);
  }, []);
  useEffect(() => {
    void run(load);
  }, [load, run]);
  return (
    <>
      <div className="eyebrow">ADMINISTRATION / ROLES</div>
      <h1>Administrators & managers</h1>
      <p>
        Managers may manage other users' access. They cannot promote themselves or manage
        administrators.
      </p>
      <section>
        {roles.managed && (
          <div className="callout">
            Administrators are set by workspace deployment policy. Only verified accounts on that
            list can become administrators.
          </div>
        )}
        <Field label="Principal">
          <select value={user} onChange={(e) => setUser(e.target.value)}>
            <option value="">Choose a signed-in principal…</option>
            {users.map((u) => (
              <option key={u.id} value={u.id}>
                {u.username}
              </option>
            ))}
          </select>
        </Field>
        <div className="actions">
          {['admins', 'managers'].map((r) => (
            <button
              disabled={!user || (r === 'admins' && roles.managed)}
              key={r}
              onClick={() =>
                void run(async () => {
                  await send('/admin/api/' + r + '/' + encodeURIComponent(user), {});
                  await load();
                }, 'Role granted')
              }
            >
              Grant {r === 'admins' ? 'administrator' : 'manager'}
            </button>
          ))}
        </div>
      </section>
      <div className="split">
        {(['admins', 'managers'] as const).map((r) => (
          <section key={r}>
            <h2>{r === 'admins' ? 'Administrators' : 'Managers'}</h2>
            {roles[r].map((id) => (
              <div className="row" key={id}>
                <strong>{users.find((u) => u.id === id)?.username || id}</strong>
                <button
                  className="danger subtle"
                  disabled={r === 'admins' && (roles.managed || roles.admins.length === 1)}
                  onClick={() =>
                    void run(async () => {
                      await api('/admin/api/' + r + '/' + encodeURIComponent(id), {
                        method: 'DELETE',
                      });
                      await load();
                    }, 'Role removed')
                  }
                >
                  Remove
                </button>
              </div>
            ))}
          </section>
        ))}
      </div>
    </>
  );
}

function Clients({ run }: { run: Run }) {
  const [management, setManagement] = useState(false);
  const [clients, setClients] = useState<User[]>([]),
    [name, setName] = useState(''),
    [issued, setIssued] = useState<Record<string, unknown>>();
  const load = useCallback(
    async () => setClients((await api<{ clients: User[] }>('/admin/api/clients')).clients),
    [],
  );
  useEffect(() => {
    void run(load);
  }, [load, run]);
  return (
    <>
      <div className="eyebrow">ADMINISTRATION / AUTOMATION</div>
      <h1>Service clients</h1>
      <p>
        Bots use client credentials and start with zero tool permissions. Grant access explicitly in
        Users.
      </p>
      <div className="split">
        <section>
          {clients.length ? (
            clients.map((client) => (
              <div className="row" key={client.id}>
                <div>
                  <strong>{client.username}</strong>
                  <small>{client.id}</small>
                </div>
                <Badge value="bot" />
              </div>
            ))
          ) : (
            <Empty title="No service clients">
              Create a separate identity for each automation.
            </Empty>
          )}
        </section>
        <section>
          <h2>Create a service client</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                setIssued(
                  await send('/admin/api/clients', {
                    client_name: name,
                    management_allowed: management,
                  }),
                );
                setName('');
                await load();
              }, 'Client created. Save its secret now.');
            }}
          >
            <Field label="Client name">
              <input
                required
                maxLength={128}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Build pipeline"
              />
            </Field>
            <label className="check">
              <input
                type="checkbox"
                checked={management}
                onChange={(e) => setManagement(e.target.checked)}
              />
              Allow management API access (roles still apply)
            </label>
            <button className="primary">Create client</button>
          </form>
          {issued && (
            <div className="issued">
              <h3>Client secret — shown once</h3>
              <Code value={issued} />
              <button onClick={() => setIssued(undefined)}>Dismiss secret</button>
            </div>
          )}
        </section>
      </div>
    </>
  );
}

function Approvals({ me, run }: { me: Me; run: Run }) {
  interface Approval {
    id: string;
    tool: string;
    status: string;
    principal: { username: string; client_id?: string };
    arguments_summary: unknown;
    four_eyes: boolean;
    execution_summary?: { credentials_source: string; code_version: string };
  }
  const [items, setItems] = useState<Approval[]>([]);
  const load = useCallback(
    async () => setItems((await api<{ approvals: Approval[] }>('/admin/api/approvals')).approvals),
    [],
  );
  useEffect(() => {
    void run(load);
  }, [load, run]);
  return (
    <>
      <div className="eyebrow">WORKSPACE / HUMAN REVIEW</div>
      <div className="page-title">
        <div>
          <h1>Approvals</h1>
          <p>Review the caller, tool and arguments before authorizing a destructive action.</p>
        </div>
        <button onClick={() => void run(load)}>Refresh</button>
      </div>
      {!me.interaction_csrf && (
        <div className="notice">Sign in using this console to enable interactive approvals.</div>
      )}
      {items.length ? (
        items.map((item) => (
          <section key={item.id}>
            <div className="section-title">
              <h2>{item.tool}</h2>
              <Badge value={item.status} />
            </div>
            <p>
              Requested by {item.principal.username}
              {item.four_eyes ? ' · a different human must approve' : ''}
            </p>
            {item.execution_summary && (
              <p className="muted">
                Connection:{' '}
                {item.execution_summary.credentials_source === 'session_metadata'
                  ? 'credentials supplied with this request'
                  : item.execution_summary.credentials_source === 'store'
                    ? 'saved personal credentials'
                    : 'server connection'}
                {' · '}Revision: {item.execution_summary.code_version || 'not declared'}
                {item.principal.client_id && <> · Client: {item.principal.client_id}</>}
              </p>
            )}
            <Code value={item.arguments_summary} />
            <small className="muted">{item.id}</small>
            {item.status === 'pending' && (
              <div className="actions">
                {['approve', 'reject'].map((decision) => (
                  <button
                    key={decision}
                    className={decision === 'approve' ? 'primary' : 'danger'}
                    disabled={!me.interaction_csrf}
                    onClick={() =>
                      void run(async () => {
                        await send('/admin/api/approvals/' + item.id, { decision }, 'POST', {
                          'X-Hub-Interactive': me.interaction_csrf!,
                        });
                        await load();
                      }, 'Review recorded. The caller may retry the same request.')
                    }
                  >
                    {decision === 'approve' ? 'Approve action' : 'Reject'}
                  </button>
                ))}
              </div>
            )}
          </section>
        ))
      ) : (
        <Empty title="No actions awaiting review">
          Destructive calls that require human approval will appear here.
        </Empty>
      )}
    </>
  );
}

function Audit({ run }: { run: Run }) {
  const [data, setData] = useState<{
    pending_events: unknown[];
    pending_count: number;
    dropped: number;
  }>();
  const load = useCallback(() => run(async () => setData(await api('/admin/api/audit'))), [run]);
  useEffect(() => {
    void load();
  }, [load]);
  return (
    <>
      <div className="eyebrow">ADMINISTRATION / TRACEABILITY</div>
      <div className="page-title">
        <div>
          <h1>Audit outbox</h1>
          <p>Calls are buffered durably and delivered to the configured audit sink.</p>
        </div>
        <button onClick={() => void load()}>Refresh</button>
      </div>
      <div className="stats">
        <article>
          <span>PENDING DELIVERY</span>
          <strong>{data?.pending_count ?? '—'}</strong>
        </article>
        <article>
          <span>DROPPED EVENTS</span>
          <strong>{data?.dropped ?? '—'}</strong>
          <small>Investigate any non-zero value</small>
        </article>
      </div>
      <section>
        <h2>Recent pending events</h2>
        {data?.pending_events.length ? (
          data.pending_events.map((event, index) => (
            <details key={index}>
              <summary>
                Event {index + 1} · {(event as { request_id: string }).request_id}
              </summary>
              <Code value={event} />
            </details>
          ))
        ) : (
          <Empty title="Outbox is empty">Delivered events are available in your audit sink.</Empty>
        )}
      </section>
    </>
  );
}

let bootstrap: Promise<Me | undefined> | undefined;
function App() {
  const { route, navigate } = useRouter();
  const view = route.view;
  const guard = useDraftGuard();
  const noticeTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const [menuOpen, setMenuOpen] = useState(false);
  useEffect(() => setMenuOpen(false), [route]);
  const [me, setMe] = useState<Me>(),
    [loading, setLoading] = useState(true),
    [notice, setNotice] = useState<Notice>(),
    [pending, setPending] = useState(0);
  const run = useCallback<Run>(async (work, success) => {
    setPending((n) => n + 1);
    try {
      await work();
      setNotice((old) => (old?.error ? undefined : old));
      if (success) {
        setNotice({ message: success, error: false });
        clearTimeout(noticeTimer.current);
        noticeTimer.current = setTimeout(() => setNotice(undefined), 7000);
      }
      return true;
    } catch (error) {
      clearTimeout(noticeTimer.current);
      setNotice({
        message: error instanceof Error ? error.message : 'Operation failed',
        error: true,
      });
      return false;
    } finally {
      setPending((n) => n - 1);
    }
  }, []);
  useEffect(() => () => clearTimeout(noticeTimer.current), []);
  useEffect(() => {
    if (loading) return;
    const heading = document.querySelector<HTMLElement>('#workspace-content h1');
    if (heading) {
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    }
  }, [route, loading]);
  useEffect(() => {
    bootstrap ??= (async () => {
      await callback();
      return session() ? await api<Me>('/admin/api/whoami') : undefined;
    })();
    void run(async () => setMe(await bootstrap)).finally(() => setLoading(false));
  }, [run]);
  const nav: [View, string, string][] = [
    ['overview', 'Overview', '◈'],
    ['servers', 'MCP servers', '◇'],
    ['credentials', 'My credentials', '⌘'],
    ['approvals', 'Approvals', '✓'],
    ...(me?.admin || me?.manager
      ? [['users', 'Users & access', '◎'] as [View, string, string]]
      : []),
    ...(me?.admin
      ? ([
          ['groups', 'Groups', '▦'],
          ['roles', 'Workspace roles', '♧'],
          ['clients', 'Service clients', '↗'],
          ['audit', 'Audit outbox', '≡'],
        ] as [View, string, string][])
      : []),
  ];
  if (loading)
    return (
      <div className="splash">
        <div className="brand">◈ MCP HUB</div>
        <p>Connecting to your workspace…</p>
      </div>
    );
  if (!me)
    return (
      <div className="login">
        <div className="login-inner">
          <div className="brand">◈ MCP HUB</div>
          <div className="eyebrow">YOUR ORGANIZATION'S TOOL LAYER</div>
          <h1>
            Every tool.
            <br />
            One trusted connection.
          </h1>
          <p>
            Connect your AI workspace to the services you use, with access managed by your
            organization.
          </p>
          {notice && (
            <div role="alert" className="notice error">
              {notice.message}
            </div>
          )}
          <button className="primary" onClick={() => void run(login)}>
            Continue with company sign-in <span>→</span>
          </button>
          <small>Uses your configured identity provider. No separate password.</small>
        </div>
        <div className="login-art" aria-hidden="true">
          <div className="orbit one" />
          <div className="orbit two" />
          <div className="orbit three" />
          <div className="hub-node">◈</div>
          <span className="node a">TOOLS</span>
          <span className="node b">IDENTITY</span>
          <span className="node c">SERVICES</span>
        </div>
      </div>
    );
  return (
    <div className="shell">
      <a
        className="skip-link"
        href="#workspace-content"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById('workspace-content')?.focus();
        }}
      >
        Skip to content
      </a>
      <aside>
        <a
          className="brand"
          href={href({ view: 'overview' })}
          onClick={(e) => {
            e.preventDefault();
            void navigate({ view: 'overview' });
          }}
        >
          ◈{' '}
          <span>
            MCP HUB<small>WORKSPACE CONSOLE</small>
          </span>
        </a>
        <button
          className="mobile-menu-toggle"
          aria-expanded={menuOpen}
          aria-controls="workspace-navigation"
          onClick={() => setMenuOpen((open) => !open)}
        >
          {menuOpen ? 'Close menu' : 'Menu'} <span aria-hidden="true">{menuOpen ? '×' : '☰'}</span>
        </button>
        <div className="nav-label">WORKSPACE</div>
        <nav
          id="workspace-navigation"
          className={`workspace-nav ${menuOpen ? 'open' : ''}`}
          aria-label="Workspace navigation"
        >
          {nav.map(([key, label, icon]) => (
            <React.Fragment key={key}>
              {key === 'users' && <div className="nav-label">ADMINISTRATION</div>}
              <a
                href={href({ view: key })}
                className={view === key ? 'active' : ''}
                aria-current={view === key ? 'page' : undefined}
                onClick={(e) => {
                  e.preventDefault();
                  void navigate({ view: key });
                }}
              >
                <span aria-hidden="true">{icon}</span>
                {label}
              </a>
            </React.Fragment>
          ))}
        </nav>
        <div className="identity">
          <span className="avatar">{me.principal.username[0].toUpperCase()}</span>
          <div>
            <strong title={me.principal.username}>{me.principal.username}</strong>
            <small>{me.admin ? 'Administrator' : me.manager ? 'Manager' : me.group}</small>
          </div>
          <button
            title="Sign out"
            aria-label="Sign out"
            onClick={() => {
              void (async () => {
                if (await guard())
                  await run(async () => {
                    await logout();
                    setMe(undefined);
                  });
              })();
            }}
          >
            ↪
          </button>
        </div>
      </aside>
      <main>
        <header>
          <span>
            Organization workspace <span className="slash">/</span>{' '}
            {nav.find(([key]) => key === view)?.[1]}
          </span>
          <span className="connection">
            <i />
            {pending ? 'Working…' : notice?.error ? 'Action needs attention' : 'Workspace ready'}
          </span>
        </header>
        {notice && (
          <div
            role={notice.error ? 'alert' : 'status'}
            className={`notice floating ${notice.error ? 'error' : 'success'}`}
          >
            <span>{notice.message}</span>
            <button aria-label="Dismiss notification" onClick={() => setNotice(undefined)}>
              ×
            </button>
          </div>
        )}
        <div className="content" id="workspace-content" tabIndex={-1}>
          {!nav.some(([key]) => key === view) ? (
            <Empty title="This page needs a different role">
              Ask a workspace administrator for help, or{' '}
              <a
                className="text-link"
                href={href({ view: 'overview' })}
                onClick={(e) => {
                  e.preventDefault();
                  void navigate({ view: 'overview' });
                }}
              >
                return to your tools
              </a>
              .
            </Empty>
          ) : view === 'overview' ? (
            <Overview run={run} navigate={navigate} />
          ) : view === 'credentials' ? (
            <PersonalCredentials run={run} initialService={route.item} />
          ) : view === 'servers' ? (
            <Servers me={me} run={run} route={route} navigate={navigate} />
          ) : view === 'users' ? (
            <UsersAccess me={me} run={run} route={route} navigate={navigate} />
          ) : view === 'groups' ? (
            <GroupsEditor run={run} route={route} navigate={navigate} />
          ) : view === 'roles' ? (
            <Roles run={run} />
          ) : view === 'clients' ? (
            <Clients run={run} />
          ) : view === 'approvals' ? (
            <Approvals me={me} run={run} />
          ) : (
            <Audit run={run} />
          )}
        </div>
        <footer>
          MCP Hub <span>Identity-aware tools. Explicit permissions.</span>
        </footer>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfirmProvider>
      <DraftProvider>
        <App />
      </DraftProvider>
    </ConfirmProvider>
  </React.StrictMode>,
);
