import { useCallback, useEffect, useRef, useState } from 'react';
import {
  api,
  send,
  type AccessDirectory,
  type AccessServer,
  type Capability,
  type Me,
  type PermissionSource,
  type Server,
  type UserAccess,
} from './api';
import {
  Badge,
  Empty,
  Field,
  FormError,
  Loading,
  useConfirm,
  useDraftGuard,
  useTask,
  useUnsavedChanges,
  type Run,
} from './ui';
import { href, type Navigate, type Route } from './navigation';

export const capabilityLabels: Record<Capability, string> = {
  read: 'Read',
  write: 'Create & update',
  destructive: 'Delete & destructive',
};
const capabilities: Capability[] = ['read', 'write', 'destructive'];
const help: Record<Capability, string> = {
  read: 'Search, list and view information.',
  write: 'Create records and change existing data.',
  destructive: 'Delete data or perform destructive actions.',
};
export function PermissionBadges({ caps }: { caps: string[] }) {
  return (
    <div className="permission-badges">
      {caps.length ? (
        capabilities
          .filter((cap) => caps.includes(cap))
          .map((cap) => <Badge key={cap} value={cap} label={capabilityLabels[cap]} />)
      ) : (
        <span className="muted">No access</span>
      )}
    </div>
  );
}
export function CapabilityPicker({
  value,
  onChange,
  disabled = false,
  label = 'Permissions',
}: {
  value: string[];
  onChange: (value: string[]) => void;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <fieldset className="capability-picker" disabled={disabled}>
      <legend>{label}</legend>
      {capabilities.map((cap) => (
        <label className={`capability-option ${value.includes(cap) ? 'selected' : ''}`} key={cap}>
          <input
            type="checkbox"
            checked={value.includes(cap)}
            onChange={(e) =>
              onChange(e.target.checked ? [...value, cap] : value.filter((v) => v !== cap))
            }
          />
          <span>
            <strong>{capabilityLabels[cap]}</strong>
            <small>{help[cap]}</small>
          </span>
        </label>
      ))}
    </fieldset>
  );
}
export function accessReason(source: PermissionSource) {
  if (source.admin) return 'Full access through the administrator role.';
  if (source.owner) return 'Full access as the server owner.';
  if (source.visible === false) return 'The server has not been shared with this person.';
  if (source.personal_deny && source.personal_grant === null)
    return 'Blocked for this person, including group access.';
  if (source.effective_caps.length)
    return source.personal_grant !== null
      ? `Personal permissions, combined with group “${source.group}”.`
      : `Access through group “${source.group}”.`;
  return `No permissions assigned personally or through group “${source.group}”.`;
}
export function AccessExplanation({ source }: { source: PermissionSource }) {
  return (
    <div className="access-explanation">
      <PermissionBadges caps={source.effective_caps} />
      <p>{accessReason(source)}</p>
      {source.available === false && source.effective_caps.length > 0 && (
        <p className="warning-text">
          Access is configured. Tools will be available when the server is connected.
        </p>
      )}
    </div>
  );
}

type Person = AccessDirectory['users'][number];
function PermissionEditor({
  person,
  server,
  source,
  me,
  run,
  onSaved,
}: {
  person: Person;
  server: AccessServer;
  source: PermissionSource;
  me: Me;
  run: Run;
  onSaved: () => Promise<void>;
}) {
  const initial =
    source.personal_grant !== null ? 'grant' : source.personal_deny ? 'block' : 'inherit';
  const [mode, setMode] = useState(source.effective_caps.length ? initial : 'grant'),
    [caps, setCaps] = useState<string[]>(
      source.personal_grant?.length ? source.personal_grant : ['read'],
    ),
    [touched, setTouched] = useState(false);
  const task = useTask(run);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus({ preventScroll: false });
  }, [person.id, server.name]);
  const dirty =
    mode !== initial ||
    (mode === 'grant' &&
      JSON.stringify([...caps].sort()) !==
        JSON.stringify([...(source.personal_grant || [])].sort()));
  useUnsavedChanges(touched && dirty);
  const automatic = source.admin || source.owner,
    locked = automatic || (!me.admin && person.id === me.principal.id);
  const inherited = source.group_caps || [];
  const preview =
    mode === 'block' ? [] : [...new Set([...inherited, ...(mode === 'grant' ? caps : [])])];
  return (
    <div className="access-editor" aria-label={`Access for ${person.username}`}>
      <div className="section-title">
        <div>
          <span className="eyebrow">PERSONAL ACCESS</span>
          <h2 ref={heading} tabIndex={-1}>
            {person.username}
          </h2>
        </div>
        <Badge
          value={person.kind}
          label={person.admin ? 'Administrator' : person.kind === 'human' ? 'Person' : undefined}
        />
      </div>
      <p>
        Server <strong>{server.name}</strong> · group <strong>{person.group}</strong>
      </p>
      <AccessExplanation source={source} />
      {locked ? (
        <div className="callout">
          {automatic
            ? 'This access comes from ownership or an administrator role. Personal rules cannot restrict it.'
            : 'Managers cannot change their own access. Ask an administrator.'}
        </div>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void task.execute(async () => {
              await send(
                `/admin/api/users/${encodeURIComponent(person.id)}/access/${encodeURIComponent(server.name)}`,
                { mode, caps: mode === 'grant' ? caps : [] },
                'PUT',
              );
              await onSaved();
            }, `Access updated for ${person.username}. Changes apply to the next tool request.`);
          }}
        >
          <fieldset className="access-modes" disabled={task.busy}>
            <legend>How should this person get access?</legend>
            {[
              [
                'inherit',
                'Use group permissions',
                inherited.length
                  ? `Follow group “${person.group}”.`
                  : `Group “${person.group}” has no access to this server.`,
              ],
              [
                'grant',
                'Add personal permissions',
                'Give this person access without changing their group.',
              ],
              [
                'block',
                'Block access',
                'Remove personal permissions and block group access to this server.',
              ],
            ].map(([value, label, description]) => (
              <label className={`mode-option ${mode === value ? 'selected' : ''}`} key={value}>
                <input
                  type="radio"
                  name={`mode-${person.id}-${server.name}`}
                  value={value}
                  checked={mode === value}
                  onChange={() => {
                    setMode(value);
                    setTouched(true);
                  }}
                />
                <span>
                  <strong>{label}</strong>
                  <small>{description}</small>
                </span>
              </label>
            ))}
          </fieldset>
          {mode === 'grant' && (
            <CapabilityPicker
              value={caps}
              onChange={(value) => {
                setCaps(value);
                setTouched(true);
              }}
              disabled={task.busy}
            />
          )}
          <div className="access-preview">
            <strong>After saving</strong>
            <PermissionBadges caps={preview} />
            {mode === 'grant' && inherited.some((cap) => !caps.includes(cap)) && (
              <p>Group permissions are included. To remove all access, choose Block access.</p>
            )}
            {source.visible === false && preview.length > 0 && (
              <p>
                {me.admin
                  ? 'The server will also be shared with this person. Other people keep their current access.'
                  : 'An administrator must share this restricted server first.'}
              </p>
            )}
            {mode === 'block' && (
              <p>This person will no longer be able to list or call this server’s tools.</p>
            )}
          </div>
          <FormError message={task.error} />
          <button
            className="primary"
            disabled={
              task.busy ||
              (mode === 'grant' && !caps.length) ||
              (!dirty && source.visible !== false)
            }
          >
            {task.busy ? 'Saving access…' : 'Save access'}
          </button>
        </form>
      )}
    </div>
  );
}

export function ServerAccess({
  server,
  me,
  run,
  onUpdate,
}: {
  server: Server;
  me: Me;
  run: Run;
  onUpdate: () => Promise<void>;
}) {
  const [data, setData] = useState<AccessDirectory>(),
    [search, setSearch] = useState(''),
    [selected, setSelected] = useState(''),
    [audience, setAudience] = useState(server.visibility);
  const task = useTask(run),
    confirm = useConfirm(),
    draftGuard = useDraftGuard();
  const load = useCallback(async () => {
    const result = await api<AccessDirectory>(
      '/admin/api/access?server=' + encodeURIComponent(server.name),
    );
    setData(result);
  }, [server.name]);
  useEffect(() => {
    void run(load);
  }, [load, run]);
  useEffect(() => setAudience(server.visibility), [server.visibility]);
  useUnsavedChanges(audience !== server.visibility);
  if (!data)
    return (
      <>
        <Loading label="Loading people and permissions…" />
        <button onClick={() => void run(load)}>Retry</button>
      </>
    );
  const person = data.users.find((u) => u.id === selected),
    info = data.servers.find((s) => s.name === server.name)!;
  const people = data.users.filter((u) =>
    `${u.username} ${u.group}`.toLowerCase().includes(search.toLowerCase()),
  );
  const count = Object.values(data.members).filter((s) => s.effective_caps.length).length;
  return (
    <>
      <section className="audience-panel">
        <div>
          <h2>Who can use this server?</h2>
          <p>Choose a person below and save their permissions. Sharing is handled for you.</p>
        </div>
        <div className="audience-summary">
          <Badge value={server.visibility} />
          <span>
            {count} {count === 1 ? 'account has' : 'accounts have'} access
          </span>
        </div>
      </section>
      <div className="access-layout">
        <section>
          <div className="section-title">
            <h2>People & service clients</h2>
            <span className="muted">{data.users.length}</span>
          </div>
          <Field label="Find a person" hint="People appear after their first company sign-in.">
            <input
              type="search"
              placeholder="Search by name or group…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </Field>
          <div className="people-list">
            {people.map((user) => {
              const source = data.members[user.id];
              return (
                <button
                  key={user.id}
                  className={`person-row ${selected === user.id ? 'selected' : ''}`}
                  aria-pressed={selected === user.id}
                  onClick={async () => {
                    if (selected === user.id) return;
                    if (await confirmDraft()) setSelected(user.id);
                  }}
                >
                  <span className="avatar" aria-hidden="true">
                    {user.username[0]?.toUpperCase() || '?'}
                  </span>
                  <span>
                    <strong>{user.username}</strong>
                    <small>
                      {source.admin ? 'Administrator' : source.owner ? 'Server owner' : user.group}
                    </small>
                    <PermissionBadges caps={source.effective_caps} />
                    {source.visible === false &&
                      (source.personal_grant?.length || source.group_caps.length) > 0 && (
                        <small className="warning-text">Not shared with this person</small>
                      )}
                  </span>
                  <span aria-hidden="true">→</span>
                </button>
              );
            })}
          </div>
          {!people.length && (
            <Empty title="No people match your search">
              <button onClick={() => setSearch('')}>Clear search</button>
            </Empty>
          )}
        </section>
        <section>
          {person && info ? (
            <PermissionEditor
              key={person.id + JSON.stringify(data.members[person.id])}
              person={person}
              server={info}
              source={data.members[person.id]}
              me={me}
              run={run}
              onSaved={async () => {
                await load();
                await onUpdate();
              }}
            />
          ) : (
            <Empty title="Choose a person to give access">
              Select an account to see what they can do and change their access.
            </Empty>
          )}
        </section>
      </div>
      {me.admin && (
        <section>
          <details>
            <summary>Advanced · server audience</summary>
            <p>
              Audience limits who can receive tool access. Organization audience still requires
              group or personal permissions.
            </p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void (async () => {
                  if (
                    audience === 'private' &&
                    !(await confirm({
                      title: 'Restrict this server to its owner?',
                      description:
                        'Other people will lose tool access even if they have group or personal permissions. Their permission rules will be kept.',
                      confirmLabel: 'Make private',
                      danger: true,
                    }))
                  )
                    return;
                  await task.execute(async () => {
                    await send(
                      '/admin/api/servers-dynamic/' + encodeURIComponent(server.name),
                      { visibility: audience },
                      'PUT',
                    );
                    await onUpdate();
                    await load();
                  }, 'Server audience updated');
                })();
              }}
            >
              <Field label="Server audience">
                <select
                  value={audience}
                  onChange={(e) => setAudience(e.target.value as Server['visibility'])}
                >
                  <option value="private">Private · owner and administrators</option>
                  <option value="shared">Selected people · share when granting access</option>
                  <option value="public">Organization · access still requires permissions</option>
                </select>
              </Field>
              <FormError message={task.error} />
              <button disabled={task.busy || audience === server.visibility}>
                {task.busy ? 'Saving…' : 'Save audience'}
              </button>
            </form>
          </details>
        </section>
      )}
    </>
  );
  async function confirmDraft() {
    // The permission editor owns its draft. Route changes use the same guard.
    return await draftGuard();
  }
}

export function UsersAccess({
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
  const [data, setData] = useState<AccessDirectory>(),
    [details, setDetails] = useState<UserAccess>(),
    [search, setSearch] = useState(''),
    [server, setServer] = useState(''),
    [group, setGroup] = useState('');
  const task = useTask(run),
    confirm = useConfirm(),
    guard = useDraftGuard();
  const load = useCallback(
    async () => setData(await api<AccessDirectory>('/admin/api/access')),
    [],
  );
  const loadPerson = useCallback(async () => {
    if (route.item) {
      const result = await api<UserAccess>(
        `/admin/api/users/${encodeURIComponent(route.item)}/servers`,
      );
      setDetails(result);
      setGroup(result.user.group);
    }
  }, [route.item]);
  useEffect(() => {
    void run(load);
  }, [run, load]);
  useEffect(() => {
    let active = true;
    setDetails(undefined);
    setServer('');
    if (route.item)
      void run(async () => {
        const result = await api<UserAccess>(
          `/admin/api/users/${encodeURIComponent(route.item!)}/servers`,
        );
        if (active) {
          setDetails(result);
          setGroup(result.user.group);
        }
      });
    return () => {
      active = false;
    };
  }, [route.item, run]);
  useUnsavedChanges(!!details && group !== details.user.group);
  if (!data)
    return (
      <>
        <Loading label="Loading users…" />
        <button onClick={() => void run(load)}>Retry</button>
      </>
    );
  const person = data.users.find((u) => u.id === route.item),
    people = data.users.filter((u) =>
      `${u.username} ${u.group}`.toLowerCase().includes(search.toLowerCase()),
    );
  const locked = !me.admin && (person?.admin || person?.id === me.principal.id);
  const selectedServer = data.servers.find((s) => s.name === server);
  const availableSources = details?.servers || {};
  return (
    <>
      <div className="eyebrow">ADMINISTRATION / ACCESS</div>
      <h1>Users & access</h1>
      <p>Choose a person, see their access, and give them the tools they need.</p>
      <div className="directory-layout">
        <section className="directory-list">
          <Field label="Find a user" hint="New people appear after their first sign-in.">
            <input
              type="search"
              placeholder="Name or group…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </Field>
          {people.map((user) => (
            <a
              href={href({ view: 'users', item: user.id })}
              key={user.id}
              className={`person-row ${route.item === user.id ? 'selected' : ''}`}
              aria-current={route.item === user.id ? 'page' : undefined}
              onClick={(e) => {
                e.preventDefault();
                void navigate({ view: 'users', item: user.id });
              }}
            >
              <span className="avatar" aria-hidden="true">
                {user.username[0]?.toUpperCase() || '?'}
              </span>
              <span>
                <strong>{user.username}</strong>
                <small>
                  {user.admin ? 'Administrator' : user.manager ? 'Manager' : user.group} ·{' '}
                  {user.kind === 'bot' ? 'Service client' : 'Person'}
                </small>
              </span>
            </a>
          ))}
          {!people.length && (
            <Empty title="No matching users">
              <button onClick={() => setSearch('')}>Clear search</button>
            </Empty>
          )}
        </section>
        <div>
          {route.item && !details ? (
            <section>
              <Loading label="Loading this person’s access…" />
            </section>
          ) : person && details ? (
            <>
              <section>
                <div className="section-title">
                  <div>
                    <h2>{person.username}</h2>
                    <small className="muted">
                      {person.kind === 'bot' ? 'Service client' : 'Company account'}
                    </small>
                  </div>
                  {person.admin && <Badge value="admin" label="Administrator" />}
                </div>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    void task.execute(async () => {
                      await send(
                        `/admin/api/users/${encodeURIComponent(person.id)}/group`,
                        { group },
                        'PUT',
                      );
                      await load();
                      await loadPerson();
                    }, 'Permission group updated');
                  }}
                >
                  <Field
                    label="Permission group"
                    hint="A person belongs to one group. Personal permissions can add access to individual servers."
                  >
                    <select
                      disabled={locked || task.busy || person.kind === 'bot'}
                      value={group}
                      onChange={(e) => setGroup(e.target.value)}
                    >
                      {person.kind === 'bot' && (
                        <option value="_bots">Service clients (no default access)</option>
                      )}
                      {Object.keys(data.groups).map((name) => (
                        <option key={name} value={name}>
                          {name}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <FormError message={task.error} />
                  <button
                    disabled={
                      locked || task.busy || person.kind === 'bot' || group === details.user.group
                    }
                  >
                    {task.busy ? 'Saving…' : 'Save group assignment'}
                  </button>
                </form>
              </section>
              <section>
                <div className="section-title">
                  <h2>Server access</h2>
                  <span className="muted">Effective permissions</span>
                </div>
                {data.servers.length ? (
                  data.servers.map((info) => {
                    const source = availableSources[info.name];
                    return (
                      <div className="access-server-row" key={info.name}>
                        <div>
                          <strong>{info.name}</strong>
                          {source ? (
                            <>
                              <PermissionBadges caps={source.effective_caps} />
                              <p>{accessReason(source)}</p>
                              {source.available === false && (
                                <small className="warning-text">Server is not connected</small>
                              )}
                            </>
                          ) : (
                            <p>No permissions assigned.</p>
                          )}
                        </div>
                        <button
                          disabled={locked}
                          aria-label={`Edit access to ${info.name}`}
                          onClick={async () => {
                            if (server !== info.name && (await guard())) setServer(info.name);
                          }}
                        >
                          Edit access
                        </button>
                      </div>
                    );
                  })
                ) : (
                  <Empty title="No servers yet">
                    Create an MCP server before assigning access.
                  </Empty>
                )}
                <hr />
                <Field label="Choose a server to edit">
                  <select
                    disabled={locked}
                    value={server}
                    onChange={async (e) => {
                      const next = e.target.value;
                      if (await guard()) setServer(next);
                    }}
                  >
                    <option value="">Select an MCP server…</option>
                    {data.servers.map((s) => (
                      <option key={s.name} value={s.name}>
                        {s.name}
                      </option>
                    ))}
                  </select>
                </Field>
                {selectedServer && availableSources[server] && (
                  <PermissionEditor
                    key={person.id + server + JSON.stringify(availableSources[server])}
                    person={person}
                    server={selectedServer}
                    source={availableSources[server]}
                    me={me}
                    run={run}
                    onSaved={async () => {
                      await loadPerson();
                      await load();
                    }}
                  />
                )}
              </section>
              <section>
                <details>
                  <summary>Session management</summary>
                  <p>
                    Sign this person out of every MCP client and console session. Their permissions
                    stay in place.
                  </p>
                  <button
                    className="danger"
                    disabled={locked || task.busy}
                    onClick={() => {
                      void (async () => {
                        if (
                          await confirm({
                            title: `Sign out ${person.username}?`,
                            description:
                              'All their current sessions will end. They can sign in again with the same permissions.',
                            confirmLabel: 'Sign out everywhere',
                            danger: true,
                          })
                        )
                          await task.execute(async () => {
                            await send(
                              `/admin/api/users/${encodeURIComponent(person.id)}/revoke`,
                              {},
                            );
                          }, 'Sessions revoked');
                      })();
                    }}
                  >
                    Sign out everywhere
                  </button>
                </details>
              </section>
            </>
          ) : (
            <section>
              <Empty title="Choose a person">
                View their group and see which servers they can use.
              </Empty>
            </section>
          )}
        </div>
      </div>
    </>
  );
}

export function GroupsEditor({
  run,
  route,
  navigate,
}: {
  run: Run;
  route: Route;
  navigate: Navigate;
}) {
  const [data, setData] = useState<AccessDirectory>(),
    [name, setName] = useState(''),
    [mapping, setMapping] = useState<Record<string, string[]>>({}),
    [approval, setApproval] = useState(false),
    [baseline, setBaseline] = useState(''),
    [search, setSearch] = useState('');
  const task = useTask(run),
    confirm = useConfirm();
  const editing = !!route.item && route.item !== 'new';
  const load = useCallback(
    async () => setData(await api<AccessDirectory>('/admin/api/access')),
    [],
  );
  useEffect(() => {
    void run(load);
  }, [load, run]);
  useEffect(() => {
    if (!data) return;
    const group = editing ? data.groups[route.item!] : undefined;
    const values = {
      name: editing ? route.item! : '',
      servers: group?.servers || {},
      approval: group?.approval_required || false,
    };
    setName(values.name);
    setMapping(values.servers);
    setApproval(values.approval);
    setBaseline(JSON.stringify(values));
    setSearch('');
    // Refreshing the directory must not overwrite an in-progress form.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [route.item, !!data]);
  const serialized = JSON.stringify({ name, servers: mapping, approval });
  const markSaved = useUnsavedChanges(!!baseline && baseline !== serialized);
  if (!data)
    return (
      <>
        <Loading label="Loading groups…" />
        <button onClick={() => void run(load)}>Retry</button>
      </>
    );
  const serverOptions = [
    ...data.servers,
    ...Object.keys(mapping)
      .filter((key) => !data.servers.some((s) => s.name === key))
      .map((key): AccessServer => ({
        name: key,
        description: 'Server is no longer registered',
        visibility: 'private',
        owner: '',
        managed: false,
        available: false,
        status: 'offline',
      })),
  ];
  const filtered = serverOptions.filter((s) =>
    `${s.name} ${s.description}`.toLowerCase().includes(search.toLowerCase()),
  );
  const showEditor = !!route.item;
  return (
    <>
      <div className="eyebrow">ADMINISTRATION / TEAMS</div>
      <div className="page-title">
        <div>
          <h1>Groups</h1>
          <p>Give a team the same server permissions. New people join the default group.</p>
        </div>
        <button className="primary" onClick={() => void navigate({ view: 'groups', item: 'new' })}>
          Create group
        </button>
      </div>
      <div className="directory-layout">
        <section>
          {Object.entries(data.groups).map(([key, group]) => (
            <a
              key={key}
              href={href({ view: 'groups', item: key })}
              className={`person-row ${key === route.item ? 'selected' : ''}`}
              aria-current={key === route.item ? 'page' : undefined}
              onClick={(e) => {
                e.preventDefault();
                void navigate({ view: 'groups', item: key });
              }}
            >
              <span className="server-symbol" aria-hidden="true">
                ▦
              </span>
              <span>
                <strong>{key}</strong>
                <small>
                  {data.users.filter((u) => u.group === key).length} members ·{' '}
                  {Object.keys(group.servers).length} servers
                </small>
              </span>
            </a>
          ))}
        </section>
        <section>
          {showEditor ? (
            <>
              <div className="section-title">
                <h2>{editing ? `Edit group · ${route.item}` : 'Create a group'}</h2>
                {editing && route.item === 'default' && (
                  <Badge value="default" label="Default for new users" />
                )}
              </div>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void task.execute(async () => {
                    await send(
                      '/admin/api/groups' + (editing ? '/' + encodeURIComponent(route.item!) : ''),
                      { name, servers: mapping, approval_required: approval },
                      editing ? 'PUT' : 'POST',
                    );
                    setBaseline(serialized);
                    markSaved();
                    await load();
                    if (!editing) {
                      history.replaceState(null, '', href({ view: 'groups', item: name }));
                      window.dispatchEvent(new HashChangeEvent('hashchange'));
                    }
                  }, 'Group permissions saved. Assign people to this group in Users & access.');
                }}
              >
                <Field
                  label="Group name"
                  hint="Use lowercase letters, numbers, hyphens or underscores."
                >
                  <input
                    required
                    pattern="[a-z0-9_-]{1,64}"
                    maxLength={64}
                    disabled={editing || task.busy}
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="support-team"
                  />
                </Field>
                <div className="section-title">
                  <h3>Server permissions</h3>
                  <input
                    aria-label="Find a server"
                    type="search"
                    placeholder="Find a server…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
                <div className="group-server-list">
                  {filtered.map((s) => (
                    <div className="group-server" key={s.name}>
                      <label className="check">
                        <input
                          type="checkbox"
                          disabled={task.busy}
                          checked={s.name in mapping}
                          onChange={(e) => {
                            const next = { ...mapping };
                            if (e.target.checked) next[s.name] = ['read'];
                            else delete next[s.name];
                            setMapping(next);
                          }}
                        />
                        <strong>{s.name}</strong>
                        <Badge value={s.visibility} />
                      </label>
                      {s.name in mapping && (
                        <>
                          <CapabilityPicker
                            label={`Permissions for ${s.name}`}
                            value={mapping[s.name]}
                            disabled={task.busy}
                            onChange={(value) => setMapping({ ...mapping, [s.name]: value })}
                          />
                          {s.visibility !== 'public' && (
                            <div className="callout warning">
                              This server is restricted. Team members also need to be included in
                              its audience.{' '}
                              <a
                                href={href({ view: 'servers', item: s.name, tab: 'access' })}
                                onClick={(e) => {
                                  e.preventDefault();
                                  void navigate({ view: 'servers', item: s.name, tab: 'access' });
                                }}
                              >
                                Review server access →
                              </a>
                            </div>
                          )}
                          {!mapping[s.name].length && (
                            <p className="warning-text">
                              Select a permission, or uncheck the server to remove it from this
                              group.
                            </p>
                          )}
                        </>
                      )}
                    </div>
                  ))}
                </div>
                {!filtered.length && (
                  <Empty title="No matching servers">
                    Try another search, or create a server first.
                  </Empty>
                )}
                <label className="check">
                  <input
                    type="checkbox"
                    checked={approval}
                    disabled={task.busy}
                    onChange={(e) => setApproval(e.target.checked)}
                  />
                  Require human approval for destructive actions
                </label>
                <FormError message={task.error} />
                <div className="actions">
                  <button
                    className="primary"
                    disabled={
                      task.busy ||
                      !name.trim() ||
                      Object.values(mapping).some((caps) => !caps.length) ||
                      (editing && serialized === baseline)
                    }
                  >
                    {task.busy ? 'Saving group…' : 'Save group'}
                  </button>
                  {editing && route.item !== 'default' && (
                    <button
                      type="button"
                      className="danger subtle"
                      disabled={task.busy}
                      onClick={() => {
                        void (async () => {
                          const members = data.users.filter((u) => u.group === route.item).length;
                          if (
                            await confirm({
                              title: `Delete group “${route.item}”?`,
                              description: `${members} members will move to the default group. Their personal access rules will be kept.`,
                              confirmLabel: 'Delete group',
                              danger: true,
                            })
                          )
                            await task.execute(async () => {
                              await api('/admin/api/groups/' + encodeURIComponent(route.item!), {
                                method: 'DELETE',
                              });
                              setBaseline(serialized);
                              markSaved();
                              await load();
                              history.replaceState(null, '', href({ view: 'groups' }));
                              window.dispatchEvent(new HashChangeEvent('hashchange'));
                            }, 'Group deleted');
                        })();
                      }}
                    >
                      Delete group
                    </button>
                  )}
                </div>
              </form>
            </>
          ) : (
            <Empty title="Set up access for a team">
              Choose a group to edit, or create one. Assign its members in Users & access.
            </Empty>
          )}
        </section>
      </div>
    </>
  );
}
