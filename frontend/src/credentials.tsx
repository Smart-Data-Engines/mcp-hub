import { useCallback, useEffect, useState } from 'react';
import { api, send, type Me, type Server } from './api';
import {
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

export function PersonalCredentials({
  run,
  initialService,
}: {
  run: Run;
  initialService?: string;
}) {
  const [data, setData] = useState<{ services: string[]; only_mine: Record<string, boolean> }>(),
    [servers, setServers] = useState<Server[]>([]),
    [available, setAvailable] = useState<string[]>([]),
    [service, setService] = useState(initialService || ''),
    [fields, setFields] = useState<string[]>(),
    [values, setValues] = useState<Record<string, string>>({}),
    [mine, setMine] = useState(false),
    [show, setShow] = useState(false),
    [json, setJson] = useState(''),
    [advanced, setAdvanced] = useState(false);
  const task = useTask(run),
    confirm = useConfirm(),
    guard = useDraftGuard();
  const load = useCallback(async () => {
    const [saved, definitions, access] = await Promise.all([
      api<NonNullable<typeof data>>('/credentials'),
      api<{ servers: Server[] }>('/admin/api/servers-dynamic'),
      api<Me>('/admin/api/whoami'),
    ]);
    setData(saved);
    setServers(
      definitions.servers.filter((s) => access.permissions[s.name]?.effective_caps.length),
    );
    setAvailable(
      Object.keys(access.permissions).filter(
        (name) => access.permissions[name].effective_caps.length,
      ),
    );
  }, []);
  useEffect(() => {
    void run(load);
  }, [load, run]);
  useEffect(() => {
    let active = true;
    setFields(undefined);
    setValues({});
    setJson('');
    setAdvanced(false);
    setShow(false);
    setMine(!!data?.only_mine[service]);
    if (service)
      void run(async () => {
        const known = servers.some((s) => s.name === service);
        if (!known) {
          if (active) setFields([]);
          return;
        }
        const result = await api<{ fields: string[] }>(
          `/admin/api/servers-dynamic/${encodeURIComponent(service)}/user-env-fields`,
        );
        if (active) setFields(result.fields);
      });
    return () => {
      active = false;
    };
  }, [service, servers, run]);
  const dirty =
    Object.values(values).some(Boolean) ||
    !!json ||
    (data !== undefined && mine !== !!data.only_mine[service]);
  const markSaved = useUnsavedChanges(dirty);
  const names = [
    ...new Set([
      ...available,
      ...(data?.services || []),
      ...Object.entries(data?.only_mine || {})
        .filter(([, onlyMine]) => onlyMine)
        .map(([name]) => name),
      ...(initialService ? [initialService] : []),
    ]),
  ].sort();
  if (!data)
    return (
      <>
        <Loading label="Loading your saved connections…" />
        <button onClick={() => void run(load)}>Retry</button>
      </>
    );
  return (
    <>
      <div className="eyebrow">WORKSPACE / CONNECTIONS</div>
      <h1>My credentials</h1>
      <p>
        Connect to a service using your own account. Saved values are encrypted and never displayed
        again.
      </p>
      <div className="split">
        <section>
          <h2>Your saved connections</h2>
          {data.services.length ? (
            data.services.map((name) => (
              <div className="row" key={name}>
                <div>
                  <strong>{name}</strong>
                  <p>
                    {data.only_mine[name]
                      ? 'Only your credentials will be used'
                      : 'Server credential policy applies'}
                  </p>
                </div>
                <div className="actions">
                  <button
                    disabled={task.busy}
                    aria-label={`Update credentials for ${name}`}
                    onClick={async () => {
                      if (await guard()) setService(name);
                    }}
                  >
                    Update
                  </button>
                  <button
                    className="danger subtle"
                    disabled={task.busy}
                    aria-label={`Remove credentials for ${name}`}
                    onClick={() => {
                      void (async () => {
                        if (
                          await confirm({
                            title: `Remove your credentials for ${name}?`,
                            description: data.only_mine[name]
                              ? 'Calls will fail until you add credentials again or turn off “Use only my credentials”.'
                              : 'The server’s credential policy will apply to future calls.',
                            confirmLabel: 'Remove credentials',
                            danger: true,
                          })
                        )
                          await task.execute(async () => {
                            await api('/credentials/' + encodeURIComponent(name), {
                              method: 'DELETE',
                            });
                            await load();
                          }, 'Personal credentials removed');
                      })();
                    }}
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))
          ) : (
            <Empty title="No personal credentials yet">
              Choose a server on the right. Servers that use a shared connection may work without
              personal credentials.
            </Empty>
          )}
        </section>
        <section>
          <h2>
            {data.services.includes(service)
              ? 'Replace personal credentials'
              : 'Add a personal connection'}
          </h2>
          <Field label="MCP server">
            <select
              value={service}
              disabled={task.busy}
              onChange={async (e) => {
                const next = e.target.value;
                if (await guard()) setService(next);
              }}
            >
              <option value="">Choose a server…</option>
              {names.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </Field>
          {service ? (
            fields === undefined ? (
              <Loading label="Checking what this server needs…" />
            ) : (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void task.execute(async () => {
                    let credentials: Record<string, unknown> = values;
                    if (advanced) {
                      try {
                        credentials = JSON.parse(json);
                      } catch {
                        throw new Error(
                          'Enter a valid JSON object, for example {"api_key": "your-key"}.',
                        );
                      }
                      if (
                        !credentials ||
                        Array.isArray(credentials) ||
                        typeof credentials !== 'object'
                      )
                        throw new Error('Credentials must be a JSON object.');
                    }
                    if (Object.values(credentials).some(Boolean))
                      await send('/credentials', { service, credentials, only_mine: mine });
                    else await send('/credentials/mode', { service, only_mine: mine });
                    markSaved();
                    setValues({});
                    setJson('');
                    await load();
                  }, 'Personal connection saved');
                }}
              >
                {data.services.includes(service) && (
                  <div className="callout">
                    New values replace all saved credentials for this server. Leave the fields empty
                    to change only your preference.
                  </div>
                )}
                {fields.length > 0 && !advanced
                  ? fields.map((name) => (
                      <Field key={name} label={name}>
                        <input
                          type={show ? 'text' : 'password'}
                          autoComplete="off"
                          disabled={task.busy}
                          spellCheck={false}
                          required={
                            !data.services.includes(service) || Object.values(values).some(Boolean)
                          }
                          value={values[name] || ''}
                          onChange={(e) => setValues({ ...values, [name]: e.target.value })}
                        />
                      </Field>
                    ))
                  : !advanced && (
                      <div className="callout">
                        This server does not declare any personal credential fields. You can use it
                        without adding values, unless its owner tells you otherwise.
                      </div>
                    )}
                {fields.length > 0 && !advanced && (
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={show}
                      disabled={task.busy}
                      onChange={(e) => setShow(e.target.checked)}
                    />
                    Show entered values
                  </label>
                )}
                <label className="check">
                  <input
                    type="checkbox"
                    checked={mine}
                    disabled={task.busy}
                    onChange={(e) => setMine(e.target.checked)}
                  />
                  Use only my credentials
                </label>
                <p className="hint">
                  When enabled, a call fails if your credentials are missing. Shared credentials
                  will not be used as a fallback.
                </p>
                <details onToggle={(e) => setAdvanced(e.currentTarget.open)}>
                  <summary>Advanced · enter a credential object</summary>
                  <Field label="Credential object (JSON)">
                    <textarea
                      rows={6}
                      disabled={task.busy}
                      value={json}
                      onChange={(e) => setJson(e.target.value)}
                      spellCheck={false}
                      placeholder={'{\n  "api_key": "your-key"\n}'}
                    />
                  </Field>
                </details>
                <FormError message={task.error} />
                <button className="primary" disabled={task.busy || !dirty}>
                  {task.busy ? 'Saving connection…' : 'Save personal connection'}
                </button>
              </form>
            )
          ) : (
            <Empty title="Choose a server">
              The form will show the fields that this server needs.
            </Empty>
          )}
        </section>
      </div>
    </>
  );
}
