import { useEffect, useState } from 'react';
import { api, send, type Me, type Server } from './api';
import { Field, FormError, Loading, useConfirm, useTask, type Run } from './ui';
import type { Navigate } from './navigation';

interface EnvironmentInfo {
  declared: string[];
  configured: string[];
  user_env: string[];
  configuration_visible: boolean;
  restart_required: boolean;
}
const modes = [
  {
    value: 'global_only',
    name: 'Shared connection',
    description: 'People with access use the connection saved for this server.',
  },
  {
    value: 'user_only',
    name: 'Personal connections',
    description: 'Each person must add their own credentials in My credentials.',
  },
  {
    value: 'both',
    name: 'Personal with shared fallback',
    description: 'Use personal credentials when available, otherwise use the shared connection.',
  },
];
function fieldLabel(name: string) {
  return name
    .split('_')
    .map((word) =>
      word.length <= 3 ? word.toUpperCase() : word[0]?.toUpperCase() + word.slice(1).toLowerCase(),
    )
    .join(' ');
}

export function ServerEnvironment({
  server,
  me,
  run,
  navigate,
  onDirtyChange,
  onSaved,
  onUpdate,
  onRestart,
  busy,
}: {
  server: Server;
  me: Me;
  run: Run;
  navigate: Navigate;
  onDirtyChange: (dirty: boolean) => void;
  onSaved: () => void;
  onUpdate: () => Promise<void>;
  onRestart: () => Promise<boolean>;
  busy: boolean;
}) {
  const base = '/admin/api/servers-dynamic/' + encodeURIComponent(server.name);
  const [info, setInfo] = useState<EnvironmentInfo>(),
    [loadError, setLoadError] = useState(''),
    [values, setValues] = useState<Record<string, string>>({}),
    [remove, setRemove] = useState<string[]>([]),
    [visible, setVisible] = useState<string[]>([]),
    [policy, setPolicy] = useState(server.policy);
  const task = useTask(run),
    confirm = useConfirm();
  const changedValues = Object.fromEntries(
    Object.entries(values).filter(([, value]) => value !== ''),
  );
  const fieldsDirty = Object.keys(changedValues).length > 0 || remove.length > 0;
  const dirty = fieldsDirty || policy !== server.policy;
  useEffect(() => {
    onDirtyChange(dirty);
  }, [dirty, onDirtyChange]);
  useEffect(() => () => onDirtyChange(false), [onDirtyChange]);
  useEffect(() => setPolicy(server.policy), [server.policy]);
  const load = async () => {
    setLoadError('');
    try {
      setInfo(await api<EnvironmentInfo>(base + '/env'));
    } catch {
      setLoadError('Could not load the saved connection status. Try again.');
    }
  };
  useEffect(() => {
    void load();
  }, [base, server.status, server.code_version]);
  const disabled = task.busy || busy;
  const mode = modes.find((item) => item.value === server.policy);
  return (
    <section className="server-environment">
      <h2>Connection & environment</h2>
      <p>Manage the connection this server uses. Saved values are encrypted and stay hidden.</p>
      <div className="connection-summary">
        <div>
          <h3>{mode?.name || 'Connection mode'}</h3>
          <p>{mode?.description}</p>
        </div>
        <span className="badge">{me.admin ? 'Managed by you' : 'Managed by an administrator'}</span>
      </div>
      {loadError && (
        <div className="callout" role="alert">
          <p>{loadError}</p>
          <button disabled={disabled} onClick={() => void load()}>
            Retry connection status
          </button>
        </div>
      )}
      {!info && !loadError && <Loading label="Loading saved connection…" />}
      {info && (
        <>
          {info.restart_required && (
            <div className="callout apply-changes" role="status">
              <div>
                <strong>Saved changes are waiting for a restart</strong>
                <p>The running server still uses the previous values.</p>
              </div>
              {me.runtime_enabled && (
                <button
                  className="primary"
                  disabled={disabled || dirty}
                  onClick={() =>
                    void (async () => {
                      if (await onRestart()) await load();
                    })()
                  }
                >
                  Restart to apply
                </button>
              )}
            </div>
          )}
          <div className="section-title">
            <div>
              <h3>Server connection details</h3>
              <p className="hint">These values are passed to the server when it starts.</p>
            </div>
            {info.configuration_visible && info.declared.length > 0 && (
              <span className="muted">
                {info.declared.filter((name) => info.configured.includes(name)).length} of{' '}
                {info.declared.length} saved
              </span>
            )}
          </div>
          {info.declared.length ? (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void task.execute(
                  async () => {
                    await send(base + '/env', { values: changedValues, remove }, 'PATCH');
                    setValues({});
                    setRemove([]);
                    setVisible([]);
                    onDirtyChange(policy !== server.policy);
                    if (policy === server.policy) onSaved();
                    await load();
                  },
                  server.status === 'running'
                    ? 'Connection saved. Restart the server to apply changes.'
                    : 'Connection saved. It will be used when the server starts.',
                );
              }}
            >
              <div className="connection-fields">
                {info.declared.map((name) => {
                  const saved = info.configured.includes(name),
                    deleting = remove.includes(name),
                    showing = visible.includes(name);
                  return (
                    <div className={'connection-field' + (deleting ? ' removing' : '')} key={name}>
                      <div className="connection-field-heading">
                        <code>{name}</code>
                        <span
                          className={'badge ' + (deleting ? 'pending' : saved ? 'saved' : 'unset')}
                        >
                          {!info.configuration_visible
                            ? 'Managed by administrator'
                            : deleting
                              ? 'Will be removed'
                              : saved
                                ? 'Saved'
                                : 'Not set'}
                        </span>
                      </div>
                      {me.admin && (
                        <>
                          <Field
                            label={fieldLabel(name)}
                            hint={
                              deleting
                                ? 'This value will be removed when you save.'
                                : saved
                                  ? 'Leave blank to keep the saved value. Enter a new value to replace it.'
                                  : 'Enter the value supplied by this service.'
                            }
                          >
                            <input
                              type={showing ? 'text' : 'password'}
                              autoComplete="new-password"
                              spellCheck={false}
                              value={values[name] || ''}
                              disabled={disabled || deleting}
                              placeholder={
                                saved ? 'Saved value stays hidden' : 'Not configured yet'
                              }
                              onChange={(event) =>
                                setValues({ ...values, [name]: event.target.value })
                              }
                            />
                          </Field>
                          <div className="actions field-actions">
                            <button
                              type="button"
                              disabled={disabled || deleting}
                              aria-label={`${showing ? 'Hide' : 'Show'} ${name}`}
                              aria-pressed={showing}
                              onClick={() =>
                                setVisible(
                                  showing
                                    ? visible.filter((item) => item !== name)
                                    : [...visible, name],
                                )
                              }
                            >
                              {showing ? 'Hide new value' : 'Show new value'}
                            </button>
                            {saved && (
                              <button
                                type="button"
                                disabled={disabled}
                                className={deleting ? '' : 'danger subtle'}
                                aria-label={`${deleting ? 'Keep' : 'Remove'} ${name}`}
                                onClick={() =>
                                  void (async () => {
                                    if (deleting) {
                                      setRemove(remove.filter((item) => item !== name));
                                      return;
                                    }
                                    if (
                                      await confirm({
                                        title: `Remove ${fieldLabel(name)}?`,
                                        description:
                                          'The saved value will be removed when you save these changes. After restarting, the server may need a replacement to connect.',
                                        confirmLabel: 'Mark for removal',
                                        danger: true,
                                      })
                                    ) {
                                      setRemove([...remove, name]);
                                      setValues({ ...values, [name]: '' });
                                    }
                                  })()
                                }
                              >
                                {deleting ? 'Keep saved value' : 'Remove saved value'}
                              </button>
                            )}
                          </div>
                        </>
                      )}
                    </div>
                  );
                })}
              </div>
              {me.admin && (
                <div className="form-footer">
                  <button className="primary" disabled={disabled || !fieldsDirty}>
                    {task.busy ? 'Saving…' : 'Save connection'}
                  </button>
                  <p className="hint">
                    Blank fields keep their saved values. Changes take effect on the next start or
                    restart.
                  </p>
                </div>
              )}
            </form>
          ) : (
            <div className="empty compact">
              <h3>No server values needed</h3>
              <p>This server does not request any shared credentials or environment values.</p>
            </div>
          )}
          <FormError message={task.error} />
          {info.user_env.length > 0 && (
            <div className="personal-connection-card">
              <h3>Your personal connection</h3>
              <p>
                This server accepts personal credentials: {info.user_env.map(fieldLabel).join(', ')}
                .
              </p>
              <button onClick={() => void navigate({ view: 'credentials', item: server.name })}>
                Set up my connection
              </button>
            </div>
          )}
          {me.admin && (
            <details className="advanced-panel">
              <summary>Change connection mode</summary>
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  void task.execute(async () => {
                    await send(base + '/policy', { policy });
                    await onUpdate();
                    onDirtyChange(fieldsDirty);
                    if (!fieldsDirty) onSaved();
                  }, 'Connection mode saved');
                }}
              >
                <fieldset className="connection-modes">
                  <legend>Connection mode</legend>
                  {modes.map((item) => (
                    <label className="connection-mode" key={item.value}>
                      <input
                        type="radio"
                        name="connection-mode"
                        value={item.value}
                        checked={policy === item.value}
                        disabled={disabled}
                        onChange={() => setPolicy(item.value)}
                      />
                      <span>
                        <strong>{item.name}</strong>
                        <small>{item.description}</small>
                      </span>
                    </label>
                  ))}
                </fieldset>
                <button className="primary" disabled={disabled || policy === server.policy}>
                  Save connection mode
                </button>
              </form>
            </details>
          )}
        </>
      )}
    </section>
  );
}
