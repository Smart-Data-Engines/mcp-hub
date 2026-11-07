import { useEffect, useRef, useState } from 'react';
import { api, send, type Server } from './api';
import { Field, FormError, Loading, useConfirm, useTask, useUnsavedChanges, type Run } from './ui';

type Saved = { configured: string[]; repository: string };
interface ConnectionInfo {
  policy: string;
  personal: Saved;
  shared: Saved;
  can_manage: boolean;
  can_change_policy: boolean;
  can_configure_shared: boolean;
  only_mine: boolean;
  restart_required: boolean;
  token_url: string;
  guide_url: string;
  permissions: string;
}
interface TestResult {
  ok: boolean;
  account: string;
  repository: string;
  message: string;
  note: string;
}

export function StarterConnection({
  server,
  run,
  onDirtyChange,
  onSaved,
  onUpdate,
  onStart,
  onRestart,
  busy = false,
  personalView = false,
}: {
  server: Server;
  run: Run;
  onDirtyChange?: (dirty: boolean) => void;
  onSaved?: () => void;
  onUpdate?: () => Promise<void>;
  onStart?: () => Promise<boolean>;
  onRestart?: () => Promise<boolean>;
  busy?: boolean;
  personalView?: boolean;
}) {
  const base =
    '/admin/api/servers-dynamic/' + encodeURIComponent(server.name) + '/starter-connection';
  const [info, setInfo] = useState<ConnectionInfo>();
  const [loadError, setLoadError] = useState('');
  const [policy, setPolicy] = useState(server.policy);
  const [token, setToken] = useState('');
  const [repository, setRepository] = useState('');
  const [show, setShow] = useState(false);
  const [result, setResult] = useState<TestResult>();
  const task = useTask(run),
    confirm = useConfirm();
  const saved = policy === 'global_only' ? info?.shared : info?.personal;
  const canEdit = policy !== 'global_only' || (!personalView && info?.can_configure_shared);
  const dirty =
    !!token || (!!info && (repository !== (saved?.repository || '') || policy !== info.policy));
  const dirtyRef = useRef(dirty);
  dirtyRef.current = dirty;
  const markSaved = useUnsavedChanges(dirty);
  useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);
  const load = async (reset = true) => {
    setLoadError('');
    try {
      const data = await api<ConnectionInfo>(base);
      setInfo(data);
      if (reset) {
        setPolicy(data.policy);
        setRepository(
          (data.policy === 'global_only' ? data.shared : data.personal).repository || '',
        );
      }
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : 'Could not load your connection.');
    }
  };
  useEffect(() => {
    void load(!dirtyRef.current);
  }, [base, server.policy, server.status, server.code_version]);
  if (!info)
    return loadError ? (
      <div className="callout" role="alert">
        <p>{loadError}</p>
        <button onClick={() => void load()}>Retry connection</button>
      </div>
    ) : (
      <Loading label="Loading GitHub connection…" />
    );
  const disabled = busy || task.busy;
  const ready = saved?.configured.includes('token') && saved?.configured.includes('repository');
  return (
    <section className="starter-connection">
      <h2>GitHub connection</h2>
      <p>
        This starter reads one GitHub.com repository, its issues and pull requests. It does not
        change your repository.
      </p>
      {loadError && (
        <div className="callout" role="alert">
          {loadError}
        </div>
      )}
      {!personalView && info.can_change_policy ? (
        <fieldset disabled={disabled} className="starter-mode">
          <legend>Who provides the GitHub account?</legend>
          {[
            [
              'user_only',
              'Each person uses their own account',
              'Recommended: everyone adds their own repository and token.',
            ],
            [
              'global_only',
              'Use a shared account',
              'People granted access use the account configured by an administrator.',
            ],
          ].map(([value, label, hint]) => (
            <label className="starter-card" key={value}>
              <input
                type="radio"
                name="github-connection-mode"
                value={value}
                checked={policy === value}
                onChange={() =>
                  void (async () => {
                    if (
                      dirty &&
                      !(await confirm({
                        title: 'Switch connection type?',
                        description: 'Your unsaved connection fields will be discarded.',
                        confirmLabel: 'Switch connection type',
                      }))
                    )
                      return;
                    setPolicy(value);
                    setToken('');
                    setShow(false);
                    setResult(undefined);
                    setRepository(
                      (value === 'global_only' ? info.shared : info.personal).repository || '',
                    );
                  })()
                }
              />
              <span>
                <strong>{label}</strong>
                <small>{hint}</small>
              </span>
            </label>
          ))}
        </fieldset>
      ) : (
        <div className="connection-summary">
          <div>
            <h3>{policy === 'global_only' ? 'Shared connection' : 'Your personal account'}</h3>
            <p>
              {policy === 'global_only'
                ? 'An administrator manages this account. Your Hub permissions still apply.'
                : 'Only you can use the token saved here.'}
            </p>
          </div>
        </div>
      )}
      {policy === 'global_only' && info.only_mine && (
        <div className="callout">
          <p>Your “only personal credentials” preference blocks this shared account.</p>
          <button
            disabled={disabled || dirty}
            onClick={() =>
              void (async () => {
                if (
                  !(await confirm({
                    title: 'Use the shared GitHub account?',
                    description:
                      'This changes only your preference for this server. You will use its administrator-managed account.',
                    confirmLabel: 'Use shared account',
                  }))
                )
                  return;
                await task.execute(async () => {
                  await send('/credentials/mode', { service: server.name, only_mine: false });
                  await load();
                }, 'Your preference was updated');
              })()
            }
          >
            Use the shared connection for my account
          </button>
        </div>
      )}
      {!info.only_mine && (
        <details className="advanced-panel">
          <summary>Personal account preference</summary>
          <p>
            You can require your own account even if an administrator later selects a shared
            connection.
          </p>
          <button
            disabled={disabled || dirty}
            onClick={() =>
              void task.execute(async () => {
                await send('/credentials/mode', { service: server.name, only_mine: true });
                await load();
              }, 'Only your own credentials may be used')
            }
          >
            Always require my own account
          </button>
        </details>
      )}
      {canEdit && (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void task.execute(
              async () => {
                await send(
                  base,
                  { policy, values: { repository, ...(token ? { token } : {}) } },
                  'PATCH',
                );
                setToken('');
                setShow(false);
                setResult(undefined);
                markSaved();
                onSaved?.();
                await load();
                await onUpdate?.();
              },
              policy === 'global_only'
                ? 'Shared GitHub connection saved'
                : 'Your GitHub connection saved',
            );
          }}
        >
          <Field
            label="GitHub repository"
            hint="Use owner/repository, for example octocat/Hello-World. Only this repository is used by the starter."
          >
            <input
              required
              maxLength={201}
              placeholder="octocat/Hello-World"
              spellCheck={false}
              autoComplete="off"
              value={repository}
              disabled={disabled}
              onChange={(event) => {
                setRepository(event.target.value);
                setResult(undefined);
              }}
            />
          </Field>
          <Field
            label="GitHub token"
            hint={
              saved?.configured.includes('token')
                ? 'A token is saved and hidden. Leave this blank to keep it.'
                : 'Create a fine-grained personal access token for the selected repository.'
            }
          >
            <input
              type={show ? 'text' : 'password'}
              required={!saved?.configured.includes('token')}
              maxLength={4096}
              autoComplete="new-password"
              spellCheck={false}
              value={token}
              disabled={disabled}
              placeholder={
                saved?.configured.includes('token')
                  ? 'Saved — leave blank to keep'
                  : 'Paste your GitHub token'
              }
              onChange={(event) => {
                setToken(event.target.value);
                setResult(undefined);
              }}
            />
          </Field>
          <label className="check">
            <input
              type="checkbox"
              checked={show}
              disabled={disabled}
              onChange={(event) => setShow(event.target.checked)}
            />
            Show entered token
          </label>
          <div className="starter-help">
            <strong>Where do I get a token?</strong>
            <p>
              {info.permissions} For an account shared by a team, use a dedicated service account.
            </p>
            <a href={info.token_url} target="_blank" rel="noopener noreferrer">
              Create a GitHub token ↗
            </a>
            {' · '}
            <a href={info.guide_url} target="_blank" rel="noopener noreferrer">
              Token instructions ↗
            </a>
          </div>
          <button className="primary" disabled={disabled || !dirty}>
            {task.busy ? 'Saving…' : 'Save GitHub connection'}
          </button>
        </form>
      )}
      {info.restart_required && policy === 'global_only' && (
        <div className="callout apply-changes" role="status">
          <div>
            <strong>Saved changes are waiting for a restart</strong>
            <p>
              The test below checks your saved connection. The running server uses its previous
              shared settings until restarted.
            </p>
          </div>
          {onRestart && (
            <button disabled={disabled || dirty} onClick={() => void onRestart()}>
              Restart to apply
            </button>
          )}
        </div>
      )}
      <div className="actions starter-connection-actions">
        <button
          disabled={disabled || dirty || (canEdit && !ready)}
          onClick={() =>
            void task.execute(async () => {
              setResult(undefined);
              setResult(await send<TestResult>(base + '/test', {}));
            })
          }
        >
          {task.busy ? 'Working…' : 'Test GitHub connection'}
        </button>
        {canEdit && ready && (
          <button
            className="danger"
            disabled={disabled || dirty}
            onClick={() =>
              void (async () => {
                if (
                  !(await confirm({
                    title: 'Remove this GitHub connection?',
                    description:
                      policy === 'global_only'
                        ? 'The shared account will no longer be configured. Restart a running server to apply the removal.'
                        : 'Your saved token and repository will be removed. Other people are unaffected.',
                    confirmLabel: 'Remove connection',
                    danger: true,
                  }))
                )
                  return;
                await task.execute(async () => {
                  await api(base, { method: 'DELETE' });
                  setToken('');
                  setResult(undefined);
                  markSaved();
                  onSaved?.();
                  await load();
                }, 'GitHub connection removed');
              })()
            }
          >
            Remove connection
          </button>
        )}
        {!personalView && info.can_manage && onStart && server.status !== 'running' && (
          <button className="primary" disabled={disabled || dirty} onClick={() => void onStart()}>
            Start GitHub server
          </button>
        )}
      </div>
      {dirty && (
        <p className="hint">
          Save your changes before testing the connection or starting the server.
        </p>
      )}
      {result && (
        <div className="callout success" role="status">
          <strong>{result.message}</strong>
          <p>{result.note}</p>
          <p>
            {personalView
              ? 'Your connection is ready. Use this server’s permitted tools in your AI client.'
              : server.status === 'running'
                ? 'Your connection is ready. Use Access to choose who may use its read tools.'
                : 'Next: start the server, then use Access to choose who may use its read tools.'}
          </p>
        </div>
      )}
      <FormError message={task.error} />
    </section>
  );
}
