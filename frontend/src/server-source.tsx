import React, { useEffect, useState } from 'react';
import { api, send, type Me, type Server } from './api';
import { Code, EditorBoundary, Field, FormError, Loading, useTask, type Run } from './ui';

const Editor = React.lazy(() => import('./editor'));
interface SourceLocation {
  provider: string;
  repository: string;
  repository_url: string | null;
  folder_url: string | null;
  folder: string;
  reference: string;
  pinned: boolean;
  running_revision: string;
}

export function ServerSource({
  server,
  me,
  run,
  onDirtyChange,
  onSaved,
}: {
  server: Server;
  me: Me;
  run: Run;
  onDirtyChange: (dirty: boolean) => void;
  onSaved: () => void;
}) {
  const base = '/admin/api/servers-dynamic/' + encodeURIComponent(server.name);
  const [location, setLocation] = useState<SourceLocation>(),
    [locationError, setLocationError] = useState(''),
    [files, setFiles] = useState<Record<string, string>>(),
    [commit, setCommit] = useState(''),
    [selected, setSelected] = useState('server.py'),
    [dirty, setDirty] = useState<Record<string, string>>({}),
    [browse, setBrowse] = useState(false),
    [editing, setEditing] = useState(false);
  const task = useTask(run);
  const changed = Object.keys(dirty).length;
  useEffect(() => {
    onDirtyChange(changed > 0);
  }, [changed, onDirtyChange]);
  useEffect(() => () => onDirtyChange(false), [onDirtyChange]);
  const loadLocation = async () => {
    setLocationError('');
    try {
      setLocation(await api<SourceLocation>(base + '/source'));
    } catch {
      setLocationError('Could not load the repository details. Try again.');
    }
  };
  useEffect(() => {
    void loadLocation();
  }, [base, server.code_version, server.pinned_ref]);
  const loadFiles = () =>
    task.execute(async () => {
      const data = await api<{ files: Record<string, string>; commit: string }>(base + '/files');
      setFiles(data.files);
      setCommit(data.commit);
      if (!(selected in data.files)) setSelected(Object.keys(data.files).sort()[0] || '');
    });
  const change = (text: string) =>
    setDirty((old) => {
      const next = { ...old };
      if (text === files?.[selected]) delete next[selected];
      else next[selected] = text;
      return next;
    });
  const canEdit =
    me.source_editing_enabled &&
    selected !== 'manifest.yaml' &&
    (me.admin || selected !== 'docker.yaml');
  const basicEditor = (
    <Field
      label="File contents"
      hint="Edit here and save your changes below. No additional software is needed."
    >
      <textarea
        className="plain-source-editor"
        spellCheck={false}
        rows={22}
        disabled={task.busy}
        value={dirty[selected] ?? files?.[selected] ?? ''}
        onChange={(event) => change(event.target.value)}
      />
    </Field>
  );
  return (
    <section className="server-source">
      <h2>Source & updates</h2>
      <p>This server runs code from your workspace's Git repository.</p>
      {locationError ? (
        <div className="callout" role="alert">
          <p>{locationError}</p>
          <button onClick={() => void loadLocation()}>Retry repository details</button>
        </div>
      ) : !location ? (
        <Loading label="Loading repository details…" />
      ) : (
        <>
          <div className="source-location">
            <div className="section-title">
              <h3>{location.provider} repository</h3>
              {location.repository_url && (
                <a
                  className="button-link"
                  href={location.folder_url || location.repository_url}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Open repository ↗
                </a>
              )}
            </div>
            <dl className="source-facts">
              <div>
                <dt>Repository</dt>
                <dd>{location.repository}</dd>
              </div>
              <div>
                <dt>Folder</dt>
                <dd>
                  <code>{location.folder}</code>
                </dd>
              </div>
              <div>
                <dt>{location.pinned ? 'Pinned reference' : 'Branch'}</dt>
                <dd>
                  <code>{location.reference}</code>
                </dd>
              </div>
              <div>
                <dt>Running version</dt>
                <dd>
                  <code>{server.code_version.slice(0, 12) || 'Not started yet'}</code>
                </dd>
              </div>
            </dl>
          </div>
          <div className="update-guide">
            <h3>How to update this server</h3>
            <ol>
              <li>Change the files in the repository folder shown above.</li>
              <li>
                {location.pinned ? (
                  'Publish the changes, then choose the new source reference in Settings.'
                ) : (
                  <>
                    Commit and push your changes to <strong>{location.reference}</strong>.
                  </>
                )}
              </li>
              <li>
                Use <strong>{server.status === 'stopped' ? 'Start' : 'Restart'}</strong> above to
                deploy the code.
              </li>
            </ol>
            <p className="hint">Your repository's access permissions apply when opening it.</p>
          </div>
        </>
      )}
      <details
        className="advanced-panel"
        onToggle={(event) => {
          const open = event.currentTarget.open;
          setBrowse(open);
          if (open && !files && !task.busy) void loadFiles();
        }}
      >
        <summary>
          Browse source files <span className="muted">Optional</span>
        </summary>
        {browse && (
          <div className="source-preview">
            <div className="section-title">
              <p className="hint">
                Repository snapshot {commit.slice(0, 12) || 'loading…'}. The running version is
                shown above.
              </p>
              <button disabled={task.busy || changed > 0} onClick={() => void loadFiles()}>
                Reload files
              </button>
            </div>
            <FormError message={task.error} />
            {!files && !task.error && <Loading label="Loading source files…" />}
            {files && (
              <>
                <Field label="Source file">
                  <select
                    value={selected}
                    disabled={task.busy}
                    onChange={(event) => setSelected(event.target.value)}
                  >
                    {Object.keys(files)
                      .sort()
                      .map((file) => (
                        <option key={file} value={file}>
                          {file}
                          {file in dirty ? ' •' : ''}
                        </option>
                      ))}
                  </select>
                </Field>
                {me.source_editing_enabled && !editing && (
                  <button onClick={() => setEditing(true)}>Edit source in console</button>
                )}
                {selected in files &&
                  (editing && canEdit ? (
                    <EditorBoundary fallback={basicEditor}>
                      <React.Suspense fallback={<Loading label="Opening enhanced editor…" />}>
                        <Editor
                          key={selected}
                          filename={selected}
                          disabled={task.busy}
                          value={dirty[selected] ?? files[selected]}
                          onChange={change}
                        />
                      </React.Suspense>
                    </EditorBoundary>
                  ) : (
                    <Code value={files[selected]} />
                  ))}
                {editing && (
                  <div className="actions source-save">
                    <button
                      className="primary"
                      disabled={task.busy || !changed}
                      onClick={() =>
                        void task.execute(async () => {
                          const result = await send<{ commit: string }>(base + '/commit', {
                            files: dirty,
                            expected_commit: commit,
                            message: 'Update ' + server.name + ' from console',
                          });
                          setFiles({ ...files, ...dirty });
                          setDirty({});
                          setCommit(result.commit);
                          onDirtyChange(false);
                          onSaved();
                        }, 'Files committed together. Restart to deploy.')
                      }
                    >
                      {task.busy ? 'Saving files…' : `Commit ${changed || ''} changed files`}
                    </button>
                    <p className="hint">
                      Saving code creates a Git commit. Restart the server to deploy it.
                    </p>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </details>
    </section>
  );
}
