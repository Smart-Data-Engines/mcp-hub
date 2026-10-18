import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
} from 'react';

export type Run = (work: () => Promise<unknown>, success?: string) => Promise<boolean>;
export function Badge({ value, label }: { value: string; label?: string }) {
  const labels: Record<string, string> = {
    public: 'Organization',
    shared: 'Selected people',
    private: 'Private',
    destructive: 'Delete & destructive',
    bot: 'Service client',
  };
  return <span className={`badge ${value}`}>{label || labels[value] || value}</span>;
}
export function Empty({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="empty">
      <span className="empty-mark" aria-hidden="true">
        ◇
      </span>
      <h3>{title}</h3>
      <div>{children}</div>
    </div>
  );
}
export function Code({ value }: { value: unknown }) {
  return (
    <pre className="code">{typeof value === 'string' ? value : JSON.stringify(value, null, 2)}</pre>
  );
}
export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {React.isValidElement<{ id?: string; 'aria-describedby'?: string }>(children)
        ? React.cloneElement(children, {
            id,
            ...(hint ? { 'aria-describedby': id + '-hint' } : {}),
          })
        : children}
      {hint && (
        <small id={id + '-hint'} className="field-hint">
          {hint}
        </small>
      )}
    </div>
  );
}
export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="loading-state" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}
export class EditorBoundary extends React.Component<
  { children: React.ReactNode; fallback?: React.ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <>
        <div className="callout" role="status">
          <h3>Using the basic editor</h3>
          <p>
            The enhanced editor is unavailable. You can edit and save below; nothing needs to be
            installed.
          </p>
        </div>
        {this.props.fallback}
      </>
    ) : (
      this.props.children
    );
  }
}
export function useTask(run: Run) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState('');
  const lock = useRef(false);
  const execute = async (work: () => Promise<unknown>, success?: string) => {
    if (lock.current) return false;
    lock.current = true;
    setBusy(true);
    setError('');
    try {
      return await run(async () => {
        try {
          await work();
        } catch (e) {
          setError(e instanceof Error ? e.message : 'Could not save. Try again.');
          throw e;
        }
      }, success);
    } finally {
      lock.current = false;
      setBusy(false);
    }
  };
  return { busy, error, execute };
}
export function FormError({ message }: { message: string }) {
  return message ? (
    <p className="form-error" role="alert">
      {message}
    </p>
  ) : null;
}
export function CopyButton({ value, label = 'Copy endpoint' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false),
    [error, setError] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  return (
    <div className="copy-action">
      <button
        onClick={() => {
          void (async () => {
            try {
              if (!navigator.clipboard) throw new Error('Clipboard unavailable');
              await navigator.clipboard.writeText(value);
              setCopied(true);
              setError(false);
              clearTimeout(timer.current);
              timer.current = setTimeout(() => setCopied(false), 2500);
            } catch {
              setError(true);
            }
          })();
        }}
      >
        {label}
      </button>
      <span role="status">
        {copied ? 'Copied' : error ? 'Select and copy the text above.' : ''}
      </span>
    </div>
  );
}

type ConfirmOptions = {
  title: string;
  description: string;
  confirmLabel?: string;
  danger?: boolean;
};
type Confirm = (options: ConfirmOptions) => Promise<boolean>;
const ConfirmContext = createContext<Confirm>(async () => false);
export function useConfirm() {
  return useContext(ConfirmContext);
}

export function Modal({
  title,
  children,
  onClose,
}: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null),
    id = useId();
  const opener = useRef(document.activeElement as HTMLElement | null);
  const close = useRef(onClose);
  close.current = onClose;
  useLayoutEffect(() => {
    const node = ref.current!;
    node.showModal();
    const initial =
      node.querySelector<HTMLElement>('[data-initial-focus]') ||
      node.querySelector<HTMLElement>('input, select, textarea, button');
    initial?.focus();
    return () => {
      node.close();
      if (opener.current?.isConnected) opener.current.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      aria-labelledby={id}
      onKeyDown={(event) => {
        if (event.key !== 'Tab') return;
        const controls = [
          ...event.currentTarget.querySelectorAll<HTMLElement>(
            'button, a[href], input:not([type="hidden"]), select, textarea, summary, [tabindex]:not([tabindex="-1"])',
          ),
        ].filter((node) => !node.matches(':disabled') && node.getClientRects().length > 0);
        const first = controls[0],
          last = controls.at(-1);
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }}
      onCancel={(event) => {
        event.preventDefault();
        close.current();
      }}
    >
      <div className="dialog-heading">
        <h2 id={id}>{title}</h2>
        <button type="button" aria-label="Close dialog" onClick={onClose}>
          ×
        </button>
      </div>
      {children}
    </dialog>
  );
}
export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const [options, setOptions] = useState<ConfirmOptions>();
  const resolver = useRef<((value: boolean) => void) | undefined>(undefined);
  const confirm = useCallback<Confirm>(
    (next) =>
      new Promise((resolve) => {
        resolver.current?.(false);
        resolver.current = resolve;
        setOptions(next);
      }),
    [],
  );
  const finish = (value: boolean) => {
    setOptions(undefined);
    resolver.current?.(value);
    resolver.current = undefined;
  };
  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {options && (
        <Modal title={options.title} onClose={() => finish(false)}>
          <p>{options.description}</p>
          <div className="dialog-actions">
            <button data-initial-focus autoFocus onClick={() => finish(false)}>
              Cancel
            </button>
            <button className={options.danger ? 'danger' : 'primary'} onClick={() => finish(true)}>
              {options.confirmLabel || 'Continue'}
            </button>
          </div>
        </Modal>
      )}
    </ConfirmContext.Provider>
  );
}

type DirtyContextValue = {
  setDirty: (key: string, value: boolean) => void;
  hasChanges: () => boolean;
};
const DirtyContext = createContext<DirtyContextValue>({
  setDirty: () => {},
  hasChanges: () => false,
});
export function DraftProvider({ children }: { children: React.ReactNode }) {
  const keys = useRef(new Set<string>());
  const [value] = useState(() => ({
    setDirty: (key: string, dirty: boolean) => {
      if (dirty) keys.current.add(key);
      else keys.current.delete(key);
    },
    hasChanges: () => keys.current.size > 0,
  }));
  useEffect(() => {
    const listener = (event: BeforeUnloadEvent) => {
      if (keys.current.size) {
        event.preventDefault();
        event.returnValue = '';
      }
    };
    window.addEventListener('beforeunload', listener);
    return () => window.removeEventListener('beforeunload', listener);
  }, []);
  return <DirtyContext.Provider value={value}>{children}</DirtyContext.Provider>;
}
export function useUnsavedChanges(dirty: boolean) {
  const id = useId(),
    context = useContext(DirtyContext);
  useEffect(() => {
    context.setDirty(id, dirty);
    return () => context.setDirty(id, false);
  }, [id, context, dirty]);
  return () => context.setDirty(id, false);
}
export function useDraftGuard() {
  const context = useContext(DirtyContext),
    confirm = useConfirm();
  return useCallback(
    async () =>
      !context.hasChanges() ||
      (await confirm({
        title: 'Leave without saving?',
        description:
          'You have unsaved changes on this page. Save them first, or discard them to continue.',
        confirmLabel: 'Discard changes',
        danger: true,
      })),
    [context, confirm],
  );
}
