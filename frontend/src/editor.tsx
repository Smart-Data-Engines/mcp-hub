import { useEffect, useRef } from 'react';
import { basicSetup } from 'codemirror';
import { EditorView } from '@codemirror/view';
import { python } from '@codemirror/lang-python';
import { yaml } from '@codemirror/lang-yaml';

export default function Editor({
  filename,
  value,
  onChange,
  disabled = false,
}: {
  filename: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  const target = useRef<HTMLDivElement>(null),
    change = useRef(onChange);
  change.current = onChange;
  useEffect(() => {
    const view = new EditorView({
      doc: value,
      parent: target.current!,
      extensions: [
        basicSetup,
        filename.endsWith('.py') ? python() : yaml(),
        EditorView.lineWrapping,
        EditorView.contentAttributes.of({ 'aria-label': `Source code for ${filename}` }),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) change.current(update.state.doc.toString());
        }),
        EditorView.theme({
          '&': { height: '420px', fontSize: '13px' },
          '.cm-scroller': { overflow: 'auto' },
        }),
      ],
    });
    return () => view.destroy();
  }, [filename]);
  return <div className="editor" ref={target} inert={disabled} aria-label={`Edit ${filename}`} />;
}
