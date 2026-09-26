import { useEffect, useRef, useState } from 'react';
import * as pdfjs from 'pdfjs-dist';
import workerSrc from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import { Loading, Notice } from './ui';

pdfjs.GlobalWorkerOptions.workerSrc = workerSrc;

/**
 * Shows a watermarked view copy as pictures of its pages: no browser PDF toolbar, so no
 * save, print or download buttons, no selectable text, and no right-click "Save image".
 * The page also blocks Ctrl/Cmd+S and Ctrl/Cmd+P and prints blank while it's open.
 * This removes the easy ways out; it can't stop a screenshot or a camera, which is why
 * every view carries the viewer's name, wallet, IP, time and View ID.
 */
export default function ProtectedViewer({ blob, type, label }) {
  const host = useRef(null);
  const [state, setState] = useState({ loading: true, error: '', pages: 0 });

  useEffect(() => {
    const block = (e) => {
      if ((e.ctrlKey || e.metaKey) && ['s', 'p'].includes(e.key.toLowerCase())) e.preventDefault();
    };
    window.addEventListener('keydown', block, true);
    document.body.classList.add('protected-view-open');
    return () => { window.removeEventListener('keydown', block, true); document.body.classList.remove('protected-view-open'); };
  }, []);

  useEffect(() => {
    let cancelled = false;
    let doc = null;
    const target = host.current;
    const width = () => Math.min(target.clientWidth || 900, 1100);
    const addCanvas = () => {
      const c = document.createElement('canvas');
      c.setAttribute('aria-hidden', 'true');
      target.appendChild(c);
      return c;
    };
    (async () => {
      try {
        target.replaceChildren();
        const ratio = window.devicePixelRatio || 1;
        if (type.startsWith('image/')) {
          const bitmap = await createImageBitmap(blob);
          if (cancelled) return;
          const c = addCanvas();
          const scale = width() / bitmap.width;
          c.width = Math.round(bitmap.width * scale * ratio);
          c.height = Math.round(bitmap.height * scale * ratio);
          c.style.width = `${Math.round(bitmap.width * scale)}px`;
          c.getContext('2d').drawImage(bitmap, 0, 0, c.width, c.height);
          setState({ loading: false, error: '', pages: 1 });
          return;
        }
        doc = await pdfjs.getDocument({ data: new Uint8Array(await blob.arrayBuffer()), isEvalSupported: false }).promise;
        if (cancelled) return;
        setState({ loading: false, error: '', pages: doc.numPages });
        for (let n = 1; n <= doc.numPages && !cancelled; n += 1) {
          const page = await doc.getPage(n);
          const base = page.getViewport({ scale: 1 });
          const viewport = page.getViewport({ scale: (width() / base.width) * ratio });
          const c = addCanvas();
          c.width = Math.floor(viewport.width);
          c.height = Math.floor(viewport.height);
          c.style.width = `${Math.floor(viewport.width / ratio)}px`;
          await page.render({ canvasContext: c.getContext('2d'), viewport }).promise;
        }
      } catch {
        if (!cancelled) setState({ loading: false, error: 'This view copy could not be displayed.', pages: 0 });
      }
    })();
    return () => { cancelled = true; doc?.destroy(); };
  }, [blob, type]);

  return (
    <div className="protected-viewer" onContextMenu={(e) => e.preventDefault()} onDragStart={(e) => e.preventDefault()}
      role="document" aria-label={label}>
      {state.loading && <Loading />}
      {state.error && <Notice tone="error">{state.error}</Notice>}
      {state.pages > 1 && <p className="small muted">{state.pages} pages. Scroll to read.</p>}
      <div ref={host} className="protected-pages" />
    </div>
  );
}
