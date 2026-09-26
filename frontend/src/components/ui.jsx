import { useEffect, useId, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

/* ------------------------------------------------------------------ formatting */

export const shortWallet = (w) => (w && w.length > 12 ? `${w.slice(0, 6)}…${w.slice(-4)}` : w || '');
export const shortHash = (h) => (h && h.length > 20 ? `${h.slice(0, 10)}…${h.slice(-8)}` : h || '');

export function formatDate(value, withTime = true) {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  const date = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  return withTime ? `${date}, ${d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}` : date;
}

export const errorText = (err, fallback = 'The request failed.') =>
  err?.response?.data?.detail
    ? (typeof err.response.data.detail === 'string' ? err.response.data.detail : JSON.stringify(err.response.data.detail))
    : err?.message || fallback;

/* ------------------------------------------------------------------ status vocabulary */

const TONES = {
  APPROVED: 'clear', ACTIVE: 'clear', MINTED: 'clear', ANCHORED: 'clear', COMPLETED: 'clear', VERIFIED: 'clear',
  CREATED: 'info', ASSIGNED: 'info', IN_SERVICE: 'info', OPEN: 'info',
  PENDING: 'caution', PENDING_APPROVAL: 'caution', AUDITOR_REVIEW: 'caution', MANAGER_REVIEW: 'caution', MAINTENANCE: 'caution',
  ADMIN_REVIEW: 'alert', REJECTED: 'alert', REVOKED: 'alert', EXPIRED: 'neutral', RETIRED: 'neutral', OBSOLETE: 'neutral',
  DISMISSED: 'neutral', IDENTITY_REVOKED: 'alert', HIGH: 'alert', CRITICAL: 'alert', MEDIUM: 'caution', LOW: 'clear',
  DECOMMISSIONED: 'neutral', LOST: 'alert', DISABLED: 'alert',
};

const LABELS = {
  PENDING_APPROVAL: 'Pending approval', AUDITOR_REVIEW: 'Auditor review', MANAGER_REVIEW: 'Manager review',
  ADMIN_REVIEW: 'Admin review', IDENTITY_REVOKED: 'Identity revoked', IN_SERVICE: 'In service',
};

export const statusLabel = (s) => LABELS[s] || (s ? s.charAt(0) + s.slice(1).toLowerCase().replace(/_/g, ' ') : '');

export function Status({ value, tone, children }) {
  if (!value && !children) return null;
  return <span className={`tag ${tone || TONES[value] || 'neutral'}`}>{children || statusLabel(value)}</span>;
}

/* ------------------------------------------------------------------ primitives */

export function Button({ variant = 'secondary', size, block, className = '', busy, children, ...rest }) {
  const cls = ['btn', `btn-${variant}`, size === 'sm' && 'btn-sm', block && 'btn-block', className].filter(Boolean).join(' ');
  return (
    <button type="button" className={cls} disabled={busy || rest.disabled} aria-busy={busy || undefined} {...rest}>
      {busy && <span className="spinner" aria-hidden="true" />}
      {children}
    </button>
  );
}

export function Field({ label, hint, error, children, className = '' }) {
  return (
    <label className={`field ${className}`}>
      <span>{label}</span>
      {children}
      {hint && !error && <span className="hint">{hint}</span>}
      {error && <span className="error-text" role="alert">{error}</span>}
    </label>
  );
}

export function Id({ children, title }) {
  return <span className="id" title={title || (typeof children === 'string' ? children : undefined)}>{children}</span>;
}

export function Notice({ tone = 'info', title, children }) {
  if (!title && !children) return null;
  return (
    <div className={`notice ${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      {title && <strong>{title}</strong>}
      {children && <div>{children}</div>}
    </div>
  );
}

export function Panel({ title, aside, children, flush, id }) {
  return (
    <section className="panel" aria-labelledby={title ? `${id || title}-h` : undefined}>
      {(title || aside) && (
        <div className="panel-head">
          {title && <h2 id={`${id || title}-h`}>{title}</h2>}
          {aside && <div className="aside">{aside}</div>}
        </div>
      )}
      <div className={`panel-body${flush ? ' flush' : ''}`}>{children}</div>
    </section>
  );
}

export function Loading({ label = 'Loading' }) {
  return <div className="loading" role="status"><span className="spinner" aria-hidden="true" />{label}…</div>;
}

export function Empty({ title, children }) {
  return <div className="empty"><strong>{title}</strong>{children && <div>{children}</div>}</div>;
}

export function Facts({ items }) {
  const rows = items.filter(([, v]) => v !== undefined && v !== null && v !== '');
  return (
    <dl className="facts">
      {rows.map(([k, v]) => (
        <FactRow key={k} k={k} v={v} />
      ))}
    </dl>
  );
}
function FactRow({ k, v }) {
  return (<><dt>{k}</dt><dd>{v}</dd></>);
}

/**
 * Register: a records table that collapses into stacked labelled records on phones.
 * columns: [{ key, label, render?(row), className? }]
 */
export function Register({ columns, rows, rowKey, onRowClick, empty, foot, caption }) {
  if (!rows) return <Loading />;
  if (rows.length === 0) return empty || <Empty title="No records" />;
  return (
    <>
      <div className="register-wrap">
        <table className="register">
          {caption && <caption className="sr-only">{caption}</caption>}
          <thead>
            <tr>{columns.map((c) => <th key={c.key} scope="col" className={c.className}>{c.label}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={rowKey ? rowKey(r) : i} className={onRowClick ? 'selectable' : undefined}
                onClick={onRowClick ? () => onRowClick(r) : undefined}>
                {columns.map((c) => (
                  <td key={c.key} data-label={c.label} className={c.className}>
                    {c.render ? c.render(r) : r[c.key]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {foot && <div className="register-foot">{foot}</div>}
    </>
  );
}

/* ------------------------------------------------------------------ dialogs */

export function Dialog({ title, onClose, children, footer, wide, danger, labelledBy }) {
  const ref = useRef(null);
  const id = useId();
  useEffect(() => {
    const prev = document.activeElement;
    const first = ref.current?.querySelector('input, select, textarea, button:not(.close)');
    (first || ref.current)?.focus();
    const onKey = (e) => { if (e.key === 'Escape') onClose?.(); };
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('keydown', onKey); prev?.focus?.(); };
  }, [onClose]);
  return (
    <div className="dialog-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose?.(); }}>
      <div ref={ref} className={`dialog${wide ? ' wide' : ''}${danger ? ' danger' : ''}`} role="dialog" aria-modal="true"
        aria-labelledby={labelledBy || id} tabIndex={-1}>
        <div className="dialog-head">
          <h2 id={labelledBy || id}>{title}</h2>
          {onClose && <Button variant="quiet" size="sm" className="close" onClick={onClose} aria-label="Close">Close</Button>}
        </div>
        <div className="dialog-body">{children}</div>
        {footer && <div className="dialog-foot">{footer}</div>}
      </div>
    </div>
  );
}

/**
 * Collects the factor for ONE purpose-bound action: either a 6-digit code from the
 * purpose's authenticator (TOTP 2 / TOTP 3) or the purpose's passkey. The dialog does
 * not decide authorization; the server verifies the factor for exactly this action.
 */
export function StepUpDialog({ factor, actionLabel, onSubmit, onClose, extra, confirmLabel = 'Confirm', danger }) {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const name = factor === 'factor3' ? 'Factor 3 (approve, mint, modify, download)' : 'Factor 2 (view and submit)';
  const submit = async (method) => {
    setBusy(true); setError('');
    try { await onSubmit(method === 'passkey' ? null : code.trim()); }
    catch (err) { setError(errorText(err)); setBusy(false); }
  };
  return (
    <Dialog title={actionLabel} onClose={busy ? undefined : onClose} danger={danger}
      footer={<>
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button variant="secondary" busy={busy} onClick={() => submit('passkey')}>Use {factor === 'factor3' ? 'Passkey 3' : 'Passkey 2'}</Button>
        <Button variant={danger ? 'danger' : 'primary'} busy={busy} disabled={code.length !== 6} onClick={() => submit('code')}>{confirmLabel}</Button>
      </>}>
      {extra}
      <p className="muted small">This action requires {name}. Enter the current code from that authenticator, or use its passkey.</p>
      <Field label={`${factor === 'factor3' ? 'Factor 3' : 'Factor 2'} authenticator code`}>
        <input className="input mono" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
          onKeyDown={(e) => { if (e.key === 'Enter' && code.length === 6) submit('code'); }} />
      </Field>
      {error && <Notice tone="error">{error}</Notice>}
    </Dialog>
  );
}

/* ------------------------------------------------------------------ page scaffolding */

export function PageHeader({ crumbs = [], title, lede, actions, ribbon }) {
  return (
    <header className="page-head">
      <div className="page-head-inner">
        <div>
          {crumbs.length > 0 && (
            <nav className="crumbs" aria-label="Breadcrumb">
              {crumbs.map(([label, to], i) => (
                <span key={label} className="row" style={{ gap: 8 }}>
                  {to ? <Link to={to}>{label}</Link> : <span aria-current="page">{label}</span>}
                  {i < crumbs.length - 1 && <span className="sep" aria-hidden="true">/</span>}
                </span>
              ))}
            </nav>
          )}
          <h1 className="page-title">{title}</h1>
          {lede && <p className="page-lede">{lede}</p>}
        </div>
        {actions && <div className="page-actions">{actions}</div>}
      </div>
      {ribbon && ribbon.length > 0 && (
        <div className="ribbon" aria-label="Operational status">
          {ribbon.filter(Boolean).map((item, i) => (
            <div key={i} className={`ribbon-item${item.warn ? ' warn' : ''}`}>{item.content}</div>
          ))}
        </div>
      )}
    </header>
  );
}

export function useAsync(fn, deps) {
  const [state, setState] = useState({ data: null, error: '', loading: true });
  const run = async () => {
    setState((s) => ({ ...s, loading: true }));
    try { setState({ data: await fn(), error: '', loading: false }); }
    catch (err) { setState({ data: null, error: errorText(err), loading: false }); }
  };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { run(); }, deps);
  return { ...state, reload: run };
}

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}
