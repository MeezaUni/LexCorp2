import { useEffect, useId, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import * as api from '../services/api';

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
  err?.name === 'NotAllowedError'
    ? 'The passkey prompt was cancelled, timed out, or no passkey on this device belongs to that identity and purpose.'
    : err?.name === 'InvalidStateError'
      ? 'This device already holds a passkey for that identity and purpose.'
      : err?.response?.data?.detail
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
  // Parents often pass a new onClose function on every render. Keep the latest one in a ref so
  // the focus effect below runs only when the dialog opens; re-running it on each parent render
  // pulled the cursor back to the first field while the person was typing elsewhere.
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const prev = document.activeElement;
    const first = ref.current?.querySelector('input, select, textarea, button:not(.close)');
    (first || ref.current)?.focus();
    const onKey = (e) => { if (e.key === 'Escape') closeRef.current?.(); };
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('keydown', onKey); prev?.focus?.(); };
  }, []);
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
  const { user } = useAuth();
  // A purpose the person set to reuse their login factors is proven with the login authenticator/passkey.
  const viaLogin = factor === 'login' || Boolean(user?.[`${factor}_uses_login`]);
  const name = factor === 'login' ? 'your login factor'
    : factor === 'factor3' ? 'Factor 3 (approve, mint, modify, download)' : 'Factor 2 (view and submit)';
  const source = viaLogin ? 'login authenticator (TOTP 1)' : `${factor === 'factor3' ? 'Factor 3' : 'Factor 2'} authenticator`;
  const passkeyName = viaLogin ? 'login passkey' : factor === 'factor3' ? 'Passkey 3' : 'Passkey 2';
  const submit = async (method) => {
    setBusy(true); setError('');
    try { await onSubmit(method === 'passkey' ? null : code.trim()); }
    catch (err) { setError(errorText(err)); setBusy(false); }
  };
  if ((factor === 'factor2' || factor === 'factor3') && user && user[`${factor}_ready`] === false) {
    return <FactorSetupFirst factor={factor} onClose={onClose} />;
  }
  return (
    <Dialog title={actionLabel} onClose={busy ? undefined : onClose} danger={danger}
      footer={<>
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button variant="secondary" busy={busy} onClick={() => submit('passkey')}>Use {passkeyName}</Button>
        <Button variant={danger ? 'danger' : 'primary'} busy={busy} disabled={code.length !== 6} onClick={() => submit('code')}>{confirmLabel}</Button>
      </>}>
      {extra}
      <p className="muted small">This action requires {name}{viaLogin && factor !== 'login' ? ', which you set to use your login factors' : ''}. Enter the current code from your {source}, or use your {passkeyName}.</p>
      <Field label={`Code from your ${source}`}>
        <input className="input mono" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
          onKeyDown={(e) => { if (e.key === 'Enter' && code.length === 6) submit('code'); }} />
      </Field>
      {error && <Notice tone="error">{error}</Notice>}
    </Dialog>
  );
}

/**
 * Shown instead of the factor prompt when the action's factor isn't set up yet: turn on
 * "use my login factors" right here (proven with the login factor), or go set up separate
 * factors in My identity. Once set, the original prompt appears.
 */
function FactorSetupFirst({ factor, onClose }) {
  const { refresh } = useAuth();
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const n = factor === 'factor3' ? 3 : 2;
  const link = async (method) => {
    setBusy(true); setError('');
    try {
      const token = await api.stepUp(`${factor}.link`, method === 'passkey' ? null : code.trim());
      await api.useLoginFactorsFor(factor, token);
      await refresh();
    } catch (err) { setError(errorText(err)); setBusy(false); }
  };
  return (
    <Dialog title={`Set up Factor ${n} first`} onClose={busy ? undefined : onClose}
      footer={<>
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button variant="secondary" busy={busy} onClick={() => link('passkey')}>Use login passkey</Button>
        <Button variant="primary" busy={busy} disabled={code.length !== 6} onClick={() => link('code')}>Use my login factors</Button>
      </>}>
      <p className="small">This action needs Factor {n} ({factor === 'factor3' ? 'approve, mint, modify, download' : 'view and submit'}), which you haven't set up yet.</p>
      <p className="small muted">Quickest: confirm Factor {n} actions with the same authenticator code and passkey you sign in with. Enter your login authenticator code (or use your login passkey) to turn this on, then carry on. For separate, stronger factors, go to <Link to="/identity" onClick={onClose}>My identity</Link> instead.</p>
      <Field label="Code from your login authenticator (TOTP 1)">
        <input className="input mono" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
          onKeyDown={(e) => { if (e.key === 'Enter' && code.length === 6) link('code'); }} />
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
