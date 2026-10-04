import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Facts, Id, Register, Status, formatDate } from './ui';

/** Verify an asset: Auditors get the detailed check in Verification, everyone else the verify page
 * that the asset's QR opens. */
export function VerifyAssetButton({ serial, size }) {
  const { user } = useAuth();
  const cls = `btn btn-secondary${size === 'sm' ? ' btn-sm' : ''}`;
  const stop = (e) => e.stopPropagation();
  if (user?.role === 'AUDITOR') {
    return <Link className={cls} to={`/verification?serial=${encodeURIComponent(serial)}`} onClick={stop}>Verify</Link>;
  }
  return <a className={cls} href={`/verify/${encodeURIComponent(serial)}`} target="_blank" rel="noopener noreferrer" onClick={stop}>Verify</a>;
}

const RESULT = {
  match: ['clear', 'Matches'],
  differs: ['alert', 'Contradicts'],
  not_on_record: ['alert', 'Not on record'],
  unavailable: ['neutral', 'Not available'],
};
const GROUP = { record: 'Record', watermark: 'Visible watermark', hash: 'File hash', hidden: 'Invisible mark', ledger: 'Ledger' };
const show = (v) => (v === null || v === undefined || v === '' ? <span className="muted">—</span> : <Id>{String(v)}</Id>);

/** Every check a verification ran: what the record says, what the copy (or ledger) shows, and why. */
export function VerificationChecks({ checks, foundLabel = 'In the copy' }) {
  if (!checks?.length) return null;
  return (
    <Register rows={checks} rowKey={(c) => c.key}
      columns={[
        { key: 'c', label: 'Check', render: (c) => <><strong>{c.label}</strong><div className="small muted">{GROUP[c.group] || c.group}</div></> },
        { key: 'e', label: 'On record', render: (c) => show(c.expected) },
        { key: 'f', label: foundLabel, render: (c) => show(c.found) },
        { key: 'r', label: 'Result', render: (c) => { const [tone, text] = RESULT[c.result] || ['neutral', c.result]; return <Status tone={tone}>{text}</Status>; } },
        { key: 'w', label: 'Why', render: (c) => <span className="small">{c.reason || (c.result === 'match' ? 'Same as the record.' : '')}</span> },
      ]} />
  );
}

/** One line per contradiction, in words. */
export function Contradictions({ checks }) {
  const bad = (checks || []).filter((c) => c.result === 'differs' || c.result === 'not_on_record');
  if (!bad.length) return null;
  return <ul className="stack small" style={{ margin: 0, paddingLeft: 18 }}>{bad.map((c) => <li key={c.key}><strong>{c.label}:</strong> {c.reason}</li>)}</ul>;
}

/** Who a copy was issued to, when and from where. */
export function IssuedCopy({ copy }) {
  if (!copy) return null;
  return (
    <Facts items={[
      ['Reference', copy.action_id && <Id key="a">{copy.action_id}</Id>],
      ['Kind', copy.action_type && copy.action_type.toLowerCase()],
      ['Issued to', copy.issued_to && <span key="t">{copy.issued_to} {copy.issued_to_wallet && <Id>{copy.issued_to_wallet}</Id>}</span>],
      ['Issued', copy.issued_at && formatDate(copy.issued_at)],
      ['Network address', copy.client_ip],
      ['Document', copy.asset_serial && <span key="s"><Id>{copy.asset_serial}</Id> version {copy.asset_version}</span>],
      ['Issued copy SHA-256', copy.copy_sha256 && <Id key="h">{copy.copy_sha256}</Id>],
      ['Invisible mark', copy.hidden_mark_recorded === undefined ? undefined : copy.hidden_mark_recorded ? 'Recorded for this copy' : 'Not recorded (older copy)'],
    ]} />
  );
}
