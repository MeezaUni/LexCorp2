import { useMemo, useState } from 'react';
import { Button, Dialog, Empty, Facts, Field, Id, Notice, PageHeader, Panel, Register, Status, StepUpDialog, errorText, formatDate, useAsync } from '../components/ui';
import { refreshCounts, roleName } from '../components/Shell';
import { humanEvent } from './Dashboard';
import { useAuth } from '../context/AuthContext';
import * as api from '../services/api';
import ProtectedViewer from '../components/ProtectedViewer';

const STAGE = { AUDITOR: 'AUDITOR_REVIEW', MANAGER: 'MANAGER_REVIEW', ADMIN: 'ADMIN_REVIEW' };
const NEXT = { AUDITOR: 'the Manager of the department', MANAGER: 'an Administrator' };
const SOURCE = { AI: 'AI-assisted risk analysis', RULE: 'Integrity or security rule', LEGACY: 'Imported event' };

export default function Alerts() {
  const { user } = useAuth();
  const [tick, setTick] = useState(0);
  const { data, error } = useAsync(api.listAlerts, [tick]);
  const [scope, setScope] = useState('mine');
  const [open, setOpen] = useState(null);
  const [message, setMessage] = useState('');
  const stage = STAGE[user.role];

  const rows = useMemo(() => {
    if (!data) return null;
    if (scope === 'mine') return data.filter((a) => a.state === stage);
    if (scope === 'open') return data.filter((a) => ['AUDITOR_REVIEW', 'MANAGER_REVIEW', 'ADMIN_REVIEW'].includes(a.state));
    return data;
  }, [data, scope, stage]);
  const reload = () => { setTick((t) => t + 1); refreshCounts(); };

  return (
    <>
      <PageHeader crumbs={[['Dashboard', '/'], ['Security alerts']]} title="Security alerts"
        lede="High-risk events raised by AI-assisted analysis or by deterministic rules. People decide: an Auditor reviews first, then the department Manager, then an Administrator."
        ribbon={data && [
          { content: <>Your stage: <strong>{roleName(user.role)} review</strong></> },
          { content: <><strong>{data.filter((a) => a.state === stage).length}</strong> waiting for you</>, warn: data.some((a) => a.state === stage) },
          { content: <><strong>{data.filter((a) => a.state === 'ADMIN_REVIEW').length}</strong> escalated to Administrators</> },
        ]} />
      <div className="content">
        {error && <Notice tone="error">{error}</Notice>}
        {message && <Notice tone="success" title="Recorded">{message}</Notice>}
        <Panel flush aside={null}>
          <div className="filters">
            <div className="segmented" role="group" aria-label="Which alerts">
              {[['mine', 'Waiting for me'], ['open', 'All open'], ['all', 'All visible']].map(([k, l]) => (
                <button key={k} type="button" aria-pressed={scope === k} onClick={() => setScope(k)}>{l}</button>
              ))}
            </div>
          </div>
          <Register rows={rows} rowKey={(a) => a.alert_id} onRowClick={setOpen}
            empty={<Empty title={scope === 'mine' ? 'No alerts are waiting for your review' : 'No alerts to show'}>Alerts in other stages or departments are not shown.</Empty>}
            columns={[
              { key: 'id', label: 'Alert', render: (a) => <Id>{a.alert_id}</Id> },
              { key: 'r', label: 'Severity', render: (a) => <Status value={a.risk_level}>{a.risk_level === 'CRITICAL' ? 'Critical' : a.risk_level === 'HIGH' ? 'High' : a.risk_level}</Status> },
              { key: 'w', label: 'Subject', render: (a) => <><strong>{a.subject.name || 'Unknown identity'}</strong><div className="small muted">{a.subject.role ? roleName(a.subject.role) : '—'}{a.subject.department ? `, ${a.subject.department}` : ''}</div></> },
              { key: 'e', label: 'Event', render: (a) => <>{humanEvent(a.event_type)}{a.asset_serial && <div className="small"><Id>{a.asset_serial}</Id></div>}</> },
              { key: 's', label: 'Raised by', render: (a) => SOURCE[a.source] || a.source },
              { key: 'st', label: 'Escalation', render: (a) => <Status value={a.state} /> },
              { key: 't', label: 'Raised', render: (a) => formatDate(a.created_at) },
            ]} />
        </Panel>
      </div>
      {open && <AlertDetail alert={open} user={user} onClose={() => setOpen(null)} onDone={(m) => { setOpen(null); setMessage(m); reload(); }} />}
    </>
  );
}

function AlertDetail({ alert, user, onClose, onDone }) {
  const { data: full } = useAsync(() => api.getAlert(alert.alert_id), [alert.alert_id]);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [revoking, setRevoking] = useState(false);
  const mine = alert.state === STAGE[user.role];
  const self = alert.subject.did === user.did;

  const act = async (kind) => {
    setBusy(kind); setError('');
    try {
      if (kind === 'dismiss') { await api.dismissAlert(alert.alert_id, note); onDone(`${alert.alert_id} dismissed as a false alarm.`); }
      else { await api.forwardAlert(alert.alert_id, note); onDone(`${alert.alert_id} forwarded to ${NEXT[user.role]}.`); }
    } catch (err) { setError(errorText(err)); setBusy(''); }
  };

  return (
    <>
      <Dialog title={`Alert ${alert.alert_id}`} wide danger={alert.risk_level === 'CRITICAL'} onClose={onClose}
        footer={mine && !self ? <>
          <Button onClick={onClose}>Close</Button>
          <Button busy={busy === 'dismiss'} disabled={!note.trim()} onClick={() => act('dismiss')}>Dismiss as false alarm</Button>
          {user.role !== 'ADMIN' && <Button variant="primary" busy={busy === 'forward'} onClick={() => act('forward')}>Forward to {user.role === 'AUDITOR' ? 'Manager' : 'Administrator'}</Button>}
          {user.role === 'ADMIN' && <Button variant="danger" disabled={!note.trim()} onClick={() => setRevoking(true)}>Revoke identity</Button>}
        </> : <>
          <Button onClick={onClose}>Close</Button>
          {user.role === 'ADMIN' && alert.state === 'MANAGER_REVIEW' && !self && (
            <Button variant="primary" busy={busy === 'take'} onClick={async () => {
              setBusy('take'); setError('');
              try { await api.forwardAlert(alert.alert_id, note || 'Taken over: no independent manager covers this department'); onDone(`${alert.alert_id} moved to Administrator review.`); }
              catch (err) { setError(errorText(err)); setBusy(''); }
            }}>Take over (no independent manager)</Button>
          )}
        </>}>
        {self && <Notice tone="warning">This alert concerns your own identity. Another reviewer must decide.</Notice>}
        {!mine && !self && <Notice tone="info">This alert is at the {alert.state.replace('_', ' ').toLowerCase()} stage. You can read it but not act on it.</Notice>}
        {error && <Notice tone="error">{error}</Notice>}
        <Facts items={[
          ['Severity', <Status key="r" value={alert.risk_level} />],
          ['Risk score', alert.risk_score != null ? Number(alert.risk_score).toFixed(2) : undefined],
          ['Raised by', SOURCE[alert.source] || alert.source],
          ['Reason', alert.reason],
          ['Event', humanEvent(alert.event_type)],
          ['Subject', `${alert.subject.name || 'Unknown'}${alert.subject.role ? `, ${roleName(alert.subject.role)}` : ''}`],
          ['Subject wallet', alert.subject.wallet && <Id key="w">{alert.subject.wallet}</Id>],
          ['Department', alert.subject.department],
          ['Asset', alert.asset_serial && <Id key="a">{alert.asset_serial}</Id>],
          ['Related action', alert.related_action_id && <Id key="x">{alert.related_action_id}</Id>],
          ['Network address', alert.client_ip],
          ['Identity status', alert.subject.is_active === false ? 'Revoked or disabled' : alert.subject.is_active ? 'Active' : undefined],
          ['Current stage', <Status key="s" value={alert.state} />],
        ]} />
        {full?.evidence && <TamperEvidence alertId={alert.alert_id} evidence={full.evidence} />}
        {alert.source === 'AI' && <p className="small muted">The AI model scores behaviour against learned patterns. Its score is advice only; it never blocks, forwards or revokes anything by itself.</p>}
        <h3>Escalation history</h3>
        {full ? (
          <ul className="timeline" style={{ border: '1px solid var(--rule)', borderRadius: 4 }}>
            {full.history.map((h, i) => (
              <li key={i}><time dateTime={h.at}>{formatDate(h.at)}</time>
                <div><strong>{h.action.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase())}</strong>
                  <span className="muted"> {h.from ? `${h.from.replace('_', ' ').toLowerCase()} to ` : ''}{h.to.replace('_', ' ').toLowerCase()}{h.actor_role ? `, by ${roleName(h.actor_role)}` : ''}</span>
                  {h.note && <div className="small">“{h.note}”</div>}</div></li>
            ))}
          </ul>
        ) : <Empty title="Loading history" />}
        {mine && !self && <Field label={user.role === 'ADMIN' ? 'Decision note (required to dismiss or revoke)' : 'Note (required to dismiss; optional when forwarding)'}>
          <textarea className="textarea" value={note} onChange={(e) => setNote(e.target.value)} /></Field>}
      </Dialog>
      {revoking && (
        <StepUpDialog factor="factor3" danger actionLabel={`Revoke the identity of ${alert.subject.name || 'this user'}`} confirmLabel="Revoke identity"
          onClose={() => setRevoking(false)}
          extra={<Notice tone="error" title="This cannot be undone from this screen">All of the identity's sessions end immediately, they cannot sign in again, and their ledger roles are removed. Their history is kept.</Notice>}
          onSubmit={async (code) => {
            const token = await api.stepUp('identity.revoke', code);
            await api.revokeFromAlert(alert.alert_id, note, token);
            setRevoking(false);
            onDone(`Identity revoked from ${alert.alert_id}.`);
          }} />
      )}
    </>
  );
}

/** For a watermark tamper alert: the watermark as recorded when the copy was issued, what was
 *  found in the returned file (with where), and the uploaded file itself, opened at the flagged page. */
function TamperEvidence({ alertId, evidence }) {
  const [view, setView] = useState(null);
  const [error, setError] = useState('');
  const open = async (page) => {
    setError('');
    try { setView({ ...(await api.alertEvidence(alertId)), page }); } catch (err) { setError(await api.blobError(err)); }
  };
  const tamper = evidence.findings.filter((f) => f.severity === 'tamper');
  const review = evidence.findings.filter((f) => f.severity !== 'tamper');
  return (
    <>
      <h3>Watermark evidence</h3>
      <p className="small muted">Revision {evidence.modification_id} was made from the copy downloaded as {evidence.download_id}. The uploader was not told about this check.</p>
      {error && <Notice tone="error">{error}</Notice>}
      <div className="grid-2">
        <div className="stack">
          <strong className="small">Watermark as issued (the record)</strong>
          <pre className="evidence-record">{evidence.recorded_watermark || 'Not recorded'}</pre>
        </div>
        <div className="stack">
          <strong className="small">What was found in the returned file</strong>
          <ul className="evidence-findings">
            {tamper.map((f, i) => (
              <li key={`t${i}`}><Status value="HIGH">Changed</Status> <strong>{f.where}</strong>: {f.detail}
                {f.page && evidence.has_file && <> <Button size="sm" variant="quiet" onClick={() => open(f.page)}>Go to page {f.page}</Button></>}</li>
            ))}
            {review.map((f, i) => <li key={`r${i}`}><Status value="PENDING">Check</Status> <strong>{f.where}</strong>: {f.detail}</li>)}
          </ul>
          {evidence.has_file && <div><Button onClick={() => open(null)}>Open the uploaded file</Button></div>}
        </div>
      </div>
      {view && (
        <Dialog title={`Uploaded file${view.page ? `, page ${view.page}` : ''} (${evidence.filename || 'evidence'})`} wide onClose={() => setView(null)}>
          <ProtectedViewer blob={view.blob} type={view.type} focusPage={view.page} label="Uploaded revision file" />
          <p className="small muted">This is the file exactly as it was uploaded, shown view-only and watermarked for you ({view.actionId}). {view.page ? 'The flagged page is outlined.' : ''}</p>
        </Dialog>
      )}
    </>
  );
}
