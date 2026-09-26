import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Button, Empty, Facts, Field, Id, Notice, PageHeader, Panel, Register, Status, StepUpDialog, formatDate, shortWallet, useAsync } from '../components/ui';
import { refreshCounts } from '../components/Shell';
import { RequestActions, RequestState } from './DigitalAssetDetail';
import { useAuth } from '../context/AuthContext';
import * as api from '../services/api';
import { signAndConfirm } from '../services/chainActions';

const KIND = {
  CREATION: 'New registration', MODIFICATION: 'Revision', SHARE: 'Access delegation', DOWNLOAD: 'Download',
};
const walletOf = (did) => shortWallet(did?.split(':').pop());
const assetPath = (a) => `/${a.is_physical ? 'physical' : 'digital'}/${encodeURIComponent(a.asset_serial)}`;

export default function Requests() {
  const { user, canApprove, getSigner } = useAuth();
  const [tick, setTick] = useState(0);
  const reload = () => { setTick((t) => t + 1); refreshCounts(); };
  const queue = useAsync(async () => {
    if (!canApprove) return [];
    const [docs, phys, dls] = await Promise.all([api.pendingDocuments(), api.pendingPhysical(), api.pendingDownloads()]);
    const byId = new Map();
    for (const a of [
      ...docs.filter((x) => x.action_type !== 'DOWNLOAD').map((x) => ({ ...x, is_physical: false })),
      ...phys.map((x) => ({ ...x, is_physical: true })),
      ...dls.filter((x) => !x.details?.requires_owner_approval || x.details?.owner_approved_by).map((x) => ({ ...x, is_physical: false })),
    ]) byId.set(a.action_id, a);
    return [...byId.values()].sort((x, y) => new Date(x.created_at) - new Date(y.created_at));
  }, [tick, canApprove]);
  const consents = useAsync(async () => (await api.pendingDownloads())
    .filter((a) => a.details?.requires_owner_approval && !a.details?.owner_approved_by && a.actor_did !== user.did), [tick]);
  const mine = useAsync(api.myDownloads, [tick]);
  const [review, setReview] = useState(null);
  const [consent, setConsent] = useState(null);
  const [message, setMessage] = useState('');
  const [warning, setWarning] = useState('');

  return (
    <>
      <PageHeader crumbs={[['Dashboard', '/'], [canApprove ? 'Requests & approvals' : 'My requests']]}
        title={canApprove ? 'Requests and approvals' : 'My requests'}
        lede={canApprove ? 'Decisions need your Factor 3. You cannot decide on requests you submitted yourself.' : 'Downloads and modification copies you requested, and requests that need your consent as owner.'}
        ribbon={[
          canApprove && { content: <><strong>{queue.data?.length ?? '…'}</strong> awaiting your decision</> },
          { content: <><strong>{consents.data?.length ?? '…'}</strong> need your consent as owner</> },
          { content: <><strong>{(mine.data || []).filter((a) => a.status === 'APPROVED').length}</strong> approved and ready to download</> },
        ]} />
      <div className="content">
        {message && <Notice tone="success" title="Done">{message}</Notice>}
        {warning && <Notice tone="warning" title="Approved, but the ledger step did not finish">{warning}</Notice>}
        {canApprove && (
          <Panel title="Awaiting your decision" flush>
            <Register rows={queue.data} rowKey={(a) => a.action_id}
              empty={<Empty title="Nothing is waiting for you">New requests in your departments appear here.</Empty>}
              columns={[
                { key: 'id', label: 'Request', render: (a) => <Id>{a.action_id}</Id> },
                { key: 'k', label: 'Type', render: (a) => <>{KIND[a.action_type] || a.action_type}{a.is_physical && <div className="small muted">Physical asset</div>}{a.details?.mode === 'MODIFICATION' && <div className="small muted">Modification copy</div>}</> },
                { key: 'as', label: 'Asset', render: (a) => <Link to={assetPath(a)} onClick={(e) => e.stopPropagation()}><Id>{a.asset_serial}</Id></Link> },
                { key: 'by', label: 'Requested by', render: (a) => a.actor_did === user.did ? <span className="muted">You</span> : <Id>{walletOf(a.actor_did)}</Id> },
                { key: 'p', label: 'Purpose', render: (a) => a.purpose || '—' },
                { key: 'w', label: 'Submitted', render: (a) => formatDate(a.created_at) },
                { key: 'x', label: '', className: 'actions', render: (a) => a.actor_did === user.did
                  ? <span className="small muted">Another approver must decide</span>
                  : <Button size="sm" variant="primary" onClick={() => setReview(a)}>Review</Button> },
              ]} />
          </Panel>
        )}
        <Panel title="Download requests for documents you own" flush>
          <Register rows={consents.data} rowKey={(a) => a.action_id}
            empty={<Empty title="No requests need your consent" />}
            columns={[
              { key: 'id', label: 'Request', render: (a) => <Id>{a.action_id}</Id> },
              { key: 'as', label: 'Document', render: (a) => <Link to={`/digital/${encodeURIComponent(a.asset_serial)}`}><Id>{a.asset_serial}</Id></Link> },
              { key: 'm', label: 'Kind', render: (a) => (a.details?.mode === 'MODIFICATION' ? 'Modification copy' : 'Download') },
              { key: 'by', label: 'Requested by', render: (a) => <Id>{walletOf(a.actor_did)}</Id> },
              { key: 'p', label: 'Purpose', render: (a) => a.purpose || '—' },
              { key: 'x', label: '', className: 'actions', render: (a) => <>
                <Button size="sm" variant="primary" onClick={() => setConsent({ a, decision: 'APPROVE' })}>Consent</Button>
                <Button size="sm" onClick={() => setConsent({ a, decision: 'REJECT' })}>Refuse</Button>
              </> },
            ]} />
        </Panel>
        <Panel title="Your download and modification requests" flush>
          <Register rows={mine.data} rowKey={(a) => a.action_id}
            empty={<Empty title="You have not requested any copies">Open a document in Digital assets to request a download or a modification copy.</Empty>}
            columns={[
              { key: 'id', label: 'Request', render: (a) => <Id>{a.action_id}</Id> },
              { key: 'as', label: 'Document', render: (a) => <Link to={`/digital/${encodeURIComponent(a.asset_serial)}`}><Id>{a.asset_serial}</Id></Link> },
              { key: 'm', label: 'Kind', render: (a) => (a.details?.mode === 'MODIFICATION' ? 'Modification copy' : 'Download') },
              { key: 's', label: 'Status', render: (a) => <RequestState a={a} /> },
              { key: 'e', label: 'Available until', render: (a) => (a.token_expires_at ? formatDate(a.token_expires_at) : '—') },
              { key: 'x', label: '', className: 'actions', render: (a) => <RequestActions a={a} onMessage={(m) => { setMessage(m); reload(); }} onError={setWarning} /> },
            ]} />
        </Panel>
      </div>

      {review && (
        <Decision action={review} onClose={() => setReview(null)}
          onDone={(msg, warn) => { setReview(null); setMessage(msg); setWarning(warn || ''); reload(); }}
          getSigner={getSigner} />
      )}
      {consent && (
        <StepUpDialog factor="factor3" actionLabel={consent.decision === 'APPROVE' ? 'Consent to this download' : 'Refuse this download'}
          confirmLabel={consent.decision === 'APPROVE' ? 'Consent' : 'Refuse'} danger={consent.decision === 'REJECT'}
          onClose={() => setConsent(null)}
          extra={<p className="small">{consent.decision === 'APPROVE' ? 'After your consent a Manager or Administrator still has to approve the request.' : 'The requester is told the owner refused.'}</p>}
          onSubmit={async (code) => {
            const token = await api.stepUp('asset.approve', code);
            await api.ownerDownloadDecision(consent.a.action_id, consent.decision, null, token);
            setConsent(null); setMessage(`${consent.a.action_id} ${consent.decision === 'APPROVE' ? 'consented; now awaiting approval' : 'refused'}.`); reload();
          }} />
      )}
    </>
  );
}

function Decision({ action, onClose, onDone, getSigner }) {
  const [decision, setDecision] = useState('APPROVE');
  const [reason, setReason] = useState('');
  const [maxViews, setMaxViews] = useState(action.details?.max_views ? String(action.details.max_views) : '');
  const [until, setUntil] = useState('');
  const [allowDownload, setAllowDownload] = useState(Boolean(action.details?.request_download));
  const [progress, setProgress] = useState('');
  const d = action.details || {};
  const facts = [
    ['Request', <Id key="i">{action.action_id}</Id>],
    ['Type', KIND[action.action_type] || action.action_type],
    ['Asset', <Id key="a">{action.asset_serial}</Id>],
    ['Title', d.name],
    ['Department', d.department],
    ['Requested by', <Id key="b">{action.actor_did}</Id>],
    ['Purpose', action.purpose],
    ['For identity', d.target_did && <Id key="t">{d.target_did}</Id>],
    ['New file SHA-256', d.file_hash && <Id key="h">{d.file_hash}</Id>],
    ['Version', d.version],
    ['Owner consent', d.requires_owner_approval ? (d.owner_approved_by ? 'Given' : 'Not given') : undefined],
  ];
  const onChain = decision === 'APPROVE' && ['CREATION', 'MODIFICATION'].includes(action.action_type);

  return (
    <StepUpDialog factor="factor3" actionLabel={`Decide on ${action.action_id}`} danger={decision === 'REJECT'}
      confirmLabel={decision === 'APPROVE' ? (onChain ? 'Approve and sign' : 'Confirm approval') : 'Confirm rejection'} onClose={onClose}
      extra={<>
        <Facts items={facts} />
        <div className="segmented" role="group" aria-label="Decision">
          <button type="button" aria-pressed={decision === 'APPROVE'} onClick={() => setDecision('APPROVE')}>Approve</button>
          <button type="button" aria-pressed={decision === 'REJECT'} onClick={() => setDecision('REJECT')}>Reject</button>
        </div>
        {decision === 'REJECT' && <Field label="Reason (shown to the requester)"><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} /></Field>}
        {decision === 'APPROVE' && action.action_type === 'SHARE' && (
          <div className="form-grid">
            <Field label="View limit" hint="Empty means no limit"><input className="input" inputMode="numeric" value={maxViews} onChange={(e) => setMaxViews(e.target.value.replace(/\D/g, ''))} /></Field>
            <Field label="Accessible until" hint="Empty means no expiry"><input className="input" type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} /></Field>
            <label className="choice span-2"><input type="checkbox" checked={allowDownload} onChange={(e) => setAllowDownload(e.target.checked)} />Allow this identity to request downloads (still individually approved)</label>
          </div>
        )}
        {onChain && <p className="small muted">Approving produces a ledger transaction that your wallet signs next. LexCorp2 marks it recorded only after verifying the receipt and the contract state.</p>}
        {progress && <Notice tone="info">{progress}</Notice>}
      </>}
      onSubmit={async (code) => {
        const token = await api.stepUp('asset.approve', code);
        const body = { decision, rejection_reason: decision === 'REJECT' ? reason || null : null };
        if (decision === 'APPROVE' && action.action_type === 'SHARE') {
          body.max_views = maxViews ? Number(maxViews) : null;
          body.accessible_until = until ? new Date(until).toISOString() : null;
          body.allow_download = allowDownload;
        }
        const res = await api.decideAction(action, body, token);
        if (!onChain || !res.calldata) { onDone(`${action.action_id} ${decision === 'APPROVE' ? 'approved' : 'rejected'}.`); return; }
        try {
          const chain = await signAndConfirm(getSigner, res.calldata, res.contract_address, action.asset_serial, setProgress);
          onDone(`${action.action_id} approved and recorded on the ledger (block ${chain.block_number}).`);
        } catch (err) {
          onDone(`${action.action_id} approved.`, `${err?.response?.data?.detail || err.shortMessage || err.message}. Open the asset and use "Record on ledger" to retry.`);
        }
      }} />
  );
}
