import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ethers } from 'ethers';
import { Button, Dialog, Empty, Facts, Field, Id, Loading, Notice, PageHeader, Panel, Register, Status, StepUpDialog, downloadBlob, errorText, formatDate, shortWallet, useAsync } from '../components/ui';
import { refreshCounts } from '../components/Shell';
import { useAuth } from '../context/AuthContext';
import * as api from '../services/api';
import { signAndConfirm } from '../services/chainActions';
import ProtectedViewer from '../components/ProtectedViewer';

export const recorded = (a) => ['MINTED', 'ANCHORED'].includes(a?.lifecycle_status) || Boolean(a?.watermark_metadata?.chain_tx);

export default function DigitalAssetDetail() {
  const { serial } = useParams();
  const { user, canApprove, getSigner } = useAuth();
  const [tick, setTick] = useState(0);
  const reload = () => setTick((t) => t + 1);
  const registry = useAsync(api.getRegistry, [tick]);
  const lineage = useAsync(() => api.getLineage(serial), [serial, tick]);
  const grants = useAsync(() => api.listGrants(), [tick]);
  const mine = useAsync(api.myDownloads, [tick]);
  const logs = useAsync(() => (user.role === 'USER' ? Promise.resolve(null) : api.getDocumentLogs(serial)), [serial, tick]);

  const [dialog, setDialog] = useState(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [viewer, setViewer] = useState(null);
  useEffect(() => () => viewer && URL.revokeObjectURL(viewer.url), [viewer]);

  const asset = useMemo(() => (registry.data || []).find((a) => a.serial_number === serial), [registry.data, serial]);
  const versions = lineage.data?.lineage || [];
  const serials = new Set(versions.map((v) => v.serial_number).concat(serial));
  const myRequests = (mine.data || []).filter((a) => serials.has(a.asset_serial));
  const docGrants = (grants.data || []).filter((g) => serials.has(g.asset_serial));
  const isHolder = asset && asset.owner_wallet?.toLowerCase() === user.wallet_address.toLowerCase();
  const manages = canApprove; // scope is enforced by the server; the registry already filtered what we can see
  const root = versions[0];

  if (registry.loading && !registry.data) return (<><PageHeader title="Digital asset" /><div className="content"><Loading /></div></>);
  if (!asset) {
    return (<><PageHeader crumbs={[['Digital assets', '/digital'], [serial]]} title="Record not available" />
      <div className="content"><Notice tone="warning" title="This document is not in your scope">It does not exist, or your role and department do not permit you to see it.</Notice></div></>);
  }

  const done = (msg) => { setDialog(null); setMessage(msg); setError(''); reload(); refreshCounts(); };

  const view = async (code) => {
    const token = await api.stepUp('document.view', code);
    try {
      const res = await api.viewDocument(serial, token);
      setViewer({ blob: res.blob, type: res.type, actionId: res.actionId });
      setDialog(null);
    } catch (err) { throw new Error(await api.blobError(err)); }
  };

  const recordOnLedger = async (code, setProgress) => {
    const isRevision = (asset.version_number || 1) > 1;
    const action = isRevision ? 'document.modify' : 'asset.mint';
    const token = await api.stepUp(action, code);
    let prepared;
    if (isRevision) {
      prepared = await api.http.post('/assets/update-digital/prepare', { token_id: root.token_id, new_file_hash: asset.file_hash, new_offchain_uri: asset.metadata_cid || '' },
        { headers: { 'X-Step-Up-Token': token } }).then((r) => r.data);
    } else {
      prepared = await api.http.post('/assets/mint-digital/prepare', {
        to_address: asset.owner_wallet, token_id: asset.token_id, serial_number: asset.serial_number, owner_did: asset.owner_did,
        file_hash: asset.file_hash, offchain_uri: asset.metadata_cid || '',
      }, { headers: { 'X-Step-Up-Token': token } }).then((r) => r.data);
    }
    const res = await signAndConfirm(getSigner, prepared.calldata, prepared.contract_address, asset.serial_number, setProgress);
    done(`${asset.serial_number} recorded on the ledger (${res.lifecycle_status.toLowerCase()}, block ${res.block_number}).`);
  };

  const ribbon = [
    { content: <>Approval <strong>{asset.approval_status === 'APPROVED' ? 'granted' : asset.approval_status.replace('_', ' ').toLowerCase()}</strong></> },
    { content: <>Ledger <strong>{recorded(asset) ? 'recorded' : 'not yet recorded'}</strong>{asset.watermark_metadata?.block_number && <>, block {asset.watermark_metadata.block_number}</>}</>, warn: asset.approval_status === 'APPROVED' && !recorded(asset) },
    { content: <>Version <strong>{asset.version_number || 1}</strong> of {versions.length || 1}</> },
  ];

  return (
    <>
      <PageHeader crumbs={[['Dashboard', '/'], ['Digital assets', '/digital'], [asset.serial_number]]}
        title={asset.name || asset.serial_number}
        lede={`Controlled document owned by ${asset.owner_name || shortWallet(asset.owner_wallet)}${asset.department ? `, ${asset.department}` : ''}.`}
        ribbon={ribbon}
        actions={<>
          <Button variant="primary" onClick={() => setDialog('view')}>View document</Button>
          {isHolder
            ? <Button onClick={() => setDialog('own-download')}>Download my copy</Button>
            : user.role !== 'AUDITOR' && <Button onClick={() => setDialog('download')}>Request download</Button>}
          {user.role !== 'AUDITOR' && <Button onClick={() => setDialog('modify')}>Request modification copy</Button>}
          {(isHolder || manages) && <Button onClick={() => setDialog('share')}>Delegate access</Button>}
        </>} />
      <div className="content">
        {message && <Notice tone="success" title="Done">{message}</Notice>}
        {error && <Notice tone="error">{error}</Notice>}
        {(() => {
          const newer = versions.filter((v) => (v.version_number || 1) > (asset.version_number || 1) && v.approval_status === 'APPROVED').pop();
          return newer ? <Notice tone="info" title={`A newer approved version exists (v${newer.version_number})`}>This page shows v{asset.version_number || 1}. <Link to={`/digital/${encodeURIComponent(newer.serial_number)}`}>Open v{newer.version_number}</Link>.</Notice> : null;
        })()}
        {manages && asset.approval_status === 'APPROVED' && !recorded(asset) && (
          <Notice tone="warning" title="Approved but not yet recorded on the ledger">
            The approval exists in LexCorp2 but no verified ledger transaction has been recorded for this version.
            <div style={{ marginTop: 8 }}><Button size="sm" variant="primary" onClick={() => setDialog('ledger')}>Record on ledger</Button></div>
          </Notice>
        )}
        <div className="grid-main-side">
          <div className="stack">
            <Panel title="Record">
              <Facts items={[
                ['Asset ID', <Id key="s">{asset.serial_number}</Id>],
                ['Title', asset.name],
                ['Owner', <span key="o">{asset.owner_name || 'Unnamed'} <Id>{shortWallet(asset.owner_wallet)}</Id></span>],
                ['Department', asset.department],
                ['Approval', <Status key="a" value={asset.approval_status} />],
                ['Lifecycle', <Status key="l" value={asset.lifecycle_status} />],
                ['Token ID', asset.token_id],
                ['SHA-256', <Id key="h">{asset.file_hash}</Id>],
                ['Ledger transaction', asset.watermark_metadata?.chain_tx ? <Id key="t">{asset.watermark_metadata.chain_tx}</Id> : 'None recorded'],
                ['Created', formatDate(asset.created_at)],
              ]} />
            </Panel>
            <Panel title="Versions" flush>
              <Register rows={lineage.data ? versions : null} rowKey={(v) => v.id}
                empty={<Empty title="No version history" />}
                columns={[
                  { key: 'v', label: 'Version', render: (v) => `v${v.version_number || 1}` },
                  { key: 's', label: 'Asset ID', render: (v) => v.serial_number === serial ? <Id>{v.serial_number}</Id> : <Link to={`/digital/${encodeURIComponent(v.serial_number)}`}><Id>{v.serial_number}</Id></Link> },
                  { key: 'a', label: 'Approval', render: (v) => <Status value={v.approval_status} /> },
                  { key: 'l', label: 'Lifecycle', render: (v) => <Status value={v.lifecycle_status} /> },
                  { key: 'h', label: 'SHA-256', render: (v) => <Id title={v.file_hash}>{(v.file_hash || '').slice(0, 16)}…</Id> },
                  { key: 'c', label: 'Created', render: (v) => formatDate(v.created_at, false) },
                ]} />
            </Panel>
            {logs.data && (
              <Panel title="Document activity" flush>
                <Register rows={logs.data} rowKey={(a) => a.action_id} empty={<Empty title="No recorded views or requests" />}
                  columns={[
                    { key: 'id', label: 'Action ID', render: (a) => <Id>{a.action_id}</Id> },
                    { key: 't', label: 'Type', render: (a) => a.action_type.charAt(0) + a.action_type.slice(1).toLowerCase() },
                    { key: 'by', label: 'By', render: (a) => <Id>{shortWallet(a.actor_did?.split(':').pop())}</Id> },
                    { key: 'ip', label: 'Address', render: (a) => a.client_ip || '—' },
                    { key: 's', label: 'Status', render: (a) => <Status value={a.status} /> },
                    { key: 'd', label: 'When', render: (a) => formatDate(a.created_at) },
                  ]} />
              </Panel>
            )}
          </div>
          <div className="stack">
            <Panel title="Your requests for this document" flush>
              <Register rows={mine.data ? myRequests : null} rowKey={(a) => a.action_id}
                empty={<Empty title="No requests yet">Request a download or a modification copy above.</Empty>}
                columns={[
                  { key: 'id', label: 'Request', render: (a) => <><Id>{a.action_id}</Id><div className="small muted">{a.details?.mode === 'MODIFICATION' ? 'Modification copy' : 'Download'}</div></> },
                  { key: 's', label: 'Status', render: (a) => <RequestState a={a} /> },
                  { key: 'x', label: '', className: 'actions', render: (a) => <RequestActions a={a} onMessage={(m) => { setMessage(m); reload(); }} onError={setError} /> },
                ]} />
            </Panel>
            <Panel title="Delegated access" flush>
              <Register rows={grants.data ? docGrants : null} rowKey={(g) => g.id}
                empty={<Empty title="No delegated access">Access granted to other identities appears here with its limits.</Empty>}
                columns={[
                  { key: 'who', label: 'Identity', render: (g) => <Id>{shortWallet(g.grantee_did.split(':').pop())}</Id> },
                  { key: 'lim', label: 'Limits', render: (g) => <span className="small">{g.max_views ? `${g.views_count} of ${g.max_views} views` : `${g.views_count} views, no limit`}{g.expires_at ? `; until ${formatDate(g.expires_at)}` : ''}{g.can_download ? '; download allowed' : '; view only'}</span> },
                  { key: 's', label: 'Status', render: (g) => <Status value={g.status === 'EXHAUSTED' ? 'EXPIRED' : g.status}>{g.status === 'EXHAUSTED' ? 'Views used up' : undefined}</Status> },
                  { key: 'x', label: '', className: 'actions', render: (g) => g.status === 'ACTIVE' && (isHolder || manages) && (
                    <Button size="sm" variant="quiet" onClick={async () => { try { await api.revokeGrant(g.id); setMessage('Access revoked.'); reload(); } catch (err) { setError(errorText(err)); } }}>Revoke</Button>) },
                ]} />
            </Panel>
          </div>
        </div>
      </div>

      {dialog === 'view' && (
        <StepUpDialog factor="factor2" actionLabel="View this document" confirmLabel="View"
          extra={<p className="small">A copy watermarked with your identity, wallet, network address, date and a new View ID is generated. Each view is recorded{asset.owner_wallet?.toLowerCase() !== user.wallet_address.toLowerCase() ? ' and may count against a view limit' : ''}.</p>}
          onClose={() => setDialog(null)} onSubmit={view} />
      )}
      {viewer && (
        <Dialog title={`Protected view, ${viewer.actionId || ''}`} wide onClose={() => setViewer(null)}>
          <ProtectedViewer blob={viewer.blob} type={viewer.type} label={`Watermarked view of ${asset.serial_number}`} />
          <p className="small muted">View only: this copy can't be saved or printed from here, and it is watermarked and traceable by its View ID. {isHolder ? 'As the owner, use "Download my copy" for a copy you can keep.' : 'A copy you can keep needs an approved download.'}</p>
        </Dialog>
      )}
      {dialog === 'own-download' && (
        <StepUpDialog factor="factor3" actionLabel="Download your copy" confirmLabel="Download"
          extra={<p className="small">You own this document, so no approval is needed. You get a copy watermarked with your name, wallet, network address, date and a new Download ID. The original file stays in the vault.</p>}
          onClose={() => setDialog(null)}
          onSubmit={async (code) => {
            try {
              const { blob, filename, actionId } = await api.ownerDownload(asset.serial_number, await api.stepUp('document.download', code));
              downloadBlob(blob, filename);
              done(`Downloaded your watermarked copy (${actionId}).`);
            } catch (err) { throw new Error(await api.blobError(err)); }
          }} />
      )}
      {(dialog === 'download' || dialog === 'modify') && (
        <RequestCopy mode={dialog === 'modify' ? 'MODIFICATION' : 'STANDARD'} serial={asset.serial_number} privileged={manages} owner={isHolder}
          onClose={() => setDialog(null)} onDone={done} />
      )}
      {dialog === 'share' && <DelegateAccess serial={asset.serial_number} privileged={manages} onClose={() => setDialog(null)} onDone={done} />}
      {dialog === 'ledger' && <LedgerDialog asset={asset} onClose={() => setDialog(null)} onSubmit={recordOnLedger} />}
    </>
  );
}

export function RequestState({ a }) {
  if (a.status === 'PENDING' && a.details?.requires_owner_approval && !a.details?.owner_approved_by) return <Status value="PENDING">Awaiting owner consent</Status>;
  if (a.status === 'PENDING') return <Status value="PENDING">Awaiting approval</Status>;
  if (a.status === 'APPROVED') return <Status value="APPROVED">Approved, ready</Status>;
  if (a.status === 'COMPLETED' && a.details?.revision_mod_id) return <Status value="COMPLETED">Revision {a.details.revision_mod_id}</Status>;
  return <Status value={a.status} />;
}

/** Fetch an approved copy (Factor 3) or upload a revision after a modification copy. */
export function RequestActions({ a, onMessage }) {
  const [step, setStep] = useState(null);
  const [file, setFile] = useState(null);
  const isMod = a.details?.mode === 'MODIFICATION';
  const canUpload = isMod && a.status === 'COMPLETED' && !a.details?.revision_mod_id;
  return (
    <>
      {a.status === 'APPROVED' && <Button size="sm" variant="primary" onClick={() => setStep('fetch')}>Download copy</Button>}
      {canUpload && <Button size="sm" onClick={() => setStep('upload')}>Upload revision</Button>}
      {step === 'fetch' && (
        <StepUpDialog factor="factor3" actionLabel={`Download ${a.action_id}`} confirmLabel="Download"
          extra={<p className="small">The copy is generated once, watermarked with your identity and the Download ID. The original document is not changed.</p>}
          onClose={() => setStep(null)}
          onSubmit={async (code) => {
            const token = await api.stepUp('document.download', code);
            try {
              const { blob, filename } = await api.fetchDownload(a.action_id, token);
              downloadBlob(blob, filename);
              setStep(null);
              onMessage(`Downloaded ${filename}.`);
            } catch (err) { throw new Error(await api.blobError(err)); }
          }} />
      )}
      {step === 'upload' && (
        <StepUpDialog factor="factor3" actionLabel={`Submit revision of ${a.asset_serial}`} confirmLabel="Submit revision"
          extra={<Field label="Revised file" hint="Must be the same document type. It becomes a new pending version.">
            <input className="input" type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} /></Field>}
          onClose={() => setStep(null)}
          onSubmit={async (code) => {
            if (!file) throw new Error('Choose the revised file first.');
            const token = await api.stepUp('document.modify', code);
            const mod = await api.uploadRevision(a.asset_serial, a.action_id, file, 'Revision', token);
            setStep(null);
            onMessage(`Revision ${mod.action_id} submitted as version ${mod.details?.version}; it awaits approval.`);
          }} />
      )}
    </>
  );
}

function RequestCopy({ mode, serial, privileged, owner, onClose, onDone }) {
  const [purpose, setPurpose] = useState('');
  const who = privileged
    ? (owner ? 'As a Manager or Administrator who owns it, it is approved straight away.' : 'As a Manager or Administrator, you need only the owner\'s consent; no other approval.')
    : `It needs ${owner ? '' : 'the owner\'s consent and '}a Manager or Administrator approval.`;
  return (
    <StepUpDialog factor="factor2" actionLabel={mode === 'MODIFICATION' ? 'Request a modification copy' : 'Request a download'}
      confirmLabel="Send request" onClose={onClose}
      extra={<>
        <p className="small">{mode === 'MODIFICATION'
          ? 'A modification copy lets you edit the document outside LexCorp2 and upload the result as a new version.'
          : 'A download is a watermarked copy you keep.'} {who}</p>
        <Field label="Purpose"><input className="input" value={purpose} onChange={(e) => setPurpose(e.target.value)} placeholder="Why do you need a copy?" /></Field>
      </>}
      onSubmit={async (code) => {
        const token = await api.stepUp('download.request', code);
        const r = await api.requestDownload(serial, mode, purpose || null, token);
        onDone(r.status === 'APPROVED'
          ? `${r.action_id} is approved. Download it from My requests.`
          : `Request ${r.action_id} sent. You will be able to download it from My requests once approved.`);
      }} />
  );
}

function DelegateAccess({ serial, privileged, onClose, onDone }) {
  const [target, setTarget] = useState('');
  const [views, setViews] = useState('');
  const [download, setDownload] = useState(false);
  const [until, setUntil] = useState('');
  const did = ethers.isAddress(target.trim()) ? `did:ethr:13371:${target.trim().toLowerCase()}` : target.trim();
  return (
    <StepUpDialog factor={privileged ? 'factor3' : 'factor2'} actionLabel="Delegate access to this document"
      confirmLabel={privileged ? 'Grant access' : 'Send for approval'} onClose={onClose}
      extra={<>
        <p className="small">{privileged
          ? 'As a Manager or Administrator, the access applies immediately with the limits you set here.'
          : 'The request goes to a Manager or Administrator, who sets the final limits (view count, expiry, download).'}</p>
        <Field label="Identity wallet address or DID"><input className="input mono" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="0x…" /></Field>
        <Field label={privileged ? 'View limit' : 'Suggested view limit'} hint={privileged ? 'Empty = unlimited' : 'Optional'}><input className="input" inputMode="numeric" value={views} onChange={(e) => setViews(e.target.value.replace(/\D/g, ''))} /></Field>
        {privileged && <Field label="Accessible until" hint="Empty = no expiry"><input className="input" type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} /></Field>}
        <label className="choice"><input type="checkbox" checked={download} onChange={(e) => setDownload(e.target.checked)} />{privileged ? 'Allow this identity to request downloads' : 'Also ask to allow downloads'}</label>
      </>}
      onSubmit={async (code) => {
        if (!did.startsWith('did:')) throw new Error('Enter a valid wallet address or DID.');
        const token = await api.stepUp(privileged ? 'asset.approve' : 'access.request', code);
        const r = await api.proposeShare({
          asset_serial: serial, target_did: did, access_level: 1, max_views: views ? Number(views) : null, request_download: download,
          ...(privileged && until ? { accessible_until: new Date(until).toISOString() } : {}),
        }, token);
        onDone(r.status === 'APPROVED' ? `Access granted (${r.action_id}).` : `Access request ${r.action_id} sent for approval.`);
      }} />
  );
}

function LedgerDialog({ asset, onClose, onSubmit }) {
  const [progress, setProgress] = useState('');
  return (
    <StepUpDialog factor="factor3" actionLabel="Record this version on the ledger" confirmLabel="Sign and record" onClose={onClose}
      extra={<>
        <p className="small">Your wallet signs the transaction. The LexCorp2 contract accepts it only from a wallet holding the minting or anchoring role, and LexCorp2 records it only after verifying the receipt and the resulting contract state.</p>
        <Facts items={[['Asset ID', <Id key="s">{asset.serial_number}</Id>], ['SHA-256', <Id key="h">{asset.file_hash}</Id>]]} />
        {progress && <Notice tone="info">{progress}</Notice>}
      </>}
      onSubmit={(code) => onSubmit(code, setProgress)} />
  );
}
