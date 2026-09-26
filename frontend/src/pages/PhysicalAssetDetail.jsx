import { useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Button, Dialog, Empty, Facts, Field, Id, Loading, Notice, PageHeader, Panel, Register, Status, StepUpDialog, errorText, formatDate, shortWallet, useAsync } from '../components/ui';
import { humanEvent } from './Dashboard';
import { onLedger } from './PhysicalAssets';
import { useAuth } from '../context/AuthContext';
import * as api from '../services/api';
import { signAndConfirm } from '../services/chainActions';

const STATUSES = ['ACTIVE', 'ASSIGNED', 'MAINTENANCE', 'IN_STORAGE', 'LOST', 'RETIRED', 'DECOMMISSIONED'];

export default function PhysicalAssetDetail() {
  const { serial } = useParams();
  const { user, canApprove, getSigner } = useAuth();
  const [tick, setTick] = useState(0);
  const reload = () => setTick((t) => t + 1);
  const registry = useAsync(api.getRegistry, [tick]);
  const verify = useAsync(() => api.getVerifyData(serial), [serial, tick]);
  const [dialog, setDialog] = useState(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [card, setCard] = useState(null);
  const [qr, setQr] = useState(null);

  const asset = useMemo(() => (registry.data || []).find((a) => a.serial_number === serial && a.is_physical), [registry.data, serial]);
  const v = verify.data;

  useEffect(() => {
    let urls = [];
    if (asset && canApprove && ['APPROVED', 'ACTIVE'].includes(asset.approval_status)) {
      api.fetchCard(serial).then(({ blob }) => { const u = URL.createObjectURL(blob); urls.push(u); setCard(u); }).catch(() => setCard(null));
    }
    if (asset) api.fetchImage(api.qrImageUrl(serial)).then((u) => { urls.push(u); setQr(u); }).catch(() => setQr(null));
    return () => urls.forEach((u) => URL.revokeObjectURL(u));
  }, [asset, canApprove, serial]);

  if (registry.loading && !registry.data) return (<><PageHeader title="Physical asset" /><div className="content"><Loading /></div></>);
  if (!asset) {
    return (<><PageHeader crumbs={[['Physical assets', '/physical'], [serial]]} title="Record not available" />
      <div className="content"><Notice tone="warning" title="This asset is not in your scope">It does not exist, or your role and department do not permit you to see it.</Notice></div></>);
  }
  const done = (m) => { setDialog(null); setMessage(m); setError(''); reload(); };

  return (
    <>
      <PageHeader crumbs={[['Dashboard', '/'], ['Physical assets', '/physical'], [asset.serial_number]]}
        title={asset.name || asset.serial_number}
        lede={`${assetTypeLabel(asset.asset_type)} registered to ${asset.department || 'no department'}.`}
        ribbon={[
          { content: <>Token <strong>#{asset.token_id}</strong></> },
          { content: <>Ledger <strong>{onLedger(asset) ? 'recorded' : 'not yet recorded'}</strong></>, warn: asset.approval_status === 'APPROVED' && !onLedger(asset) },
          { content: <>Lifecycle <strong>{asset.lifecycle_status.replace(/_/g, ' ').toLowerCase()}</strong></> },
        ]}
        actions={canApprove && <>
          <Button onClick={() => setDialog('status')}>Change status</Button>
          <Button onClick={() => setDialog('maintenance')}>Record maintenance</Button>
          {card && <a className="btn btn-secondary" href={card} download={`${asset.serial_number}-card.svg`}>Download NFT card</a>}
        </>} />
      <div className="content">
        {message && <Notice tone="success" title="Done">{message}</Notice>}
        {error && <Notice tone="error">{error}</Notice>}
        {canApprove && asset.approval_status === 'APPROVED' && !onLedger(asset) && (
          <Notice tone="warning" title="Approved but not yet recorded on the ledger">
            No verified ledger transaction exists for this asset yet.
            <div style={{ marginTop: 8 }}><Button size="sm" variant="primary" onClick={() => setDialog('ledger')}>Record on ledger</Button></div>
          </Notice>
        )}
        <div className="grid-main-side">
          <div className="stack">
            <Panel title="Asset record">
              {verify.loading && !v ? <Loading /> : (
                <Facts items={[
                  ['Serial number', <Id key="s">{asset.serial_number}</Id>],
                  ['NFT / token ID', `#${asset.token_id}`],
                  ['Department', asset.department],
                  ['Approval', <Status key="a" value={asset.approval_status} />],
                  ['Lifecycle', <Status key="l" value={asset.lifecycle_status} />],
                  ['Custodian', asset.custodian_name || (asset.owner_name ? `${asset.owner_name}` : shortWallet(asset.owner_wallet))],
                  ['Location', v?.location ?? (v && v.detail_level === 'AUTHORIZED' ? 'Restricted' : undefined)],
                  ['MAC address', v?.mac_address ? <Id key="m">{v.mac_address}</Id> : v?.detail_level === 'AUTHORIZED' ? <span key="m" className="muted">Restricted for your role</span> : undefined],
                  ['Unique device address', v?.device_unique_address ? <Id key="u">{v.device_unique_address}</Id> : undefined],
                  ['Creation ID', v?.creation_id ? <Id key="c">{v.creation_id}</Id> : undefined],
                  ['Registered', formatDate(asset.created_at)],
                  ['Ledger transaction', asset.watermark_metadata?.chain_tx ? <Id key="t">{asset.watermark_metadata.chain_tx}</Id> : 'None recorded'],
                ]} />
              )}
            </Panel>
            <Panel title="Lifecycle" flush>
              {v?.lifecycle?.length ? (
                <ul className="timeline">
                  {v.lifecycle.map((e, i) => (
                    <li key={i}><time dateTime={e.at}>{formatDate(e.at)}</time><div><strong>{humanEvent(e.event)}</strong>{e.tx_hash && <div className="small"><Id>{e.tx_hash}</Id></div>}</div></li>
                  ))}
                </ul>
              ) : <Empty title="No lifecycle events recorded yet" />}
            </Panel>
            <Panel title="Maintenance log" flush>
              <Register rows={v ? (v.maintenance_history || []) : null} rowKey={(r) => r.id}
                empty={<Empty title="No maintenance recorded" />}
                columns={[
                  { key: 'w', label: 'When', render: (r) => formatDate(r.created_at) },
                  { key: 'a', label: 'Work done', render: (r) => <><strong>{r.action_description}</strong>{r.notes && <div className="small muted">{r.notes}</div>}</> },
                  { key: 'b', label: 'By', render: (r) => <Id>{shortWallet(r.performed_by_did?.split(':').pop())}</Id> },
                ]} />
            </Panel>
          </div>
          <div className="stack">
            <Panel title="Verification QR">
              <div className="stack" style={{ justifyItems: 'center' }}>
                {qr ? <img className="qr" src={qr} alt={`Verification QR for ${asset.serial_number}`} /> : <Loading label="Rendering QR" />}
                <p className="small muted" style={{ textAlign: 'center' }}>Scanning opens the public verification page, which shows only minimal public fields unless the scanner signs in with an authorized role.</p>
              </div>
            </Panel>
            {card && (
              <Panel title="NFT card">
                <img src={card} alt={`NFT card for ${asset.serial_number}`} style={{ width: '100%', border: '1px solid var(--rule)' }} />
                <p className="small muted">Carries only serial number, token ID, creation date, department and the QR code.</p>
              </Panel>
            )}
          </div>
        </div>
      </div>

      {dialog === 'status' && <StatusDialog asset={asset} onClose={() => setDialog(null)} onDone={done} />}
      {dialog === 'maintenance' && <MaintenanceDialog asset={asset} user={user} onClose={() => setDialog(null)} onDone={done} onError={setError} />}
      {dialog === 'ledger' && (
        <LedgerDialog asset={asset} onClose={() => setDialog(null)} onSubmit={async (code, progress) => {
          const token = await api.stepUp('asset.mint', code);
          const prepared = await api.prepareMintPhysical({ to_address: asset.owner_wallet, token_id: asset.token_id, serial_number: asset.serial_number, owner_did: asset.owner_did }, token);
          const res = await signAndConfirm(getSigner, prepared.calldata, prepared.contract_address, asset.serial_number, progress);
          done(`${asset.serial_number} recorded on the ledger in block ${res.block_number}.`);
        }} />
      )}
    </>
  );
}

function StatusDialog({ asset, onClose, onDone }) {
  const [status, setStatus] = useState(asset.lifecycle_status);
  const [reason, setReason] = useState('');
  return (
    <StepUpDialog factor="factor3" actionLabel="Change lifecycle status" confirmLabel="Change status" onClose={onClose}
      extra={<>
        <Field label="New status">
          <select className="select" value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUSES.map((s) => <option key={s} value={s}>{s.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase())}</option>)}
          </select>
        </Field>
        <Field label="Reason (recorded)"><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
      </>}
      onSubmit={async (code) => {
        const token = await api.stepUp('asset.manage', code);
        const r = await api.changePhysicalStatus(asset.serial_number, status, reason, token);
        onDone(`Status changed from ${r.previous_status.toLowerCase()} to ${r.lifecycle_status.toLowerCase()}.`);
      }} />
  );
}

function MaintenanceDialog({ asset, user, onClose, onDone, onError }) {
  const [what, setWhat] = useState('');
  const [notes, setNotes] = useState('');
  const [busy, setBusy] = useState(false);
  return (
    <Dialog title="Record maintenance" onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={busy} disabled={!what.trim()} onClick={async () => {
        setBusy(true);
        try { await api.addMaintenance(asset.serial_number, { performed_by_did: user.did, action_description: what.trim(), notes: notes || null }); onDone('Maintenance recorded.'); }
        catch (err) { onError(errorText(err)); onClose(); }
      }}>Record</Button></>}>
      <Field label="Work performed"><input className="input" value={what} onChange={(e) => setWhat(e.target.value)} placeholder="For example: calibration" /></Field>
      <Field label="Notes"><textarea className="textarea" value={notes} onChange={(e) => setNotes(e.target.value)} /></Field>
    </Dialog>
  );
}

function LedgerDialog({ asset, onClose, onSubmit }) {
  const [progress, setProgress] = useState('');
  return (
    <StepUpDialog factor="factor3" actionLabel="Record this asset on the ledger" confirmLabel="Sign and record" onClose={onClose}
      extra={<>
        <p className="small">Your wallet signs the mint transaction. The contract accepts it only from a wallet with the minting role; LexCorp2 records it after verifying the receipt and that the serial maps to token #{asset.token_id}.</p>
        {progress && <Notice tone="info">{progress}</Notice>}
      </>}
      onSubmit={(code) => onSubmit(code, setProgress)} />
  );
}

const TYPE_LABELS = { EQUIPMENT: 'Equipment', SENSOR: 'Sensor', COMMUNICATION: 'Communication unit', COMPUTE: 'Computing unit', VEHICLE: 'Vehicle' };

function assetTypeLabel(type) {
  if (!type) return 'Asset';
  if (type.startsWith('OTHER: ')) return type.slice(7);
  return TYPE_LABELS[type] || type.charAt(0) + type.slice(1).toLowerCase();
}
