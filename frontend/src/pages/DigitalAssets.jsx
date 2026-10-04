import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, Dialog, Field, Id, Notice, PageHeader, Panel, Register, Status, StepUpDialog, errorText, formatDate, shortHash, useAsync } from '../components/ui';
import { refreshCounts } from '../components/Shell';
import { useAuth } from '../context/AuthContext';
import { signAndConfirm } from '../services/chainActions';
import { recorded } from './DigitalAssetDetail';
import { VerifyAssetButton } from '../components/Checks';
import * as api from '../services/api';

/** One row per document lineage, showing its most recent version. */
export function groupLineages(assets) {
  const byRoot = new Map();
  for (const a of assets.filter((x) => !x.is_physical)) {
    const root = a.root_asset_id || a.id;
    const cur = byRoot.get(root);
    if (!cur || (a.version_number || 1) > (cur.version_number || 1)) byRoot.set(root, { ...a, versions: (cur?.versions || 0) + 1 });
    else cur.versions = (cur.versions || 1) + 1;
  }
  return [...byRoot.values()].sort((x, y) => new Date(y.created_at) - new Date(x.created_at));
}

export default function DigitalAssets() {
  const { user } = useAuth();
  const nav = useNavigate();
  const { data, error, reload } = useAsync(api.getRegistry, []);
  const [q, setQ] = useState('');
  const [state, setState] = useState('ALL');
  const [registering, setRegistering] = useState(false);
  const [done, setDone] = useState('');

  const rows = useMemo(() => {
    if (!data) return null;
    const needle = q.trim().toLowerCase();
    return groupLineages(data).filter((a) =>
      (state === 'ALL' || a.approval_status === state)
      && (!needle || [a.serial_number, a.name, a.department, a.owner_name].some((v) => (v || '').toLowerCase().includes(needle))));
  }, [data, q, state]);

  const canRegister = user.role !== 'AUDITOR';

  return (
    <>
      <PageHeader crumbs={[['Dashboard', '/'], ['Digital assets']]} title="Digital assets"
        lede="Controlled documents. Viewing produces a watermarked copy; downloads and changes need approval."
        actions={canRegister && <Button variant="primary" onClick={() => setRegistering(true)}>Register document</Button>}
        ribbon={data && [
          { content: <><strong>{groupLineages(data).length}</strong> documents in your scope</> },
          { content: <><strong>{groupLineages(data).filter((a) => a.approval_status === 'PENDING_APPROVAL').length}</strong> awaiting approval</> },
        ]} />
      <div className="content">
        {error && <Notice tone="error" title="The register could not be loaded">{error}</Notice>}
        {done && <Notice tone="success" title="Submitted for approval">{done}</Notice>}
        <Panel flush>
          <div className="filters">
            <Field label="Search"><input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Serial, title, department or owner" /></Field>
            <Field label="Approval state">
              <select className="select" value={state} onChange={(e) => setState(e.target.value)}>
                <option value="ALL">All states</option><option value="APPROVED">Approved</option>
                <option value="PENDING_APPROVAL">Pending approval</option><option value="REJECTED">Rejected</option>
              </select>
            </Field>
          </div>
          <Register rows={rows} rowKey={(a) => a.id} onRowClick={(a) => nav(`/digital/${encodeURIComponent(a.serial_number)}`)}
            caption="Digital asset register"
            empty={<div className="empty"><strong>No documents in your scope</strong><span>{canRegister ? 'Register a document to start its approval.' : 'Documents appear here when they are shared with you.'}</span></div>}
            columns={[
              { key: 'serial', label: 'Asset ID', render: (a) => <Id>{a.serial_number}</Id> },
              { key: 'name', label: 'Title', render: (a) => <span className="primary-cell">{a.name || 'Untitled'}</span> },
              { key: 'dept', label: 'Department', render: (a) => a.department || '—' },
              { key: 'owner', label: 'Owner', render: (a) => a.owner_name || '—' },
              { key: 'ver', label: 'Version', render: (a) => `v${a.version_number || 1}` },
              { key: 'approval', label: 'Approval', render: (a) => <Status value={a.approval_status} /> },
              { key: 'ledger', label: 'Ledger', render: (a) => <Status value={recorded(a) ? 'VERIFIED' : 'PENDING'}>{recorded(a) ? 'Recorded' : 'Not yet recorded'}</Status> },
              { key: 'hash', label: 'SHA-256', render: (a) => <Id title={a.file_hash}>{shortHash(a.file_hash)}</Id> },
              { key: 'updated', label: 'Last change', render: (a) => formatDate(a.updated_at, false) },
              { key: 'verify', label: 'Verify', render: (a) => <VerifyAssetButton serial={a.serial_number} size="sm" /> },
            ]} />
        </Panel>
      </div>
      {registering && <RegisterDocument onClose={() => setRegistering(false)}
        onDone={(msg) => { setRegistering(false); setDone(msg); reload(); refreshCounts(); }} />}
    </>
  );
}

function RegisterDocument({ onClose, onDone }) {
  const { user, isAdmin, isManager, getSigner } = useAuth();
  const direct = isAdmin || isManager; // no approval step: register and record in one go
  const [progress, setProgress] = useState('');
  const { data: departments } = useAsync(api.assignableDepartments, []);
  const [file, setFile] = useState(null);
  const [uploaded, setUploaded] = useState(null);
  const [form, setForm] = useState({ name: '', serial: '', department: user.department || '', purpose: '', recipient: '' });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [stepUp, setStepUp] = useState(false);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const upload = async (f) => {
    setFile(f); setUploaded(null); setError('');
    if (!f) return;
    setBusy(true);
    try { setUploaded(await api.uploadDocument(f)); if (!form.name) setForm((x) => ({ ...x, name: f.name.replace(/\.[^.]+$/, '') })); }
    catch (err) { setError(errorText(err)); }
    finally { setBusy(false); }
  };

  const deptOptions = isAdmin || isManager ? (departments || []) : [user.department].filter(Boolean);
  const valid = uploaded && form.name.trim() && form.serial.trim() && form.department;

  return (
    <>
      <Dialog title="Register a document" onClose={onClose} wide
        footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!valid} onClick={() => setStepUp(true)}>{direct ? 'Register and record' : 'Submit for approval'}</Button></>}>
        <p className="muted small">The file is stored in the LexCorp vault and its SHA-256 is computed by the server. {direct
          ? 'As a Manager or Administrator you register it directly: your wallet records it on the ledger straight away.'
          : 'A Manager or Administrator of the department approves it before it is recorded on the ledger.'}</p>
        {error && <Notice tone="error">{error}</Notice>}
        <div className="form-grid">
          <Field className="span-2" label="Document file" hint="PDF, Word, PowerPoint, Excel, PNG/JPEG image or plain text, up to 50 MB.">
            <input className="input" type="file" accept=".pdf,.docx,.pptx,.xlsx,.png,.jpg,.jpeg,.txt,.csv,.md" onChange={(e) => upload(e.target.files?.[0])} />
          </Field>
          {busy && <div className="span-2 small muted">Uploading and hashing {file?.name}…</div>}
          {uploaded && (
            <div className="span-2"><Notice tone="success" title="Stored in the vault">SHA-256 <Id>{uploaded.file_hash}</Id>, {Math.ceil(uploaded.file_size / 1024)} KB, type {uploaded.document_type}.</Notice></div>
          )}
          <Field label="Title"><input className="input" value={form.name} onChange={set('name')} required /></Field>
          <Field label="Asset ID (serial)" hint="Unique identifier, for example DOC-AV-2026-014"><input className="input mono" value={form.serial} onChange={set('serial')} required /></Field>
          <Field label="Department">
            <select className="select" value={form.department} onChange={set('department')}>
              <option value="">Select</option>{deptOptions.map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
          </Field>
          <Field label="Owner wallet" hint="Leave empty to own it yourself"><input className="input mono" value={form.recipient} onChange={set('recipient')} placeholder={user.wallet_address} /></Field>
          <Field className="span-2" label="Purpose (recorded with the request)"><input className="input" value={form.purpose} onChange={set('purpose')} /></Field>
        </div>
      </Dialog>
      {stepUp && (
        <StepUpDialog factor={direct ? 'factor3' : 'factor2'} actionLabel={direct ? 'Register and record this document' : 'Confirm document submission'}
          confirmLabel={direct ? 'Register and record' : 'Submit'}
          extra={progress && <Notice tone="info">{progress}</Notice>}
          onClose={() => setStepUp(false)}
          onSubmit={async (code) => {
            const token = await api.stepUp(direct ? 'asset.mint' : 'document.submit', code);
            const res = await api.proposeDocument({
              name: form.name.trim(), serial_number: form.serial.trim(), file_hash: uploaded.file_hash, offchain_uri: uploaded.offchain_uri,
              recipient_address: form.recipient.trim() || user.wallet_address, department: form.department, purpose: form.purpose || null,
            }, token);
            if (res.calldata) {
              const chain = await signAndConfirm(getSigner, res.calldata, res.contract_address, form.serial.trim(), setProgress);
              onDone(`${form.serial.trim()} registered and recorded on the ledger (block ${chain.block_number}).`);
              return;
            }
            onDone(`${form.serial.trim()} submitted as ${res.action_id}. It appears as pending until approved.`);
          }} />
      )}
    </>
  );
}
