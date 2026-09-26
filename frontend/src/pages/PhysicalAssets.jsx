import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, Dialog, Field, Id, Notice, PageHeader, Panel, Register, Status, StepUpDialog, formatDate, useAsync } from '../components/ui';
import { refreshCounts } from '../components/Shell';
import { useAuth } from '../context/AuthContext';
import * as api from '../services/api';

const MAC_RE = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/;
export const onLedger = (a) => a?.lifecycle_status === 'MINTED' || Boolean(a?.watermark_metadata?.chain_tx);

export default function PhysicalAssets() {
  const { canApprove } = useAuth();
  const nav = useNavigate();
  const { data, error, reload } = useAsync(api.getRegistry, []);
  const [q, setQ] = useState('');
  const [status, setStatus] = useState('ALL');
  const [registering, setRegistering] = useState(false);
  const [done, setDone] = useState('');

  const physical = useMemo(() => (data || []).filter((a) => a.is_physical), [data]);
  const rows = useMemo(() => {
    if (!data) return null;
    const n = q.trim().toLowerCase();
    return physical.filter((a) => (status === 'ALL' || a.approval_status === status || a.lifecycle_status === status)
      && (!n || [a.serial_number, a.name, a.department, String(a.token_id)].some((v) => (v || '').toLowerCase().includes(n))));
  }, [data, physical, q, status]);

  return (
    <>
      <PageHeader crumbs={[['Dashboard', '/'], ['Physical assets']]} title="Physical assets"
        lede="Registered equipment. Serial numbers, MAC addresses and unique device addresses are unique across the whole registry."
        actions={canApprove && <Button variant="primary" onClick={() => setRegistering(true)}>Register asset</Button>}
        ribbon={data && [
          { content: <><strong>{physical.length}</strong> assets in your scope</> },
          { content: <><strong>{physical.filter((a) => onLedger(a)).length}</strong> recorded on the ledger</> },
          { content: <><strong>{physical.filter((a) => a.approval_status === 'PENDING_APPROVAL').length}</strong> awaiting approval</> },
        ]} />
      <div className="content">
        {error && <Notice tone="error" title="The registry could not be loaded">{error}</Notice>}
        {done && <Notice tone="success" title="Submitted for approval">{done}</Notice>}
        <Panel flush>
          <div className="filters">
            <Field label="Search"><input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Serial, name, department or token" /></Field>
            <Field label="State">
              <select className="select" value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="ALL">All</option><option value="PENDING_APPROVAL">Pending approval</option><option value="APPROVED">Approved</option>
                <option value="REJECTED">Rejected</option><option value="MINTED">On ledger</option><option value="MAINTENANCE">In maintenance</option>
                <option value="RETIRED">Retired</option>
              </select>
            </Field>
          </div>
          <Register rows={rows} rowKey={(a) => a.id} onRowClick={(a) => nav(`/physical/${encodeURIComponent(a.serial_number)}`)}
            caption="Physical asset register"
            empty={<div className="empty"><strong>No physical assets in your scope</strong><span>{canApprove ? 'Register an asset to start its approval.' : 'Assets assigned to you appear here.'}</span></div>}
            columns={[
              { key: 's', label: 'Serial number', render: (a) => <Id>{a.serial_number}</Id> },
              { key: 'n', label: 'Name', render: (a) => <span className="primary-cell">{a.name || 'Unnamed'}</span> },
              { key: 't', label: 'Token ID', render: (a) => `#${a.token_id}` },
              { key: 'd', label: 'Department', render: (a) => a.department || '—' },
              { key: 'a', label: 'Approval', render: (a) => <Status value={a.approval_status} /> },
              { key: 'l', label: 'Lifecycle', render: (a) => <Status value={a.lifecycle_status} /> },
              { key: 'v', label: 'Ledger', render: (a) => <Status value={onLedger(a) ? 'VERIFIED' : 'PENDING'}>{onLedger(a) ? 'Recorded' : 'Not yet recorded'}</Status> },
              { key: 'c', label: 'Registered', render: (a) => formatDate(a.created_at, false) },
            ]} />
        </Panel>
      </div>
      {registering && <RegisterPhysical onClose={() => setRegistering(false)} onDone={(m) => { setRegistering(false); setDone(m); reload(); refreshCounts(); }} />}
    </>
  );
}

function RegisterPhysical({ onClose, onDone }) {
  const { user } = useAuth();
  const { data: departments } = useAsync(api.assignableDepartments, []);
  const [f, setF] = useState({ name: '', serial: '', type: 'EQUIPMENT', typeOther: '', hasMac: 'yes', mac: '', unique: '', location: '', department: user.department || '', custodian: '', purpose: '' });
  const [stepUp, setStepUp] = useState(false);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const macError = f.hasMac === 'yes' && f.mac && !MAC_RE.test(f.mac.trim()) ? 'Use six pairs of hex digits, for example 00:1A:2B:3C:4D:5E' : '';
  const otherOk = f.type !== 'OTHER' || f.typeOther.trim().length >= 2;
  const valid = f.name.trim() && f.serial.trim() && f.department && otherOk && (f.hasMac === 'yes' ? MAC_RE.test(f.mac.trim()) : f.unique.trim().length >= 4);

  return (
    <>
      <Dialog title="Register a physical asset" wide onClose={onClose}
        footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!valid} onClick={() => setStepUp(true)}>Submit for approval</Button></>}>
        <p className="muted small">Each asset needs its serial number plus either its MAC address or, when it has none, a unique device address. LexCorp2 refuses any value already registered to another asset.</p>
        <div className="form-grid">
          <Field label="Asset name"><input className="input" value={f.name} onChange={set('name')} /></Field>
          <Field label="Serial number"><input className="input mono" value={f.serial} onChange={set('serial')} /></Field>
          <Field label="Asset type">
            <select className="select" value={f.type} onChange={set('type')}>
              <option value="EQUIPMENT">Equipment</option><option value="SENSOR">Sensor</option><option value="COMMUNICATION">Communication unit</option>
              <option value="COMPUTE">Computing unit</option><option value="VEHICLE">Vehicle</option><option value="OTHER">Other</option>
            </select>
          </Field>
          {f.type === 'OTHER' && (
            <Field label="What is it?" hint="For example: drone battery, test rig, radio mast">
              <input className="input" value={f.typeOther} maxLength={40} onChange={set('typeOther')} autoFocus />
            </Field>
          )}
          <Field label="Department">
            <select className="select" value={f.department} onChange={set('department')}>
              <option value="">Select</option>{(departments || []).map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
          </Field>
          <fieldset className="field span-2" style={{ border: 0, padding: 0, margin: 0 }}>
            <legend>Does the device have a MAC address?</legend>
            <div className="segmented" role="group">
              <button type="button" aria-pressed={f.hasMac === 'yes'} onClick={() => setF({ ...f, hasMac: 'yes' })}>Yes, it has a MAC address</button>
              <button type="button" aria-pressed={f.hasMac === 'no'} onClick={() => setF({ ...f, hasMac: 'no' })}>No, use a unique address</button>
            </div>
          </fieldset>
          {f.hasMac === 'yes'
            ? <Field label="MAC address" error={macError}><input className="input mono" value={f.mac} onChange={set('mac')} placeholder="00:1A:2B:3C:4D:5E" aria-invalid={macError ? 'true' : undefined} /></Field>
            : <Field label="Unique device address" hint="Chip ID, IMEI or other identifier printed on the device"><input className="input mono" value={f.unique} onChange={set('unique')} /></Field>}
          <Field label="Location"><input className="input" value={f.location} onChange={set('location')} /></Field>
          <Field label="Custodian wallet" hint="Leave empty to hold custody yourself"><input className="input mono" value={f.custodian} onChange={set('custodian')} placeholder={user.wallet_address} /></Field>
          <Field label="Purpose (recorded)"><input className="input" value={f.purpose} onChange={set('purpose')} /></Field>
        </div>
      </Dialog>
      {stepUp && (
        <StepUpDialog factor="factor2" actionLabel="Confirm asset registration" confirmLabel="Submit" onClose={() => setStepUp(false)}
          onSubmit={async (code) => {
            const token = await api.stepUp('document.submit', code);
            const r = await api.proposePhysical({
              name: f.name.trim(), serial_number: f.serial.trim(), asset_type: f.type, asset_type_other: f.type === 'OTHER' ? f.typeOther.trim() : null, has_mac_address: f.hasMac === 'yes',
              mac_address: f.hasMac === 'yes' ? f.mac.trim() : null, device_unique_address: f.hasMac === 'no' ? f.unique.trim() : null,
              location: f.location || null, department: f.department, purpose: f.purpose || null,
              recipient_address: f.custodian.trim() || user.wallet_address,
            }, token);
            onDone(`${f.serial.trim()} submitted as ${r.action_id}.`);
          }} />
      )}
    </>
  );
}
