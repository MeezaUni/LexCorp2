import { useState } from 'react';
import { ethers } from 'ethers';
import { Button, Dialog, Empty, Facts, Field, Id, Notice, PageHeader, Panel, Register, Status, StepUpDialog, errorText, formatDate, shortWallet, useAsync } from '../components/ui';
import { roleName } from '../components/Shell';
import { useAuth } from '../context/AuthContext';
import * as api from '../services/api';

const CREATABLE = { ADMIN: ['MANAGER', 'AUDITOR', 'USER'], MANAGER: ['USER'] };

export default function Admin() {
  const { user, isAdmin } = useAuth();
  const [tick, setTick] = useState(0);
  const users = useAsync(() => api.listUsers(isAdmin ? { include_revoked: true } : undefined), [tick]);
  const resets = useAsync(() => (isAdmin ? api.listResetRequests() : Promise.resolve([])), [tick]);
  const departments = useAsync(api.assignableDepartments, [tick]);
  const chain = useAsync(() => (isAdmin ? api.chainStatus() : Promise.resolve(null)), [tick]);
  const [flow, setFlow] = useState(null);
  const [pin, setPin] = useState(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const reload = (m) => { setFlow(null); setMessage(m || ''); setError(''); setTick((t) => t + 1); };

  return (
    <>
      <PageHeader crumbs={[['Dashboard', '/'], [isAdmin ? 'Administration' : 'People']]} title={isAdmin ? 'Administration' : 'People in your departments'}
        lede={isAdmin ? 'Identities, departments, login resets and ledger roles. Every change here needs your Factor 3 and is audited.' : 'Register users for your departments. Changes need your Factor 3 and are audited.'}
        actions={<Button variant="primary" onClick={() => setFlow({ kind: 'create' })}>Register identity</Button>}
        ribbon={users.data && [
          { content: <><strong>{users.data.filter((u) => u.is_active).length}</strong> active identities</> },
          { content: <><strong>{users.data.filter((u) => u.onboarding_pending && u.is_active).length}</strong> not yet enrolled</> },
          isAdmin && { content: <><strong>{(resets.data || []).length}</strong> reset requests</>, warn: (resets.data || []).length > 0 },
          isAdmin && chain.data && { content: <>Ledger <strong>{chain.data.ok ? 'verified' : 'check failed'}</strong></>, warn: !chain.data.ok },
        ]} />
      <div className="content">
        {message && <Notice tone="success" title="Done">{message}</Notice>}
        {error && <Notice tone="error">{error}</Notice>}
        {isAdmin && (resets.data || []).length > 0 && (
          <Panel title="Login reset requests" flush>
            <Register rows={resets.data} rowKey={(r) => r.id}
              columns={[
                { key: 'n', label: 'Identity', render: (r) => <><strong>{r.name || 'Unnamed'}</strong><div className="small"><Id>{shortWallet(r.wallet_address)}</Id></div></> },
                { key: 'r', label: 'Role', render: (r) => roleName(r.role) },
                { key: 'why', label: 'Reason', render: (r) => r.reset_reason || '—' },
                { key: 'at', label: 'Requested', render: (r) => formatDate(r.reset_requested_at) },
                { key: 'x', label: '', className: 'actions', render: (r) => r.id !== user.id && <Button size="sm" variant="primary" onClick={() => setFlow({ kind: 'reset', target: r })}>Approve reset</Button> },
              ]} />
          </Panel>
        )}
        <Panel title="Identities" flush>
          <Register rows={users.data} rowKey={(u) => u.id} empty={<Empty title="No identities in your scope" />}
            columns={[
              { key: 'n', label: 'Name', render: (u) => <><strong>{u.name || 'Unnamed'}</strong>{u.id === user.id && <span className="small muted"> (you)</span>}</> },
              { key: 'r', label: 'Role', render: (u) => roleName(u.role) },
              { key: 'd', label: 'Department', render: (u) => u.department || '—' },
              { key: 'w', label: 'Wallet', render: (u) => <Id title={u.wallet_address}>{shortWallet(u.wallet_address)}</Id> },
              { key: 's', label: 'Status', render: (u) => (!u.is_active ? <Status value="REVOKED" /> : u.onboarding_pending ? <Status value="PENDING">Not yet enrolled</Status> : <Status value="ACTIVE" />) },
              { key: 'x', label: '', className: 'actions', render: (u) => u.is_active && u.id !== user.id && (CREATABLE[user.role] || []).includes(u.role) && <>
                {isAdmin && <Button size="sm" variant="quiet" onClick={() => setFlow({ kind: 'role', target: u })}>Change role</Button>}
                {isAdmin && u.role === 'MANAGER' && <Button size="sm" variant="quiet" onClick={() => setFlow({ kind: 'scope', target: u })}>Departments</Button>}
                <Button size="sm" variant="quiet" onClick={() => setFlow({ kind: 'revoke', target: u })}>Revoke</Button>
              </> },
            ]} />
        </Panel>
        {isAdmin && (
          <div className="grid-2">
            <Panel title="Departments" aside={<Button size="sm" onClick={() => setFlow({ kind: 'dept' })}>Add department</Button>}>
              {(departments.data || []).length ? <ul style={{ margin: 0, paddingLeft: 18 }}>{departments.data.map((d) => <li key={d}>{d}</li>)}</ul> : <Empty title="No departments" />}
            </Panel>
            <Panel title="Ledger roles" aside={<Button size="sm" onClick={async () => { try { const r = await api.reconcileRoles(); reload(`Ledger roles reconciled: ${r.synced} identities checked, ${r.unregistered_revoked} unregistered holders revoked, ${r.failed} failures.`); } catch (err) { setError(errorText(err)); } }}>Reconcile now</Button>}>
              <p className="small muted">Managers and Administrators hold the minting, anchoring and management roles on the ledger; Auditors hold the audit role; Users hold none. LexCorp keeps the ledger in step automatically and removes roles from revoked or unknown wallets.</p>
              {chain.data && <Facts items={[
                ['Contract', <Id key="c">{chain.data.contract_address}</Id>], ['Chain', chain.data.chain_id], ['Head block', chain.data.head_block],
                ...Object.entries(chain.data.checks || {}).map(([k, v]) => [k.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase()), v === true ? 'Pass' : String(v)]),
              ]} />}
            </Panel>
          </div>
        )}
      </div>

      {flow?.kind === 'create' && <CreateIdentity departments={departments.data || []} roles={CREATABLE[user.role] || []} onClose={() => setFlow(null)}
        onDone={(res) => { setPin({ title: 'Identity registered', res }); reload(`${res.name || res.wallet_address} registered as ${roleName(res.role)}.`); }} />}
      {flow?.kind === 'role' && <RoleChange target={flow.target} roles={CREATABLE[user.role]} onClose={() => setFlow(null)} onDone={reload} />}
      {flow?.kind === 'revoke' && (
        <StepUpDialog factor="factor3" danger actionLabel={`Revoke ${flow.target.name || shortWallet(flow.target.wallet_address)}`} confirmLabel="Revoke identity" onClose={() => setFlow(null)}
          extra={<Notice tone="error">Sessions end immediately, sign-in is refused, and ledger roles are removed. History is kept. An identity that still holds assets cannot be revoked until they are reassigned.</Notice>}
          onSubmit={async (code) => { await api.revokeUser(flow.target.id, await api.stepUp('identity.revoke', code)); reload('Identity revoked.'); }} />
      )}
      {flow?.kind === 'reset' && (
        <StepUpDialog factor="factor3" actionLabel={`Approve login reset for ${flow.target.name || shortWallet(flow.target.wallet_address)}`} confirmLabel="Approve reset" onClose={() => setFlow(null)}
          extra={<Notice tone="warning">Only approve after confirming the person's identity out of band (in person or by a known phone number).</Notice>}
          onSubmit={async (code) => { const r = await api.approveReset(flow.target.id, await api.stepUp('admin.reset', code)); setPin({ title: 'Login reset approved', res: r }); reload('Login reset approved.'); }} />
      )}
      {flow?.kind === 'scope' && <ManagedDepartments target={flow.target} departments={departments.data || []} onClose={() => setFlow(null)} onDone={reload} />}
      {flow?.kind === 'dept' && <AddDepartment onClose={() => setFlow(null)} onDone={reload} />}
      {pin && (
        <Dialog title={pin.title} onClose={() => setPin(null)} footer={<Button variant="primary" onClick={() => setPin(null)}>I have handed the PIN over</Button>}>
          <Notice tone="warning" title="Shown once">Give this single-use PIN to the person in person or through a trusted channel. It expires in 3 hours and is never shown again.</Notice>
          <Facts items={[
            ['Wallet', <Id key="w">{pin.res.wallet_address}</Id>],
            ['Provisioning PIN', <span key="p" className="secret-box" data-sensitive="true" data-testid="one-time-pin">{pin.res.one_time_pin}</span>],
            ['Expires', formatDate(pin.res.pin_expires_at)],
            ['Ledger roles', pin.res.chain_roles ? (pin.res.chain_roles.ok ? (pin.res.chain_roles.roles || []).join(', ') || 'None (user role)' : 'Update pending; retried automatically') : undefined],
          ]} />
        </Dialog>
      )}
    </>
  );
}

function CreateIdentity({ departments, roles, onClose, onDone }) {
  const [f, setF] = useState({ name: '', role: roles[roles.length - 1], department: '', wallet: '', contact: '' });
  const [generated, setGenerated] = useState(null);
  const [ack, setAck] = useState(false);
  const [stepUp, setStepUp] = useState(false);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const addrOk = ethers.isAddress(f.wallet.trim());
  const valid = f.name.trim() && f.department && addrOk && (!generated || ack);
  return (
    <>
      <Dialog title="Register an identity" wide onClose={onClose}
        footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!valid} onClick={() => setStepUp(true)}>Register</Button></>}>
        <p className="small muted">Prefer the wallet address the person created on their own device (sign-in screen, "Create a wallet"): then nobody else ever sees their key.</p>
        <div className="form-grid">
          <Field label="Full name"><input className="input" value={f.name} onChange={set('name')} /></Field>
          <Field label="Role"><select className="select" value={f.role} onChange={set('role')}>{roles.map((r) => <option key={r} value={r}>{roleName(r)}</option>)}</select></Field>
          <Field label="Department"><select className="select" value={f.department} onChange={set('department')}><option value="">Select</option>{departments.map((d) => <option key={d} value={d}>{d}</option>)}</select></Field>
          <Field label="Contact number" hint="Used to confirm identity out of band"><input className="input" value={f.contact} onChange={set('contact')} /></Field>
          <Field className="span-2" label="Wallet address" error={f.wallet && !addrOk ? 'Not a valid address' : ''}>
            <input className="input mono" value={f.wallet} onChange={(e) => { setF({ ...f, wallet: e.target.value }); setGenerated(null); }} placeholder="0x…" />
          </Field>
        </div>
        {!generated && <div><Button size="sm" variant="quiet" onClick={() => { const w = ethers.Wallet.createRandom(); setGenerated({ address: w.address, phrase: w.mnemonic.phrase }); setF({ ...f, wallet: w.address }); setAck(false); }}>The person cannot create one: generate a wallet for them</Button></div>}
        {generated && (
          <Notice tone="warning" title="Custodial hand-over">
            You now know this person's recovery phrase. Hand it over privately and ask them to keep it secret. It is not stored anywhere by LexCorp.
            <div className="secret-box" data-sensitive="true" style={{ margin: '8px 0' }}>{generated.phrase}</div>
            <label className="choice"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />I have recorded the phrase for secure hand-over.</label>
          </Notice>
        )}
      </Dialog>
      {stepUp && (
        <StepUpDialog factor="factor3" actionLabel="Confirm identity registration" confirmLabel="Register identity" onClose={() => setStepUp(false)}
          onSubmit={async (code) => {
            const token = await api.stepUp('identity.provision', code);
            const res = await api.createUser({ wallet_address: f.wallet.trim(), name: f.name.trim(), role: f.role, department: f.department, contact_number: f.contact || null }, token);
            onDone(res);
          }} />
      )}
    </>
  );
}

function RoleChange({ target, roles, onClose, onDone }) {
  const [role, setRole] = useState(target.role);
  return (
    <StepUpDialog factor="factor3" actionLabel={`Change role of ${target.name || shortWallet(target.wallet_address)}`} confirmLabel="Change role" onClose={onClose}
      extra={<><Field label="New role"><select className="select" value={role} onChange={(e) => setRole(e.target.value)}>{roles.map((r) => <option key={r} value={r}>{roleName(r)}</option>)}</select></Field>
        <p className="small muted">Their sessions end so the new role applies at next sign-in, and ledger roles are updated.</p></>}
      onSubmit={async (code) => { await api.changeRole(target.id, role, await api.stepUp('identity.role', code)); onDone(`Role changed to ${roleName(role)}.`); }} />
  );
}

function ManagedDepartments({ target, departments, onClose, onDone }) {
  const [sel, setSel] = useState(new Set(target.managed_departments || []));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  return (
    <Dialog title={`Departments managed by ${target.name || shortWallet(target.wallet_address)}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={busy} onClick={async () => {
        setBusy(true); try { await api.setManagedDepartments(target.id, [...sel]); onDone('Managed departments updated.'); } catch (err) { setError(errorText(err)); setBusy(false); }
      }}>Save</Button></>}>
      {error && <Notice tone="error">{error}</Notice>}
      <p className="small muted">In addition to their own department ({target.department || 'none'}).</p>
      {departments.filter((d) => d !== target.department).map((d) => (
        <label key={d} className="choice"><input type="checkbox" checked={sel.has(d)} onChange={(e) => { const n = new Set(sel); e.target.checked ? n.add(d) : n.delete(d); setSel(n); }} />{d}</label>
      ))}
    </Dialog>
  );
}

function AddDepartment({ onClose, onDone }) {
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  return (
    <Dialog title="Add a department" onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={busy} disabled={name.trim().length < 2} onClick={async () => {
        setBusy(true); try { await api.createDepartment(name.trim()); onDone(`Department ${name.trim()} added.`); } catch (err) { setError(errorText(err)); setBusy(false); }
      }}>Add</Button></>}>
      {error && <Notice tone="error">{error}</Notice>}
      <Field label="Department name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} /></Field>
    </Dialog>
  );
}
