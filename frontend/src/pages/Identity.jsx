import { useState } from 'react';
import { Button, Dialog, Empty, Facts, Field, Id, Notice, PageHeader, Panel, Register, Status, StepUpDialog, errorText, formatDate, useAsync } from '../components/ui';
import { roleName } from '../components/Shell';
import { useAuth } from '../context/AuthContext';
import * as api from '../services/api';
import { hasEncryptedWallet, storedWalletAddress } from '../services/walletCore';

const PURPOSES = [
  { id: 'factor2', title: 'Factor 2: view and submit', uses: 'Viewing documents, submitting registrations, requesting access and downloads.' },
  { id: 'factor3', title: 'Factor 3: approve, mint and modify', uses: 'Approvals, ledger recording, revisions, downloads, identity administration.' },
];

export default function Identity() {
  const { user, refresh } = useAuth();
  const [tick, setTick] = useState(0);
  const passkeys = useAsync(api.listPasskeys, [tick]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [flow, setFlow] = useState(null);
  const reload = async (msg) => { setMessage(msg || ''); setError(''); setFlow(null); setTick((t) => t + 1); await refresh(); };

  const localWallet = storedWalletAddress();
  const walletMatches = localWallet && localWallet.toLowerCase() === user.wallet_address.toLowerCase();
  const has = (scope) => (passkeys.data || []).some((p) => p.factor_scope === scope);

  return (
    <>
      <PageHeader crumbs={[['Dashboard', '/'], ['My identity']]} title="My identity"
        lede="Your wallet identity and the separate factors that protect each kind of action."
        ribbon={[
          { content: <>Login factors <strong>{user.is_totp_enabled && user.has_login_passkey ? 'complete' : 'incomplete'}</strong></> },
          { content: <>This device <strong>{walletMatches ? 'holds your wallet' : 'holds no wallet for you'}</strong></>, warn: !walletMatches && user.role !== 'USER' },
        ]} />
      <div className="content">
        {message && <Notice tone="success" title="Saved">{message}</Notice>}
        {error && <Notice tone="error">{error}</Notice>}
        <div className="grid-2">
          <Panel title="Identity">
            <Facts items={[
              ['Name', user.name || 'Unnamed'],
              ['Role', roleName(user.role)],
              ['Department', user.department || 'None'],
              ['Organisation', user.organization],
              ['Wallet', <Id key="w">{user.wallet_address}</Id>],
              ['DID', <Id key="d">{user.did}</Id>],
            ]} />
          </Panel>
          <Panel title="Wallet on this device">
            {hasEncryptedWallet()
              ? <Notice tone={walletMatches ? 'success' : 'warning'} title={walletMatches ? 'Encrypted wallet present' : 'A different wallet is stored here'}>
                  {walletMatches ? 'It is unlocked only in memory, with a key the server releases to your signed-in session. Needed to sign ledger transactions.' : 'Provision your own wallet on this device with a PIN from your administrator.'}
                </Notice>
              : <Notice tone="info" title="No wallet stored on this device">You can still sign in and use most features. Signing ledger transactions (approvals, recording) needs the wallet on this device; ask your administrator for a provisioning PIN.</Notice>}
          </Panel>
        </div>

        <Panel title="Login factors">
          <Facts items={[
            ['Login authenticator (TOTP 1)', user.is_totp_enabled ? <Status key="t" value="ACTIVE">Configured</Status> : <Status key="t" value="PENDING">Missing</Status>],
            ['Login passkey (Passkey 1)', user.has_login_passkey ? <Status key="p" value="ACTIVE">Configured</Status> : <Status key="p" value="PENDING">Missing</Status>],
          ]} />
          <p className="small muted" style={{ marginTop: 12 }}>Login factors cannot be changed by yourself. If you lose one, ask an administrator; they verify you in person, then your login factors and sessions are reset and you receive a new provisioning PIN.</p>
          {user.reset_requested ? <Notice tone="info">Your reset request is waiting for an administrator.</Notice>
            : <Button onClick={() => setFlow({ kind: 'reset' })}>Ask an administrator to reset my login factors</Button>}
        </Panel>

        {PURPOSES.map((p) => {
          const totpOn = user[`is_totp_${p.id}_enabled`];
          const keyOn = has(p.id);
          return (
            <Panel key={p.id} title={p.title} aside={<Status value={totpOn || keyOn ? 'ACTIVE' : 'PENDING'}>{totpOn || keyOn ? 'Protected' : 'Not set up'}</Status>}>
              <p className="small muted">{p.uses}</p>
              <div className="grid-2">
                <div className="stack">
                  <h3>Authenticator app</h3>
                  <p className="small">{totpOn ? 'Configured.' : 'Not configured.'}</p>
                  <div className="row">
                    {!totpOn && <Button variant="primary" onClick={() => setFlow({ kind: 'totp', purpose: p.id, needsProof: keyOn })}>Set up authenticator</Button>}
                    {totpOn && <Button onClick={() => setFlow({ kind: 'totp-reset', purpose: p.id })}>Remove authenticator</Button>}
                  </div>
                </div>
                <div className="stack">
                  <h3>Passkeys</h3>
                  {(passkeys.data || []).filter((k) => k.factor_scope === p.id).map((k) => (
                    <div key={k.credential_id} className="row" style={{ justifyContent: 'space-between' }}>
                      <span className="small">{k.device_name}<span className="muted">, added {formatDate(k.created_at, false)}</span></span>
                      <Button size="sm" variant="quiet" onClick={() => setFlow({ kind: 'passkey-remove', purpose: p.id, credential: k })}>Remove</Button>
                    </div>
                  ))}
                  {!keyOn && <p className="small">No passkey registered.</p>}
                  <div><Button onClick={() => (totpOn || keyOn ? setFlow({ kind: 'passkey-add', purpose: p.id }) : addPasskey(p.id, null).then(() => reload('Passkey registered.')).catch((e) => setError(errorText(e))))}>Register passkey on this device</Button></div>
                </div>
              </div>
            </Panel>
          );
        })}
        <Panel title="All passkeys" flush>
          <Register rows={passkeys.data} rowKey={(k) => k.credential_id} empty={<Empty title="No passkeys" />}
            columns={[
              { key: 'n', label: 'Device', render: (k) => k.device_name },
              { key: 'p', label: 'Purpose', render: (k) => ({ login: 'Login (Passkey 1)', factor2: 'Factor 2', factor3: 'Factor 3' }[k.factor_scope]) },
              { key: 'd', label: 'Registered', render: (k) => formatDate(k.created_at) },
            ]} />
        </Panel>
      </div>

      {flow?.kind === 'totp' && (flow.needsProof && !flow.token
        ? <StepUpDialog factor={flow.purpose} actionLabel="Prove this factor first" confirmLabel="Continue" onClose={() => setFlow(null)}
            extra={<p className="small">This factor already has a passkey. Confirm with it before adding an authenticator app.</p>}
            onSubmit={async (code) => setFlow({ ...flow, token: await api.stepUp(`${flow.purpose}.manage`, code) })} />
        : <TotpEnrol purpose={flow.purpose} token={flow.token} onClose={() => setFlow(null)} onDone={() => reload('Authenticator configured.')} />)}
      {flow?.kind === 'totp-reset' && (
        <StepUpDialog factor={flow.purpose} actionLabel="Remove this authenticator" confirmLabel="Remove" danger onClose={() => setFlow(null)}
          onSubmit={async (code) => { await api.resetFactorTotp(flow.purpose, await api.stepUp(`${flow.purpose}.manage`, code)); await reload('Authenticator removed.'); }} />
      )}
      {flow?.kind === 'passkey-add' && (
        <StepUpDialog factor={flow.purpose} actionLabel="Add a passkey to this factor" confirmLabel="Continue" onClose={() => setFlow(null)}
          extra={<p className="small">Prove the factor you already have, then your device asks you to create the new passkey.</p>}
          onSubmit={async (code) => { await addPasskey(flow.purpose, await api.stepUp(`${flow.purpose}.manage`, code)); await reload('Passkey registered.'); }} />
      )}
      {flow?.kind === 'passkey-remove' && (
        <StepUpDialog factor={flow.purpose} actionLabel={`Remove ${flow.credential.device_name}`} confirmLabel="Remove" danger onClose={() => setFlow(null)}
          onSubmit={async (code) => { await api.disablePasskey(flow.credential.credential_id, await api.stepUp(`${flow.purpose}.manage`, code)); await reload('Passkey removed.'); }} />
      )}
      {flow?.kind === 'reset' && <ResetRequest onClose={() => setFlow(null)} onDone={() => reload('Your request was sent to the administrators.')} />}
    </>
  );
}

const addPasskey = (purpose, token) =>
  api.registerPasskey(purpose, `${navigator.platform || 'This device'} (${purpose === 'factor2' ? 'Passkey 2' : 'Passkey 3'})`, token);

function TotpEnrol({ purpose, token, onClose, onDone }) {
  const [setup, setSetup] = useState(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const start = async () => { setBusy(true); try { setSetup(await api.startTotp(purpose, token)); } catch (err) { setError(errorText(err)); } finally { setBusy(false); } };
  const verify = async () => { setBusy(true); setError(''); try { await api.verifyTotp(purpose, code); onDone(); } catch (err) { setError(errorText(err)); setBusy(false); } };
  return (
    <Dialog title={`Set up ${purpose === 'factor2' ? 'Factor 2' : 'Factor 3'} authenticator`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button>{setup
        ? <Button variant="primary" busy={busy} disabled={code.length !== 6} onClick={verify}>Confirm</Button>
        : <Button variant="primary" busy={busy} onClick={start}>Generate key</Button>}</>}>
      {error && <Notice tone="error">{error}</Notice>}
      {!setup && <p className="small">Use a separate entry in your authenticator app. Each factor has its own key; one factor can never stand in for another.</p>}
      {setup && (
        <>
          <div className="row" style={{ alignItems: 'flex-start' }}>
            <img className="qr" src={setup.qr_data_uri} alt="Authenticator enrolment QR code" data-sensitive="true" />
            <div className="stack" style={{ flex: 1, minWidth: 200 }}><span className="small muted">Or type this key:</span><div className="secret-box" data-sensitive="true">{setup.secret}</div></div>
          </div>
          <Field label="Code shown in the app"><input className="input mono" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} /></Field>
        </>
      )}
    </Dialog>
  );
}

function ResetRequest({ onClose, onDone }) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  return (
    <Dialog title="Ask for a login factor reset" onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={busy} onClick={async () => {
        setBusy(true); try { await api.requestResetSignedIn(reason || 'Requested from My identity'); onDone(); } catch (err) { setError(errorText(err)); setBusy(false); }
      }}>Send request</Button></>}>
      {error && <Notice tone="error">{error}</Notice>}
      <p className="small">When an administrator approves, your login authenticator, login passkey and all sessions are revoked, and you receive a new provisioning PIN.</p>
      <Field label="Reason"><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
    </Dialog>
  );
}
