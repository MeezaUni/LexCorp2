import { useState } from 'react';
import { ethers } from 'ethers';
import { Mark } from '../components/Shell';
import { Button, Field, Notice, errorText } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { getNonce, loginWithPasskey, loginWithTotp, provisionWallet, requestResetWithWallet } from '../services/api';
import { parseWalletInput, storeEncryptedWallet } from '../services/walletCore';

const TABS = [
  ['signin', 'Sign in'],
  ['provision', 'First-time provisioning'],
  ['create', 'Create a wallet'],
  ['locked', 'Locked out'],
];

export default function SignIn() {
  const { notice, onAuthenticated } = useAuth();
  const [tab, setTab] = useState('signin');
  const [error, setError] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);

  const run = async (label, fn) => {
    setError(''); setStatus(label); setBusy(true);
    try { await fn(); } catch (err) { setError(errorText(err)); } finally { setBusy(false); setStatus(''); }
  };
  const signNonce = async (wallet) => {
    const { nonce, message } = await getNonce(wallet.address);
    return { nonce, message, signature: await wallet.signMessage(message) };
  };

  return (
    <div className="auth-screen">
      <aside className="auth-aside">
        <div className="row"><Mark size={40} /><div><div className="brand-name">LexCorp2</div><div className="brand-sub">Asset Assurance &amp; Custody</div></div></div>
        <h1>Controlled records for digital and physical assets</h1>
        <p>Every document view, download and change is tied to a verified identity, approved by a responsible officer, watermarked and anchored to the organisation's permissioned ledger.</p>
        <ul>
          <li>Sign-in uses your wallet identity plus your login authenticator or login passkey.</li>
          <li>Sensitive actions ask for a separate factor bound to that one action.</li>
          <li>Sessions end when your network address changes or after 15 minutes idle.</li>
        </ul>
        <div className="foot">Authorised personnel only. Activity on this system is recorded.</div>
      </aside>

      <main className="auth-main">
        <div className="auth-panel">
          <div className="tabs" role="tablist" aria-label="Access options">
            {TABS.map(([id, label]) => (
              <button key={id} role="tab" aria-selected={tab === id} aria-controls={`panel-${id}`} id={`tab-${id}`}
                onClick={() => { setTab(id); setError(''); }}>{label}</button>
            ))}
          </div>
          {notice && !error && <Notice tone="warning">{notice}</Notice>}
          {error && <Notice tone="error" title="That did not work">{error}</Notice>}
          {status && <Notice tone="info">{status}</Notice>}

          <section role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
            {tab === 'signin' && <SignInForm busy={busy} run={run} done={onAuthenticated} />}
            {tab === 'provision' && <ProvisionForm busy={busy} run={run} done={onAuthenticated} signNonce={signNonce} />}
            {tab === 'create' && <CreateWallet />}
            {tab === 'locked' && <LockedOut busy={busy} run={run} signNonce={signNonce} />}
          </section>
        </div>
      </main>
    </div>
  );
}

function SignInForm({ busy, run, done }) {
  const [address, setAddress] = useState('');
  const [code, setCode] = useState('');
  const addressOk = ethers.isAddress(address.trim());
  return (
    <form className="form" onSubmit={(e) => { e.preventDefault(); run('Checking your login authenticator code', async () => { await loginWithTotp(address.trim(), code); await done(); }); }}>
      <h2>Sign in to LexCorp2</h2>
      <Field label="Wallet address" hint="Type the address of your LexCorp2 wallet. It is not remembered on this device.">
        <input className="input mono" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="0x…"
          autoComplete="off" spellCheck={false} required aria-invalid={address && !addressOk ? 'true' : undefined} />
      </Field>
      <Field label="Login authenticator code (TOTP 1)">
        <input className="input mono" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
          inputMode="numeric" autoComplete="one-time-code" maxLength={6} />
      </Field>
      <Button type="submit" variant="primary" block busy={busy} disabled={!addressOk || code.length !== 6}>Sign in with authenticator code</Button>
      <Button block busy={busy} disabled={!addressOk}
        onClick={() => run('Waiting for your login passkey', async () => { await loginWithPasskey(address.trim()); await done(); })}>
        Sign in with login passkey
      </Button>
    </form>
  );
}

function ProvisionForm({ busy, run, done, signNonce }) {
  const [key, setKey] = useState('');
  const [pin, setPin] = useState('');
  return (
    <form className="form" onSubmit={(e) => {
      e.preventDefault();
      run('Proving wallet ownership and checking the provisioning PIN', async () => {
        const wallet = parseWalletInput(key);
        const { nonce, message, signature } = await signNonce(wallet);
        const result = await provisionWallet(message, signature, nonce, pin.trim());
        await storeEncryptedWallet(wallet, result.wallet_key);
        setKey(''); setPin('');
        await done();
      });
    }}>
      <h2>Provision your wallet on this device</h2>
      <p className="muted">Use this the first time, or after an administrator reset your login factors. You need your wallet recovery phrase (or private key) and the single-use provisioning PIN from your administrator, valid for 3 hours.</p>
      <Field label="Recovery phrase or private key" hint="Used on this device only. It is encrypted here and never sent to the server.">
        <textarea className="textarea mono" rows={3} value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" spellCheck={false} required />
      </Field>
      <Field label="Provisioning PIN">
        <input className="input mono" value={pin} onChange={(e) => setPin(e.target.value)} maxLength={12} autoComplete="off" spellCheck={false} required />
      </Field>
      <Button type="submit" variant="primary" block busy={busy} disabled={!key.trim() || pin.trim().length < 6}>Provision wallet and continue to security setup</Button>
    </form>
  );
}

function CreateWallet() {
  const [wallet, setWallet] = useState(null);
  const [confirmed, setConfirmed] = useState(false);
  return (
    <div className="form">
      <h2>Create a wallet for your identity</h2>
      <p className="muted">Generate a new wallet on this device and give only its <strong>address</strong> to your administrator, who registers your identity and issues a provisioning PIN. Nothing is stored or sent: record the recovery phrase yourself and keep it private.</p>
      {!wallet && <Button variant="primary" onClick={() => { const w = ethers.Wallet.createRandom(); setWallet({ address: w.address, phrase: w.mnemonic.phrase }); setConfirmed(false); }}>Generate wallet on this device</Button>}
      {wallet && (
        <>
          <Field label="Wallet address (share this with your administrator)"><div className="secret-box">{wallet.address}</div></Field>
          <Field label="Recovery phrase (write it down; it is shown only now)"><div className="secret-box" data-sensitive="true">{wallet.phrase}</div></Field>
          <label className="choice"><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />I have recorded the recovery phrase in a safe place.</label>
          <Button disabled={!confirmed} onClick={() => setWallet(null)}>Clear it from the screen</Button>
        </>
      )}
    </div>
  );
}

function LockedOut({ busy, run, signNonce }) {
  const [key, setKey] = useState('');
  const [reason, setReason] = useState('');
  const [sent, setSent] = useState('');
  return (
    <form className="form" onSubmit={(e) => {
      e.preventDefault();
      run('Signing your request with the wallet', async () => {
        const wallet = parseWalletInput(key);
        const { nonce, message, signature } = await signNonce(wallet);
        const res = await requestResetWithWallet(message, signature, nonce, reason || 'Lost login factors');
        setKey(''); setSent(res.message || 'Request sent to the administrators.');
      });
    }}>
      <h2>Ask an administrator to reset your login factors</h2>
      <p className="muted">Login factors cannot be reset by yourself. Sign a request with your wallet; an administrator confirms it with you in person and issues a new provisioning PIN.</p>
      {sent && <Notice tone="success" title="Request recorded">{sent}</Notice>}
      <Field label="Recovery phrase or private key" hint="Used only to sign the request on this device; not stored or sent.">
        <textarea className="textarea mono" rows={3} value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" spellCheck={false} required />
      </Field>
      <Field label="Reason"><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="For example: phone replaced" /></Field>
      <Button type="submit" variant="primary" block busy={busy} disabled={!key.trim()}>Send signed reset request</Button>
    </form>
  );
}
