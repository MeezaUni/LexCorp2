import { useState } from 'react';
import { Mark } from '../components/Shell';
import { Button, Field, Notice, errorText, shortWallet } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { registerPasskey, startTotp, verifyTotp } from '../services/api';

/**
 * Mandatory enrolment after provisioning. The session is setup-only: the server refuses
 * every application endpoint until BOTH Login TOTP 1 and Login Passkey 1 exist.
 */
export default function Enrolment() {
  const { user, refresh, signOut } = useAuth();
  const [totp, setTotp] = useState(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const act = async (fn) => {
    setBusy(true); setError('');
    try { await fn(); await refresh(); } catch (err) { setError(errorText(err)); } finally { setBusy(false); }
  };

  const totpDone = Boolean(user.is_totp_enabled);
  const passkeyDone = Boolean(user.has_login_passkey);
  const current = !totpDone ? 1 : !passkeyDone ? 2 : 3;

  return (
    <div className="auth-screen">
      <aside className="auth-aside">
        <div className="row"><Mark size={40} /><div><div className="brand-name">LexCorp</div><div className="brand-sub">Identity enrolment</div></div></div>
        <h1>Set up your login factors</h1>
        <p>Your wallet is provisioned. Before you can use LexCorp, register both login factors. Afterwards you sign in with either one.</p>
        <ul>
          <li>Identity: {user.name || 'Unnamed'}</li>
          <li>Role: {user.role}{user.department ? `, ${user.department}` : ''}</li>
          <li>Wallet: <span className="id" style={{ color: '#fff' }}>{shortWallet(user.wallet_address)}</span></li>
        </ul>
        <div className="foot">Access to the application stays blocked until both steps are complete.</div>
      </aside>
      <main className="auth-main">
        <div className="auth-panel">
          <h2 style={{ fontSize: '1.5rem' }}>Security enrolment</h2>
          {error && <Notice tone="error" title="Enrolment step failed">{error}</Notice>}
          <ol className="steps">
            <li className={`step${totpDone ? ' done' : current === 1 ? ' current' : ''}`}>
              <div className="step-head">
                <span className="step-num" aria-hidden="true">{totpDone ? '✓' : 1}</span>
                <h3>Login authenticator (TOTP 1)</h3>
                <span className={`tag ${totpDone ? 'clear' : 'caution'}`} style={{ marginLeft: 'auto' }}>{totpDone ? 'Configured' : 'Required'}</span>
              </div>
              {!totpDone && (
                <div className="step-body">
                  {!totp && (
                    <>
                      <p className="muted small">Add LexCorp to an authenticator app (for example Microsoft or Google Authenticator) on a device you keep with you.</p>
                      <div><Button variant="primary" busy={busy} onClick={() => act(async () => setTotp(await startTotp('login')))}>Start authenticator setup</Button></div>
                    </>
                  )}
                  {totp && (
                    <form className="stack" onSubmit={(e) => { e.preventDefault(); act(async () => { await verifyTotp('login', code); setTotp(null); setCode(''); }); }}>
                      <div className="row" style={{ alignItems: 'flex-start' }}>
                        <img className="qr" src={totp.qr_data_uri} alt="Authenticator enrolment QR code" data-sensitive="true" />
                        <div className="stack" style={{ flex: 1, minWidth: 200 }}>
                          <span className="small muted">Scan the code, or type this key into the app:</span>
                          <span className="small muted">Only this newest code works. If your app already has a LexCorp Login entry from an earlier attempt, delete it.</span>
                          <div className="secret-box" data-sensitive="true" data-testid="totp-secret">{totp.secret}</div>
                        </div>
                      </div>
                      <Field label="Code shown in the app">
                        <input className="input mono" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code}
                          onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} />
                      </Field>
                      <div><Button type="submit" variant="primary" busy={busy} disabled={code.length !== 6}>Confirm authenticator</Button></div>
                    </form>
                  )}
                </div>
              )}
            </li>
            <li className={`step${passkeyDone ? ' done' : current === 2 ? ' current' : ''}`}>
              <div className="step-head">
                <span className="step-num" aria-hidden="true">{passkeyDone ? '✓' : 2}</span>
                <h3>Login passkey (Passkey 1)</h3>
                <span className={`tag ${passkeyDone ? 'clear' : 'caution'}`} style={{ marginLeft: 'auto' }}>{passkeyDone ? 'Configured' : 'Required'}</span>
              </div>
              {!passkeyDone && (
                <div className="step-body">
                  <p className="muted small">Registers this device's platform authenticator (for example Windows Hello). Your device asks for your PIN, fingerprint or face.</p>
                  <div><Button variant="primary" busy={busy} onClick={() => act(() => registerPasskey('login', 'Login passkey (Passkey 1)'))}>Register login passkey</Button></div>
                </div>
              )}
            </li>
          </ol>
          {current === 3 && <Notice tone="success" title="Enrolment complete">Loading your workspace…</Notice>}
          <div><Button variant="quiet" onClick={() => signOut('You signed out during enrolment.')}>Sign out</Button></div>
        </div>
      </main>
    </div>
  );
}
