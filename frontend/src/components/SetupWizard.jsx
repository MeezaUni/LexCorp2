import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { getMe, registerPasskey } from '../services/api';

/**
 * Mandatory first-login security setup. Shown instead of the application while the
 * session is setup-only. The server independently refuses every application endpoint
 * until BOTH Login TOTP 1 and Login Passkey 1 are configured.
 */
export default function SetupWizard({ onComplete, onSignOut }) {
  const [me, setMe] = useState(null);
  const [totp, setTotp] = useState(null);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    try { setMe(await getMe()); } catch (err) { setError(err.response?.data?.detail || 'Could not load setup status.'); }
  };
  useEffect(() => { refresh(); }, []);

  const finishIfComplete = async (result) => {
    if (result?.setup_complete && result.token) {
      await onComplete({ token: result.token, user: result.user });
      return true;
    }
    await refresh();
    return false;
  };

  const startTotp = async () => {
    setError(''); setBusy(true);
    try {
      const { data } = await axios.post('/api/auth/2fa/setup');
      setTotp(data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Could not start authenticator setup.');
    } finally { setBusy(false); }
  };

  const verifyTotp = async (e) => {
    e.preventDefault();
    setError(''); setBusy(true);
    try {
      const { data } = await axios.post('/api/auth/2fa/verify', { token: code });
      setTotp(null); setCode('');
      await finishIfComplete(data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid code.');
    } finally { setBusy(false); }
  };

  const setupPasskey = async () => {
    setError(''); setBusy(true);
    try {
      const data = await registerPasskey('login', 'Login Passkey (Passkey 1)');
      await finishIfComplete(data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Passkey registration failed.');
    } finally { setBusy(false); }
  };

  const card = { background: '#fff', border: '1px solid #e2e8f0', borderRadius: '12px', padding: '1.25rem', marginBottom: '1rem' };
  const done = (ok) => ({ fontSize: '11px', fontWeight: 700, padding: '3px 8px', borderRadius: '6px', background: ok ? '#dcfce7' : '#fef3c7', color: ok ? '#166534' : '#92400e' });
  const btn = { background: '#0f172a', color: '#fff', border: 'none', padding: '9px 16px', borderRadius: '8px', fontSize: '13px', fontWeight: 600, cursor: busy ? 'wait' : 'pointer' };

  return (
    <div style={{ minHeight: '100vh', background: '#f1f5f9', display: 'flex', justifyContent: 'center', padding: '3rem 1rem', fontFamily: 'Inter, system-ui, sans-serif' }}>
      <div style={{ maxWidth: '560px', width: '100%' }}>
        <h2 style={{ margin: '0 0 4px', color: '#0f172a' }}>Mandatory Security Setup</h2>
        <p style={{ margin: '0 0 1.5rem', color: '#475569', fontSize: '14px' }}>
          Before you can use LexCorp you must configure <strong>both</strong> login factors. You will sign in with either of them afterwards.
          {me && <><br /><span style={{ fontFamily: 'monospace', fontSize: '12px' }}>{me.did}</span></>}
        </p>

        {error && <div style={{ background: '#fef2f2', border: '1px solid #fecaca', color: '#991b1b', padding: '0.75rem', borderRadius: '8px', fontSize: '13px', marginBottom: '1rem' }}>{error}</div>}

        <div style={card}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <strong>Step 1 · Login Authenticator (TOTP 1)</strong>
            <span style={done(me?.is_totp_enabled)}>{me?.is_totp_enabled ? 'CONFIGURED' : 'REQUIRED'}</span>
          </div>
          {!me?.is_totp_enabled && !totp && (
            <button style={{ ...btn, marginTop: '12px' }} disabled={busy} onClick={startTotp}>Set up authenticator app</button>
          )}
          {totp && (
            <form onSubmit={verifyTotp} style={{ marginTop: '12px', display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
              <img src={totp.qr_data_uri} alt="Authenticator QR" style={{ width: '150px', height: '150px', border: '1px solid #e2e8f0', borderRadius: '8px' }} />
              <div style={{ flex: 1 }}>
                <p style={{ fontSize: '12px', color: '#475569', margin: '0 0 6px' }}>Scan with Google/Microsoft Authenticator, or enter this key manually:</p>
                <code style={{ fontSize: '12px', wordBreak: 'break-all', userSelect: 'all' }}>{totp.secret}</code>
                <input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} maxLength={6} placeholder="6-digit code" inputMode="numeric"
                  style={{ display: 'block', width: '100%', margin: '10px 0', padding: '9px', borderRadius: '8px', border: '1px solid #cbd5e1', boxSizing: 'border-box' }} />
                <button type="submit" style={btn} disabled={busy || code.length !== 6}>Verify &amp; enable</button>
              </div>
            </form>
          )}
        </div>

        <div style={card}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <strong>Step 2 · Login Passkey (Passkey 1)</strong>
            <span style={done(me?.has_login_passkey)}>{me?.has_login_passkey ? 'CONFIGURED' : 'REQUIRED'}</span>
          </div>
          {!me?.has_login_passkey && (
            <>
              <p style={{ fontSize: '12px', color: '#475569', margin: '8px 0' }}>Uses this device's platform authenticator (e.g. Windows Hello). Your device will ask for your PIN, fingerprint or face.</p>
              <button style={btn} disabled={busy} onClick={setupPasskey}>Register Login Passkey</button>
            </>
          )}
        </div>

        <button onClick={onSignOut} style={{ background: 'none', border: 'none', color: '#64748b', fontSize: '13px', cursor: 'pointer', textDecoration: 'underline' }}>Sign out</button>
      </div>
    </div>
  );
}
