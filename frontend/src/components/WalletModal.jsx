import React, { useState, useEffect } from 'react';
import { parseWalletInput, storeEncryptedWallet } from '../services/walletCore';
import {
  getNonce,
  provisionWallet,
  loginWithTotp,
  loginWithPasskey,
  requestAdminAssistanceWithWallet,
} from '../services/api';

const s = {
  label: { display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' },
  input: { width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '13px', fontFamily: 'monospace', boxSizing: 'border-box' },
  primary: (busy) => ({ width: '100%', background: '#0f172a', color: '#fff', border: 'none', padding: '11px', borderRadius: '8px', fontSize: '13px', fontWeight: '600', cursor: busy ? 'wait' : 'pointer', opacity: busy ? 0.7 : 1 }),
  secondary: (busy) => ({ width: '100%', background: '#fff', color: '#0f172a', border: '1px solid #0f172a', padding: '11px', borderRadius: '8px', fontSize: '13px', fontWeight: '600', cursor: busy ? 'wait' : 'pointer', opacity: busy ? 0.7 : 1 }),
  hint: { fontSize: '12px', color: '#475569', marginBottom: '1rem', lineHeight: '1.45' },
  field: { marginBottom: '1rem' },
};

const errorText = (err, fallback) => err?.response?.data?.detail || err?.message || fallback;

export default function WalletModal({ isOpen, onClose, onAuthenticated, notice }) {
  const [activeTab, setActiveTab] = useState('signin');
  const [loginAddress, setLoginAddress] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [importKey, setImportKey] = useState('');
  const [importPin, setImportPin] = useState('');
  const [resetKey, setResetKey] = useState('');
  const [resetReason, setResetReason] = useState('');
  const [error, setError] = useState('');
  const [statusMsg, setStatusMsg] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      // The wallet address is typed by the user each time; it is never pre-filled from storage.
      setError(''); setStatusMsg(''); setOtpCode(''); setImportKey(''); setImportPin(''); setResetKey('');
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const run = async (label, fn) => {
    setError(''); setStatusMsg(label); setLoading(true);
    try { await fn(); } finally { setLoading(false); setStatusMsg(''); }
  };

  const signNonce = async (wallet) => {
    const { nonce, message } = await getNonce(wallet.address);
    const signature = await wallet.signMessage(message);
    return { nonce, message, signature };
  };

  const handleTotpLogin = (e) => {
    e.preventDefault();
    run('Verifying Login Authenticator (TOTP 1)...', async () => {
      try {
        const result = await loginWithTotp(loginAddress.trim(), otpCode.trim());
        await onAuthenticated(result);
        onClose();
      } catch (err) {
        setError(errorText(err, 'Sign-in failed.'));
      }
    });
  };

  const handlePasskeyLogin = () => {
    if (!loginAddress.trim()) { setError('Type your wallet address first.'); return; }
    run('Waiting for Login Passkey (Passkey 1)...', async () => {
      try {
        const result = await loginWithPasskey(loginAddress.trim());
        await onAuthenticated(result);
        onClose();
      } catch (err) {
        setError(errorText(err, 'Passkey sign-in failed.'));
      }
    });
  };

  const handleImport = (e) => {
    e.preventDefault();
    run('Verifying wallet ownership and provisioning PIN...', async () => {
      try {
        const wallet = parseWalletInput(importKey);
        const { nonce, message, signature } = await signNonce(wallet);
        const result = await provisionWallet(message, signature, nonce, importPin.trim());
        setStatusMsg('Encrypting wallet on this device...');
        await storeEncryptedWallet(wallet, result.wallet_key);
        setImportKey(''); setImportPin('');
        await onAuthenticated(result);
        onClose();
      } catch (err) {
        setError(errorText(err, 'Wallet import failed.'));
      }
    });
  };

  const handleResetRequest = (e) => {
    e.preventDefault();
    run('Signing admin assistance request...', async () => {
      try {
        const wallet = parseWalletInput(resetKey);
        const { nonce, message, signature } = await signNonce(wallet);
        const res = await requestAdminAssistanceWithWallet(message, signature, nonce, resetReason || 'Locked out of login factors');
        setResetKey('');
        setStatusMsg('');
        setError('');
        alert(res.message);
        setActiveTab('signin');
      } catch (err) {
        setError(errorText(err, 'Request failed.'));
      }
    });
  };

  const tabs = [['signin', 'Sign In'], ['import', 'First-Time Import'], ['locked', 'Locked Out?']];

  return (
    <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(15, 23, 42, 0.75)', backdropFilter: 'blur(6px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999, padding: '1rem' }}>
      <div style={{ background: '#fff', borderRadius: '16px', maxWidth: '480px', width: '100%', boxShadow: '0 25px 50px -12px rgba(0,0,0,0.25)', border: '1px solid #e2e8f0', overflow: 'hidden' }}>
        <div style={{ background: '#0f172a', color: '#fff', padding: '1.25rem 1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: '700' }}>LexCorp Authentication</h3>
            <p style={{ margin: '2px 0 0', fontSize: '11px', color: '#94a3b8' }}>Wallet identity · did:ethr:13371 · purpose-bound MFA</p>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '18px', cursor: 'pointer' }}>✕</button>
        </div>

        <div style={{ padding: '1.5rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '6px', marginBottom: '1.25rem' }}>
            {tabs.map(([tab, label]) => (
              <button key={tab} type="button" onClick={() => { setActiveTab(tab); setError(''); }}
                style={{ background: activeTab === tab ? '#0f172a' : '#f8fafc', color: activeTab === tab ? '#fff' : '#475569', border: `1px solid ${activeTab === tab ? '#0f172a' : '#cbd5e1'}`, padding: '8px 4px', borderRadius: '6px', fontSize: '11px', fontWeight: '600', cursor: 'pointer' }}>
                {label}
              </button>
            ))}
          </div>

          {notice && !error && (
            <div style={{ background: '#fffbeb', border: '1px solid #fde68a', color: '#92400e', padding: '0.75rem', borderRadius: '8px', fontSize: '12px', marginBottom: '1rem' }}>{notice}</div>
          )}
          {error && (
            <div style={{ background: '#fef2f2', border: '1px solid #fecaca', color: '#991b1b', padding: '0.75rem', borderRadius: '8px', fontSize: '12px', marginBottom: '1rem' }}>{error}</div>
          )}
          {statusMsg && (
            <div style={{ background: '#eff6ff', border: '1px solid #bfdbfe', color: '#1e40af', padding: '0.75rem', borderRadius: '8px', fontSize: '12px', marginBottom: '1rem' }}>{statusMsg}</div>
          )}

          {activeTab === 'signin' && (
            <form onSubmit={handleTotpLogin}>
              <p style={s.hint}>Type your wallet address, then use your <strong>Login Authenticator (TOTP 1)</strong> or <strong>Login Passkey (Passkey 1)</strong>.</p>
              <div style={s.field}>
                <label style={s.label}>Wallet Address</label>
                <input value={loginAddress} onChange={(e) => setLoginAddress(e.target.value)} placeholder="0x..." autoComplete="off" spellCheck={false} required style={s.input} />
              </div>
              <div style={s.field}>
                <label style={s.label}>Login Authenticator Code (TOTP 1)</label>
                <input value={otpCode} onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))} placeholder="6-digit code" inputMode="numeric" maxLength={6} style={s.input} />
              </div>
              <button type="submit" disabled={loading || otpCode.length !== 6} style={{ ...s.primary(loading), marginBottom: '8px' }}>Sign in with Authenticator</button>
              <button type="button" onClick={handlePasskeyLogin} disabled={loading} style={s.secondary(loading)}>Sign in with Login Passkey</button>
            </form>
          )}

          {activeTab === 'import' && (
            <form onSubmit={handleImport}>
              <p style={s.hint}>First time on this device, or re-provisioned by an administrator? Enter your wallet recovery phrase or private key and the <strong>single-use provisioning PIN</strong> (valid 3 hours) from your administrator. The key is encrypted on this device and never sent to the server.</p>
              <div style={s.field}>
                <label style={s.label}>Recovery Phrase or Private Key</label>
                <textarea value={importKey} onChange={(e) => setImportKey(e.target.value)} placeholder="12/24-word phrase or 0x private key" rows={2} required autoComplete="off" spellCheck={false} style={s.input} />
              </div>
              <div style={s.field}>
                <label style={s.label}>Provisioning PIN</label>
                <input value={importPin} onChange={(e) => setImportPin(e.target.value)} placeholder="12-character PIN" maxLength={12} required autoComplete="off" spellCheck={false} style={s.input} />
              </div>
              <button type="submit" disabled={loading} style={s.primary(loading)}>Import Wallet &amp; Continue to Security Setup</button>
            </form>
          )}

          {activeTab === 'locked' && (
            <form onSubmit={handleResetRequest}>
              <p style={s.hint}>Lost your Login Authenticator or Login Passkey? Login factors cannot be reset self-service. Sign a request with your wallet key; an administrator will verify it out-of-band and issue a new provisioning PIN.</p>
              <div style={s.field}>
                <label style={s.label}>Recovery Phrase or Private Key (used only to sign, not stored)</label>
                <textarea value={resetKey} onChange={(e) => setResetKey(e.target.value)} rows={2} required autoComplete="off" spellCheck={false} style={s.input} />
              </div>
              <div style={s.field}>
                <label style={s.label}>Reason</label>
                <input value={resetReason} onChange={(e) => setResetReason(e.target.value)} placeholder="e.g. phone replaced" style={{ ...s.input, fontFamily: 'inherit' }} />
              </div>
              <button type="submit" disabled={loading} style={s.primary(loading)}>REQUEST ADMIN ASSISTANCE</button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
