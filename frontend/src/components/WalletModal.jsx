import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  createNewWallet,
  importWallet,
  unlockWallet,
  hasEncryptedWallet,
  removeWallet
} from '../services/walletCore';

export default function WalletModal({ isOpen, onClose, onUnlocked, onAuthenticated, forceLogin = false }) {
  const [mode, setMode] = useState('unlock'); // 'unlock', 'create', 'import', 'show_phrase'
  const [password, setPassword] = useState('');
  const [importKey, setImportKey] = useState('');
  const [createdPhrase, setCreatedPhrase] = useState('');
  const [createdAddress, setCreatedAddress] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [loginMethod, setLoginMethod] = useState('password');
  const [loginAddress, setLoginAddress] = useState('');
  const [otpCode, setOtpCode] = useState('');

  const walletExists = hasEncryptedWallet();

  useEffect(() => {
    if (isOpen) {
      setError('');
      setPassword('');
      setImportKey('');
      if (walletExists || forceLogin) {
        setMode('unlock');
      } else {
        setMode('create');
      }
    }
  }, [isOpen, walletExists, forceLogin]);

  if (!isOpen) return null;

  const handleUnlock = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    setStatusMsg('Decrypting secure enclave...');

    try {
      const wallet = await unlockWallet(password);
      onUnlocked(wallet);
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to unlock wallet');
    } finally {
      setLoading(false);
      setStatusMsg('');
    }
  };

  const handleTotpLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const result = await axios.post('/api/auth/login/totp', { wallet_address: loginAddress, token: otpCode });
      onAuthenticated(result.data);
      onClose();
    } catch (err) {
      setError(err.response?.data?.detail || 'Mobile authenticator login failed.');
    } finally {
      setLoading(false);
    }
  };

  const decodeBase64Url = (value) => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (char) => char.charCodeAt(0));
  const encodeBase64Url = (value) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const encodeHex = (value) => Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, '0')).join('');

  const handlePasskeyLogin = async () => {
    setError('');
    setLoading(true);
    try {
      const optionResponse = await axios.post('/api/auth/login/passkey/options', { wallet_address: loginAddress });
      const options = optionResponse.data.options;
      const credential = await navigator.credentials.get({
        publicKey: {
          ...options,
          challenge: decodeBase64Url(options.challenge),
          allowCredentials: (options.allowCredentials || []).map((item) => ({ ...item, id: decodeBase64Url(item.id) })),
        },
      });
      if (!credential) throw new Error('Passkey prompt was cancelled.');
      const result = await axios.post('/api/auth/login/passkey/verify', {
        wallet_address: loginAddress,
        credential_id: encodeHex(credential.rawId),
        response: {
          id: credential.id,
          rawId: encodeBase64Url(credential.rawId),
          type: credential.type,
          response: {
            authenticatorData: encodeBase64Url(credential.response.authenticatorData),
            clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
            signature: encodeBase64Url(credential.response.signature),
            userHandle: credential.response.userHandle ? encodeBase64Url(credential.response.userHandle) : null,
          },
        },
      });
      onAuthenticated(result.data);
      onClose();
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Passkey login failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    setStatusMsg('Generating high-entropy cryptographic keypair...');

    try {
      const wallet = await createNewWallet(password);
      setCreatedAddress(wallet.address);
      setCreatedPhrase(wallet.mnemonic ? wallet.mnemonic.phrase : 'Private key generated directly');
      setMode('show_phrase');
    } catch (err) {
      setError(err.message || 'Failed to create wallet');
    } finally {
      setLoading(false);
      setStatusMsg('');
    }
  };

  const handleImport = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    setStatusMsg('Importing and encrypting key container...');

    try {
      const wallet = await importWallet(importKey, password);
      onUnlocked(wallet);
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to import wallet');
    } finally {
      setLoading(false);
      setStatusMsg('');
    }
  };

  const handleFinishCreation = async () => {
    // Unlock with the password we used
    try {
      const wallet = await unlockWallet(password);
      onUnlocked(wallet);
      onClose();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleReset = () => {
    if (window.confirm('Are you sure you want to remove the current wallet from this browser? Make sure you have your backup phrase/private key saved!')) {
      removeWallet();
      setMode('create');
      setError('');
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(15, 23, 42, 0.7)',
      backdropFilter: 'blur(4px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999,
      padding: '1rem'
    }}>
      <div style={{
        background: '#ffffff',
        borderRadius: '16px',
        maxWidth: '480px',
        width: '100%',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
        border: '1px solid #e2e8f0',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Header */}
        <div style={{
          background: '#0f172a',
          color: '#ffffff',
          padding: '1.25rem 1.5rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: '700', letterSpacing: '0.025em' }}>
              LexCorp Authentication
            </h3>
            <p style={{ margin: '2px 0 0', fontSize: '11px', color: '#94a3b8' }}>
              Secure Identity Verification (Consortium 13371)
            </p>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: '#94a3b8',
              fontSize: '18px',
              cursor: 'pointer'
            }}
          >
            ✕
          </button>
        </div>

        {/* Content Body */}
        <div style={{ padding: '1.5rem' }}>
          {mode === 'unlock' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '6px', marginBottom: '1rem' }}>
              {[
                ['password', 'Password'],
                ['mobile', 'Mobile Auth'],
                ['passkey', 'Passkey']
              ].map(([method, label]) => (
                <button
                  key={method}
                  type="button"
                  onClick={() => setLoginMethod(method)}
                  style={{ background: loginMethod === method ? '#dbeafe' : '#f8fafc', color: loginMethod === method ? '#1d4ed8' : '#475569', border: `1px solid ${loginMethod === method ? '#93c5fd' : '#cbd5e1'}`, padding: '8px 4px', borderRadius: '6px', fontSize: '11px', fontWeight: '600', cursor: 'pointer' }}
                >
                  {label}
                </button>
              ))}
            </div>
          )}

          {error && (
            <div style={{
              background: '#fef2f2',
              border: '1px solid #fecaca',
              color: '#991b1b',
              padding: '0.75rem',
              borderRadius: '8px',
              fontSize: '12px',
              marginBottom: '1rem'
            }}>
              {error}
            </div>
          )}

          {/* Mode: UNLOCK WALLET */}
          {mode === 'unlock' && loginMethod !== 'password' && (
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>Wallet Address</label>
              <input type="text" value={loginAddress} onChange={(e) => setLoginAddress(e.target.value)} placeholder="0x..." required style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '14px', boxSizing: 'border-box' }} />
            </div>
          )}

          {mode === 'unlock' && loginMethod === 'mobile' && (
            <form onSubmit={handleTotpLogin}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>6-Digit Authenticator Code</label>
              <input type="text" inputMode="numeric" maxLength={6} value={otpCode} onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))} required style={{ width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '18px', letterSpacing: '4px', boxSizing: 'border-box' }} />
              <button type="submit" disabled={loading} style={{ width: '100%', marginTop: '12px', background: '#2563eb', color: '#fff', border: 'none', padding: '12px', borderRadius: '8px', fontSize: '14px', fontWeight: '600' }}>{loading ? 'Verifying...' : 'Login with Mobile Auth'}</button>
            </form>
          )}

          {mode === 'unlock' && loginMethod === 'passkey' && (
            <button type="button" onClick={handlePasskeyLogin} disabled={loading} style={{ width: '100%', background: '#2563eb', color: '#fff', border: 'none', padding: '12px', borderRadius: '8px', fontSize: '14px', fontWeight: '600' }}>
              {loading ? 'Waiting for passkey...' : 'Login with Passkey'}
            </button>
          )}

          {mode === 'unlock' && loginMethod === 'password' && (
            <form onSubmit={handleUnlock}>
              <p style={{ fontSize: '13px', color: '#475569', marginBottom: '1rem' }}>
                Enter your local PIN/Password to decrypt your private key and access your identity.
              </p>
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>
                  Wallet Passphrase
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter encryption password"
                  autoFocus
                  required
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    border: '1px solid #cbd5e1',
                    fontSize: '14px',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                style={{
                  width: '100%',
                  background: '#2563eb',
                  color: '#ffffff',
                  border: 'none',
                  padding: '12px',
                  borderRadius: '8px',
                  fontSize: '14px',
                  fontWeight: '600',
                  cursor: loading ? 'not-allowed' : 'pointer'
                }}
              >
                {loading ? (statusMsg || 'Unlocking...') : 'Unlock & Authenticate'}
              </button>

              <div style={{ marginTop: '1.25rem', textAlign: 'center', fontSize: '12px' }}>
                <button
                  type="button"
                  onClick={handleReset}
                  style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: 0 }}
                >
                  Reset Identity
                </button>
              </div>
            </form>
          )}

          {/* Mode: CREATE WALLET */}
          {mode === 'create' && (
            <form onSubmit={handleCreate}>
              <p style={{ fontSize: '13px', color: '#475569', marginBottom: '1rem' }}>
                Generate a new cryptographic EVM keypair directly in your browser.
              </p>
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>
                  Create Encryption Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Minimum 6 characters"
                  required
                  minLength={6}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    border: '1px solid #cbd5e1',
                    fontSize: '14px',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                style={{
                  width: '100%',
                  background: '#0f172a',
                  color: '#ffffff',
                  border: 'none',
                  padding: '12px',
                  borderRadius: '8px',
                  fontSize: '14px',
                  fontWeight: '600',
                  cursor: loading ? 'not-allowed' : 'pointer'
                }}
              >
                {loading ? (statusMsg || 'Creating Keyring...') : 'Generate New Keyring'}
              </button>

              <div style={{ marginTop: '1.25rem', textAlign: 'center', fontSize: '12px' }}>
                <span style={{ color: '#64748b' }}>Already have a keypair? </span>
                <button
                  type="button"
                  onClick={() => setMode('import')}
                  style={{ background: 'none', border: 'none', color: '#2563eb', fontWeight: '600', cursor: 'pointer' }}
                >
                  Import Mnemonic/Key
                </button>
              </div>
            </form>
          )}

          {/* Mode: SHOW RECOVERY PHRASE */}
          {mode === 'show_phrase' && (
            <div>
              <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', padding: '0.75rem', borderRadius: '8px', marginBottom: '1rem' }}>
                <div style={{ fontSize: '12px', fontWeight: '700', color: '#166534', marginBottom: '4px' }}>
                  Wallet Created Successfully!
                </div>
                <div style={{ fontSize: '11px', color: '#15803d', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                  Address: {createdAddress}
                </div>
              </div>

              <label style={{ display: 'block', fontSize: '12px', fontWeight: '700', color: '#334155', marginBottom: '6px' }}>
                Secret Recovery Phrase (Write this down!):
              </label>
              <div style={{
                background: '#f8fafc',
                border: '1px dashed #cbd5e1',
                padding: '1rem',
                borderRadius: '8px',
                fontFamily: 'monospace',
                fontSize: '13px',
                color: '#0f172a',
                lineHeight: '1.6',
                marginBottom: '1.25rem',
                wordBreak: 'break-word',
                userSelect: 'all'
              }}>
                {createdPhrase}
              </div>

              <button
                type="button"
                onClick={handleFinishCreation}
                style={{
                  width: '100%',
                  background: '#16a34a',
                  color: '#ffffff',
                  border: 'none',
                  padding: '12px',
                  borderRadius: '8px',
                  fontSize: '14px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                I Have Saved It, Continue
              </button>
            </div>
          )}

          {/* Mode: IMPORT WALLET */}
          {mode === 'import' && (
            <form onSubmit={handleImport}>
              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>
                  Mnemonic (12 words) or Private Key (0x...)
                </label>
                <textarea
                  value={importKey}
                  onChange={(e) => setImportKey(e.target.value)}
                  placeholder="Paste your 12-word recovery phrase or 0x... private key"
                  required
                  rows={3}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    border: '1px solid #cbd5e1',
                    fontSize: '13px',
                    boxSizing: 'border-box',
                    fontFamily: 'monospace'
                  }}
                />
              </div>

              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>
                  Encryption Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password to encrypt this wallet locally"
                  required
                  minLength={6}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    border: '1px solid #cbd5e1',
                    fontSize: '14px',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                style={{
                  width: '100%',
                  background: '#2563eb',
                  color: '#ffffff',
                  border: 'none',
                  padding: '12px',
                  borderRadius: '8px',
                  fontSize: '14px',
                  fontWeight: '600',
                  cursor: loading ? 'not-allowed' : 'pointer'
                }}
              >
                {loading ? (statusMsg || 'Encrypting & Storing...') : 'Import Wallet'}
              </button>

              <div style={{ marginTop: '1.25rem', textAlign: 'center', fontSize: '12px' }}>
                <button
                  type="button"
                  onClick={() => setMode(walletExists ? 'unlock' : 'create')}
                  style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
