import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ethers } from 'ethers';
import {
  importWallet,
  unlockWallet,
  hasEncryptedWallet,
} from '../services/walletCore';

export default function WalletModal({ isOpen, onClose, onUnlocked, onAuthenticated, forceLogin = false }) {
  const [activeTab, setActiveTab] = useState('import');
  const [importKey, setImportKey] = useState('');
  const [importOtp, setImportOtp] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [loginAddress, setLoginAddress] = useState('');
  const [otpCode, setOtpCode] = useState('');

  const walletStored = hasEncryptedWallet();

  useEffect(() => {
    if (isOpen) {
      setError('');
      setImportKey('');
      setImportOtp('');
      setOtpCode('');
      // If a wallet is already stored, default to Mobile Auth or Passkey, else default to First-time Import
      if (walletStored) {
        setActiveTab('mobile');
      } else {
        setActiveTab('import');
      }
    }
  }, [isOpen, walletStored]);

  if (!isOpen) return null;

  const handleImportWithOtp = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    setStatusMsg('Verifying credentials...');

    try {
      // 1. Derive wallet from Key/Phrase
      let wallet;
      const keyOrPhrase = importKey.trim();
      if (keyOrPhrase.includes(' ')) {
        wallet = ethers.Wallet.fromPhrase(keyOrPhrase);
      } else {
        wallet = new ethers.Wallet(keyOrPhrase);
      }

      // 2. Verify Single-Use 3-Hour OTP with backend
      await axios.post('/api/auth/otp/verify-import', {
        wallet_address: wallet.address,
        pin: importOtp.trim()
      });

      // 3. Save wallet locally without passwords
      await importWallet(keyOrPhrase);

      // 4. Authenticate & sign in with SIWE
      await onUnlocked(wallet);
      onClose();
    } catch (err) {
      console.error('Import error:', err);
      setError(err.response?.data?.detail || err.message || 'Account import and verification failed.');
    } finally {
      setLoading(false);
      setStatusMsg('');
    }
  };

  const handleTotpLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    setStatusMsg('Authenticating session...');
    try {
      const result = await axios.post('/api/auth/login/totp', {
        wallet_address: loginAddress.trim(),
        token: otpCode.trim()
      });
      onAuthenticated(result.data);
      onClose();
    } catch (err) {
      setError(err.response?.data?.detail || 'Mobile authenticator login failed.');
    } finally {
      setLoading(false);
      setStatusMsg('');
    }
  };

  const decodeBase64Url = (value) => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (char) => char.charCodeAt(0));
  const encodeBase64Url = (value) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const encodeHex = (value) => Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, '0')).join('');

  const handlePasskeyLogin = async () => {
    if (!loginAddress.trim()) {
      setError('Please enter your wallet address first.');
      return;
    }
    setError('');
    setLoading(true);
    setStatusMsg('Requesting passkey authentication...');
    try {
      const optionResponse = await axios.post('/api/auth/login/passkey/options', { wallet_address: loginAddress.trim() });
      const options = optionResponse.data.options;
      const credential = await navigator.credentials.get({
        publicKey: {
          ...options,
          challenge: decodeBase64Url(options.challenge),
          allowCredentials: (options.allowCredentials || []).map((item) => ({ ...item, id: decodeBase64Url(item.id) })),
          userVerification: 'required',
        },
      });
      if (!credential) throw new Error('Passkey prompt was cancelled.');
      const result = await axios.post('/api/auth/login/passkey/verify', {
        wallet_address: loginAddress.trim(),
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
      setStatusMsg('');
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(15, 23, 42, 0.75)',
      backdropFilter: 'blur(6px)',
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
              Passwordless Identity &amp; Key Infrastructure (Consortium 13371)
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
          {/* Tab Selection */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '6px', marginBottom: '1.5rem' }}>
            {[
              ['import', 'First-Time Setup'],
              ['mobile', 'Mobile Auth'],
              ['passkey', 'Passkey']
            ].map(([tab, label]) => (
              <button
                key={tab}
                type="button"
                onClick={() => { setActiveTab(tab); setError(''); }}
                style={{
                  background: activeTab === tab ? '#0f172a' : '#f8fafc',
                  color: activeTab === tab ? '#ffffff' : '#475569',
                  border: `1px solid ${activeTab === tab ? '#0f172a' : '#cbd5e1'}`,
                  padding: '8px 4px',
                  borderRadius: '6px',
                  fontSize: '11px',
                  fontWeight: '600',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                {label}
              </button>
            ))}
          </div>

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

          {statusMsg && (
            <div style={{
              background: '#eff6ff',
              border: '1px solid #bfdbfe',
              color: '#1e40af',
              padding: '0.75rem',
              borderRadius: '8px',
              fontSize: '12px',
              marginBottom: '1rem'
            }}>
              {statusMsg}
            </div>
          )}

          {/* First-Time Setup (Key + PIN) */}
          {activeTab === 'import' && (
            <form onSubmit={handleImportWithOtp}>
              <p style={{ fontSize: '13px', color: '#475569', marginBottom: '1rem', lineHeight: '1.4' }}>
                First time logging in? Enter your provisioned recovery phrase or private key along with the 12-digit single-use PIN provided by your administrator.
              </p>

              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>
                  Wallet Passphrase or Private Key
                </label>
                <textarea
                  value={importKey}
                  onChange={(e) => setImportKey(e.target.value)}
                  placeholder="Paste 12/24-word recovery phrase or 0x private key"
                  required
                  rows={2}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    border: '1px solid #cbd5e1',
                    fontSize: '13px',
                    fontFamily: 'monospace',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>
                  One-Time Setup PIN (12 Digits)
                </label>
                <input
                  type="text"
                  value={importOtp}
                  onChange={(e) => setImportOtp(e.target.value)}
                  placeholder="e.g. 123456789012"
                  required
                  maxLength={12}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    borderRadius: '8px',
                    border: '1px solid #cbd5e1',
                    fontSize: '14px',
                    fontFamily: 'monospace',
                    letterSpacing: '1px',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                style={{
                  width: '100%',
                  background: '#16a34a',
                  color: '#fff',
                  border: 'none',
                  padding: '12px',
                  borderRadius: '8px',
                  fontSize: '14px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                {loading ? 'Verifying & Initializing...' : 'Verify & Setup Account'}
              </button>
            </form>
          )}

          {/* Returning User: Mobile Authenticator (TOTP Factor 1) */}
          {activeTab === 'mobile' && (
            <form onSubmit={handleTotpLogin}>
              <p style={{ fontSize: '13px', color: '#475569', marginBottom: '1rem', lineHeight: '1.4' }}>
                Authenticate securely using your registered Mobile Authenticator app (Factor 1).
              </p>

              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>
                Wallet Address
              </label>
              <input
                type="text"
                value={loginAddress}
                onChange={(e) => setLoginAddress(e.target.value)}
                placeholder="0x..."
                required
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  borderRadius: '8px',
                  border: '1px solid #cbd5e1',
                  fontSize: '13px',
                  fontFamily: 'monospace',
                  marginBottom: '1rem',
                  boxSizing: 'border-box'
                }}
              />

              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>
                6-Digit Authenticator Code
              </label>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                required
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  borderRadius: '8px',
                  border: '1px solid #cbd5e1',
                  fontSize: '18px',
                  letterSpacing: '4px',
                  textAlign: 'center',
                  fontFamily: 'monospace',
                  boxSizing: 'border-box'
                }}
              />

              <button
                type="submit"
                disabled={loading}
                style={{
                  width: '100%',
                  marginTop: '1rem',
                  background: '#2563eb',
                  color: '#fff',
                  border: 'none',
                  padding: '12px',
                  borderRadius: '8px',
                  fontSize: '14px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                {loading ? 'Authenticating...' : 'Login with Mobile Auth'}
              </button>
            </form>
          )}

          {/* Returning User: Hardware Passkey / WebAuthn */}
          {activeTab === 'passkey' && (
            <div>
              <p style={{ fontSize: '13px', color: '#475569', marginBottom: '1rem', lineHeight: '1.4' }}>
                Authenticate passwordlessly using Windows Hello, Touch ID, or a FIDO2 hardware security key.
              </p>

              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>
                Wallet Address
              </label>
              <input
                type="text"
                value={loginAddress}
                onChange={(e) => setLoginAddress(e.target.value)}
                placeholder="0x..."
                required
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  borderRadius: '8px',
                  border: '1px solid #cbd5e1',
                  fontSize: '13px',
                  fontFamily: 'monospace',
                  marginBottom: '1rem',
                  boxSizing: 'border-box'
                }}
              />

              <button
                type="button"
                onClick={handlePasskeyLogin}
                disabled={loading}
                style={{
                  width: '100%',
                  background: '#2563eb',
                  color: '#fff',
                  border: 'none',
                  padding: '12px',
                  borderRadius: '8px',
                  fontSize: '14px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                {loading ? 'Waiting for Security Key...' : 'Login with Passkey'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
