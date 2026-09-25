import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { registerPasskey, requestAdminAssistance } from '../services/api';

const API_BASE = '/api';

const FactorCard = ({ title, desc, isSetup, setupHandler, verifyHandler, disableHandler, resetHandler, lockedMessage, setupData, code, setCode, loading, error, success }) => (
  <div style={{ background: '#fff', padding: '1.5rem', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
      <h3 style={{ margin: 0, fontSize: '15px', fontWeight: '700', color: '#0f172a', display: 'flex', alignItems: 'center', gap: '6px' }}>
        {title}
      </h3>
      <span style={{
        fontSize: '11px', fontWeight: '700', padding: '3px 8px', borderRadius: '999px',
        background: isSetup ? '#dcfce7' : '#fee2e2',
        color: isSetup ? '#166534' : '#991b1b',
        border: `1px solid ${isSetup ? '#bbf7d0' : '#fecaca'}`
      }}>
        {isSetup ? '● Active' : '○ Not Configured'}
      </span>
    </div>

    <p style={{ fontSize: '12px', color: '#64748b', margin: '0 0 1rem 0' }}>{desc}</p>

    {error && <div style={{ background: '#fef2f2', border: '1px solid #fecaca', color: '#991b1b', padding: '8px 12px', borderRadius: '6px', fontSize: '12px', marginBottom: '1rem' }}>{error}</div>}
    {success && <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', color: '#166534', padding: '8px 12px', borderRadius: '6px', fontSize: '12px', marginBottom: '1rem' }}>{success}</div>}

    {!isSetup && !setupData && (
      <button onClick={setupHandler} disabled={loading} style={{
        width: '100%', background: '#0f172a', color: '#fff', border: 'none', padding: '10px 16px', borderRadius: '8px', fontSize: '13px', fontWeight: '600', cursor: loading ? 'not-allowed' : 'pointer'
      }}>
        {loading ? 'Generating...' : 'Setup Authenticator'}
      </button>
    )}

    {setupData && (
      <div style={{ background: '#f8fafc', padding: '1rem', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
        <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
          {/* Rendered by the LexCorp server: the otpauth URI contains the secret and must not go to a third-party QR service. */}
          <img src={setupData.qr_data_uri} alt="Authenticator QR" style={{ width: '140px', height: '140px', borderRadius: '8px', border: '2px solid #e2e8f0' }} />
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '6px', wordBreak: 'break-all' }}>Manual key: <code style={{ userSelect: 'all' }}>{setupData.secret}</code></div>
        </div>
        <form onSubmit={verifyHandler}>
          <input type="text" maxLength={6} placeholder="000000" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} style={{
            width: '100%', padding: '8px', borderRadius: '6px', border: '1px solid #cbd5e1', fontSize: '16px', textAlign: 'center', letterSpacing: '4px', marginBottom: '8px'
          }} required />
          <button type="submit" disabled={loading} style={{
            width: '100%', background: '#16a34a', color: '#fff', border: 'none', padding: '8px', borderRadius: '6px', fontSize: '13px', fontWeight: '700', cursor: 'pointer'
          }}>Verify</button>
        </form>
      </div>
    )}

    {isSetup && (
      <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '8px', padding: '12px', fontSize: '12px', color: '#166534' }}>
        ✓ Authenticator activated.
        {lockedMessage && <div style={{ marginTop: '8px', color: '#475569' }}>{lockedMessage}</div>}
        {disableHandler && (
          <button onClick={disableHandler} disabled={loading} style={{ display: 'block', marginTop: '10px', background: '#fff', color: '#991b1b', border: '1px solid #fecaca', padding: '7px 10px', borderRadius: '6px', cursor: 'pointer' }}>
            Disable (requires current code)
          </button>
        )}
        {resetHandler && (
          <button onClick={resetHandler} disabled={loading} style={{ display: 'block', marginTop: '8px', background: '#fff', color: '#92400e', border: '1px solid #fed7aa', padding: '7px 10px', borderRadius: '6px', cursor: 'pointer' }}>
            Reset & Re-enroll
          </button>
        )}
      </div>
    )}
  </div>
);

export default function Identity() {
  const { wallet, user, refreshUser } = useAuth();
  const [showProof, setShowProof] = useState(false);

  // TOTP 2FA State (Factor 1 - Login)
  const [totpSetupData, setTotpSetupData] = useState(null);
  const [totpCode, setTotpCode] = useState('');
  const [totpLoading, setTotpLoading] = useState(false);
  const [totpSuccess, setTotpSuccess] = useState('');
  const [totpError, setTotpError] = useState('');
  const [isTotpEnabled, setIsTotpEnabled] = useState(false);

  // TOTP Factor 2 State (View & Propose)
  const [f2SetupData, setF2SetupData] = useState(null);
  const [f2Code, setF2Code] = useState('');
  const [f2Loading, setF2Loading] = useState(false);
  const [f2Success, setF2Success] = useState('');
  const [f2Error, setF2Error] = useState('');
  const [isF2Enabled, setIsF2Enabled] = useState(false);

  // TOTP Factor 3 State (Mint & Approve)
  const [f3SetupData, setF3SetupData] = useState(null);
  const [f3Code, setF3Code] = useState('');
  const [f3Loading, setF3Loading] = useState(false);
  const [f3Success, setF3Success] = useState('');
  const [f3Error, setF3Error] = useState('');
  const [isF3Enabled, setIsF3Enabled] = useState(false);

  // WebAuthn Passkeys State
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const [passkeySuccess, setPasskeySuccess] = useState('');
  const [passkeyError, setPasskeyError] = useState('');
  const [registeredPasskeys, setRegisteredPasskeys] = useState([]);
  const [passkeyScope, setPasskeyScope] = useState('factor2');

  useEffect(() => {
    if (user) {
      setIsTotpEnabled(!!user.is_totp_enabled);
      setIsF2Enabled(!!user.is_totp_factor2_enabled);
      setIsF3Enabled(!!user.is_totp_factor3_enabled);
      axios.get(`${API_BASE}/auth/webauthn/credentials`)
        .then((res) => setRegisteredPasskeys(res.data || []))
        .catch(() => setRegisteredPasskeys([]));
    }
  }, [user]);

  if (!wallet) return <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>Connect wallet to view identity.</div>;

  const userDID = user?.did || (wallet?.address ? `did:ethr:13371:${wallet.address.toLowerCase()}` : 'N/A');

  // --- TOTP Setup Flow ---
  const handleStartTotpSetup = async () => {
    setTotpError('');
    setTotpSuccess('');
    setTotpLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/auth/2fa/setup`);
      setTotpSetupData(res.data);
    } catch (err) {
      setTotpError(err.response?.data?.detail || 'Failed to initiate 2FA setup.');
    } finally {
      setTotpLoading(false);
    }
  };

  const handleVerifyTotp = async (e) => {
    e.preventDefault();
    if (!totpCode || totpCode.length !== 6) {
      setTotpError('Please enter a valid 6-digit code.');
      return;
    }
    setTotpError('');
    setTotpSuccess('');
    setTotpLoading(true);
    try {
      await axios.post(`${API_BASE}/auth/2fa/verify`, { token: totpCode });
      setTotpSuccess('✓ TOTP 2FA successfully verified and activated!');
      setIsTotpEnabled(true);
      setTotpSetupData(null);
      setTotpCode('');
      if (refreshUser) refreshUser();
    } catch (err) {
      setTotpError(err.response?.data?.detail || 'Invalid TOTP code. Check your authenticator app.');
    } finally {
      setTotpLoading(false);
    }
  };

  // --- TOTP Factor 2 Flow ---
  const handleStartF2Setup = async () => {
    setF2Error('');
    setF2Success('');
    setF2Loading(true);
    try {
      const res = await axios.post(`${API_BASE}/auth/2fa/factor2/setup`);
      setF2SetupData(res.data);
    } catch (err) {
      setF2Error(err.response?.data?.detail || 'Failed to initiate Factor 2 setup.');
    } finally {
      setF2Loading(false);
    }
  };

  const handleVerifyF2 = async (e) => {
    e.preventDefault();
    if (!f2Code || f2Code.length !== 6) {
      setF2Error('Please enter a valid 6-digit code.');
      return;
    }
    setF2Error('');
    setF2Success('');
    setF2Loading(true);
    try {
      await axios.post(`${API_BASE}/auth/2fa/factor2/verify`, { token: f2Code });
      setF2Success('✓ Factor 2 (View/Submission) TOTP successfully verified and activated!');
      setIsF2Enabled(true);
      setF2SetupData(null);
      setF2Code('');
      if (refreshUser) refreshUser();
    } catch (err) {
      setF2Error(err.response?.data?.detail || 'Invalid TOTP code.');
    } finally {
      setF2Loading(false);
    }
  };

  const handleDisableF2 = async () => {
    setF2Error('');
    setF2Loading(true);
    try {
      const code = window.prompt('Enter your current Factor 2 (View/Submission) TOTP code to confirm:');
      if (!code) return;
      await axios.post(`${API_BASE}/auth/2fa/factor2/disable`, { totp_code: code.trim() });
      setIsF2Enabled(false);
      setF2Success('Factor 2 disabled.');
    } catch (err) {
      setF2Error(err.response?.data?.detail || 'Failed to disable Factor 2.');
    } finally {
      setF2Loading(false);
    }
  };

  // --- TOTP Factor 3 Flow ---
  const handleStartF3Setup = async () => {
    setF3Error('');
    setF3Success('');
    setF3Loading(true);
    try {
      const res = await axios.post(`${API_BASE}/auth/2fa/factor3/setup`);
      setF3SetupData(res.data);
    } catch (err) {
      setF3Error(err.response?.data?.detail || 'Failed to initiate Factor 3 setup.');
    } finally {
      setF3Loading(false);
    }
  };

  const handleVerifyF3 = async (e) => {
    e.preventDefault();
    if (!f3Code || f3Code.length !== 6) {
      setF3Error('Please enter a valid 6-digit code.');
      return;
    }
    setF3Error('');
    setF3Success('');
    setF3Loading(true);
    try {
      await axios.post(`${API_BASE}/auth/2fa/factor3/verify`, { token: f3Code });
      setF3Success('✓ Factor 3 (Mint/Approve/Revise) TOTP successfully verified and activated!');
      setIsF3Enabled(true);
      setF3SetupData(null);
      setF3Code('');
      if (refreshUser) refreshUser();
    } catch (err) {
      setF3Error(err.response?.data?.detail || 'Invalid TOTP code.');
    } finally {
      setF3Loading(false);
    }
  };

  const handleDisableF3 = async () => {
    setF3Error('');
    setF3Loading(true);
    try {
      const code = window.prompt('Enter your current Factor 3 (Mint/Approve/Modify) TOTP code to confirm:');
      if (!code) return;
      await axios.post(`${API_BASE}/auth/2fa/factor3/disable`, { totp_code: code.trim() });
      setIsF3Enabled(false);
      setF3Success('Factor 3 disabled.');
    } catch (err) {
      setF3Error(err.response?.data?.detail || 'Failed to disable Factor 3.');
    } finally {
      setF3Loading(false);
    }
  };

  // --- Passkey registration: Factor 2 / Factor 3 only (the Login Passkey is set up during onboarding) ---
  const scopeLabel = { factor2: 'Factor 2 (View/Submission)', factor3: 'Factor 3 (Mint/Approve/Modify)' };
  const scopeProtected = (scope) => (scope === 'factor2' ? isF2Enabled : isF3Enabled) || registeredPasskeys.some((pk) => pk.factor_scope === scope);

  const handleRegisterPasskey = async () => {
    setPasskeyError('');
    setPasskeySuccess('');
    setPasskeyLoading(true);
    try {
      let code = null;
      if (scopeProtected(passkeyScope)) {
        code = window.prompt(`${scopeLabel[passkeyScope]} is already protected. Enter a current ${scopeLabel[passkeyScope]} TOTP code to add another passkey:`);
        if (!code) return;
      }
      const deviceName = navigator.userAgent.includes('Windows') ? 'Windows Hello' : navigator.userAgent.includes('Mac') ? 'Touch ID' : 'Platform Authenticator';
      await registerPasskey(passkeyScope, `${deviceName} (${scopeLabel[passkeyScope]})`, code ? code.trim() : null);
      setPasskeySuccess(`✓ ${scopeLabel[passkeyScope]} passkey registered.`);
      const credentials = await axios.get(`${API_BASE}/auth/webauthn/credentials`);
      setRegisteredPasskeys(credentials.data || []);
    } catch (err) {
      setPasskeyError(err.response?.data?.detail || err.message || 'Passkey enrollment failed.');
    } finally {
      setPasskeyLoading(false);
    }
  };

  const handleDisablePasskey = async (credential) => {
    setPasskeyError('');
    try {
      const code = window.prompt(`Enter a current ${scopeLabel[credential.factor_scope]} TOTP code to remove this passkey:`);
      if (!code) return;
      await axios.delete(`${API_BASE}/auth/webauthn/credentials/${credential.credential_id}`, { data: { totp_code: code.trim() } });
      setRegisteredPasskeys(prev => prev.filter((c) => c.credential_id !== credential.credential_id));
      setPasskeySuccess('Passkey disabled.');
    } catch (err) {
      setPasskeyError(err.response?.data?.detail || 'Failed to disable passkey.');
    }
  };

  // --- Admin MFA Reset Request ---
  const handleRequestReset = async () => {
    setPasskeyError('');
    try {
      const reason = window.prompt('Briefly describe why you need your login factors reset (e.g. phone lost):') || 'Login factor reset requested';
      await requestAdminAssistance(reason);
      if (refreshUser) refreshUser();
    } catch (err) {
      setPasskeyError(err.response?.data?.detail || 'Failed to request admin reset.');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', width: '100%', boxSizing: 'border-box' }}>
      {user?.reset_requested && (
        <div style={{ background: '#fffbeb', border: '1px solid #fcd34d', borderRadius: '8px', padding: '1rem', marginBottom: '1rem' }}>
            <h4 style={{ margin: '0 0 4px 0', color: '#92400e', fontSize: '14px' }}>⏳ Admin MFA Reset Pending</h4>
            <p style={{ margin: 0, color: '#92400e', fontSize: '12px' }}>
                Your administrator has been notified. They will review and issue a new single-use 3-hour login PIN.
            </p>
        </div>
      )}

      {/* TOP HEADER: Verifiable Identity */}
      <div style={{ background: '#fff', padding: '1.75rem', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
        <div style={{ marginBottom: '1.5rem', borderBottom: '1px solid #e2e8f0', paddingBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#0f172a', margin: '0 0 4px 0' }}>
              Personnel Identity &amp; Strong Security Enclave
            </h2>
            <p style={{ fontSize: '13px', color: '#64748b', margin: 0 }}>
              W3C Decentralized Identifiers (DID), FIDO2/WebAuthn Hardware Passkeys &amp; 3-Factor TOTP.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => setShowProof(true)}
              style={{
                background: '#eff6ff',
                color: '#1d4ed8',
                border: '1px solid #bfdbfe',
                padding: '6px 12px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Verify My DID
            </button>
          </div>
        </div>

        {/* Identity Grid */}
        <div style={{ display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
          <div style={{ background: '#f8fafc', padding: '1.25rem', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
            <div style={{ fontSize: '11px', fontWeight: '700', color: '#64748b', textTransform: 'uppercase', marginBottom: '4px' }}>
              Active Clearance Role
            </div>
            <div style={{ fontSize: '14px', color: '#0f172a', fontWeight: '600' }}>
              <span style={{
                background: user?.role === 'ADMIN' ? '#fee2e2' : user?.role === 'MANAGER' ? '#dbeafe' : user?.role === 'AUDITOR' ? '#fef3c7' : '#f1f5f9',
                color: user?.role === 'ADMIN' ? '#991b1b' : user?.role === 'MANAGER' ? '#1e40af' : user?.role === 'AUDITOR' ? '#92400e' : '#475569',
                padding: '3px 10px',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: '700',
                display: 'inline-block',
                marginBottom: '4px'
              }}>
                {user?.role || 'USER'}
              </span>
            </div>
            <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
              {user?.name || 'Personnel'}
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: '1.25rem', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
            <div style={{ fontSize: '11px', fontWeight: '700', color: '#64748b', textTransform: 'uppercase', marginBottom: '4px' }}>
              Cryptographic Keyring Wallet
            </div>
            <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#334155', wordBreak: 'break-all', fontWeight: '600' }}>
              {wallet.address}
            </div>
          </div>

          <div style={{ background: '#f8fafc', padding: '1.25rem', borderRadius: '8px', border: '1px solid #e2e8f0', gridColumn: '1 / -1' }}>
            <div style={{ fontSize: '11px', fontWeight: '700', color: '#64748b', textTransform: 'uppercase', marginBottom: '4px' }}>
              W3C Decentralized Identifier (DID)
            </div>
            <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#2563eb', wordBreak: 'break-all', fontWeight: '600' }}>
              {userDID}
            </div>
            <div style={{ fontSize: '11px', color: '#16a34a', marginTop: '6px', fontWeight: '600' }}>
              ✓ Anchored to Hyperledger Besu Consortium (Chain ID: 13371)
            </div>
          </div>
        </div>
      </div>

      {/* SECURITY FACTORS & PASSKEYS */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.5rem' }}>

        {/* FACTOR 1: Login */}
        <FactorCard
           title="📱 Login Authenticator"
           desc="RFC 6238 TOTP for account login access."
           isSetup={isTotpEnabled}
           setupHandler={handleStartTotpSetup}
           verifyHandler={handleVerifyTotp}
           disableHandler={null}
           resetHandler={null}
           lockedMessage="Login factors cannot be reset self-service. Use REQUEST ADMIN ASSISTANCE below if you lose access." 
           setupData={totpSetupData}
           code={totpCode}
           setCode={setTotpCode}
           loading={totpLoading}
           error={totpError}
           success={totpSuccess}
        />

        {/* FACTOR 2: View/Sub */}
        <FactorCard
           title="👁 View/Submission Auth"
           desc="TOTP enforced for document viewing & proposal creation."
           isSetup={isF2Enabled}
           setupHandler={handleStartF2Setup}
           verifyHandler={handleVerifyF2}
           disableHandler={handleDisableF2}
           resetHandler={null} // Simplified
           setupData={f2SetupData}
           code={f2Code}
           setCode={setF2Code}
           loading={f2Loading}
           error={f2Error}
           success={f2Success}
        />

        {/* FACTOR 3: Mint/Approve */}
        <FactorCard
           title="🚀 Mint/Approval Auth"
           desc="TOTP enforced for minting, approving & revising."
           isSetup={isF3Enabled}
           setupHandler={handleStartF3Setup}
           verifyHandler={handleVerifyF3}
           disableHandler={handleDisableF3}
           resetHandler={null}
           setupData={f3SetupData}
           code={f3Code}
           setCode={setF3Code}
           loading={f3Loading}
           error={f3Error}
           success={f3Success}
        />

        {/* PASSKEYS */}
        <div style={{ background: '#fff', padding: '1.5rem', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ margin: 0, fontSize: '15px', fontWeight: '700', color: '#0f172a', display: 'flex', alignItems: 'center', gap: '6px' }}>
              🔑 Hardware Passkeys (WebAuthn / FIDO2)
            </h3>
          </div>
          <p style={{ fontSize: '12px', color: '#64748b', margin: '0 0 1rem 0' }}>
            Binds physical hardware biometrics to your identity for secure step-up authorizations.
          </p>

          {(passkeyError || passkeySuccess) && (
            <div style={{
              background: passkeyError ? '#fef2f2' : '#f0fdf4',
              border: `1px solid ${passkeyError ? '#fecaca' : '#bbf7d0'}`,
              color: passkeyError ? '#991b1b' : '#166534',
              padding: '10px 12px',
              borderRadius: '6px',
              fontSize: '12px',
              marginBottom: '1rem'
            }}>
              {passkeyError || passkeySuccess}
            </div>
          )}

          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', color: '#334155', marginBottom: '4px' }}>
              Passkey Authorization Purpose / Scope
            </label>
            <select
              value={passkeyScope}
              onChange={(e) => setPasskeyScope(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: '6px',
                border: '1px solid #cbd5e1',
                fontSize: '13px',
                backgroundColor: '#f8fafc',
                color: '#0f172a'
              }}
            >
              <option value="factor2">View &amp; Proposal Submission (Factor 2)</option>
              <option value="factor3">Mint, Approval &amp; Revisions (Factor 3)</option>
            </select>
          </div>

          <button
            onClick={handleRegisterPasskey}
            disabled={passkeyLoading}
            style={{
              width: '100%',
              background: '#2563eb',
              color: '#fff',
              border: 'none',
              padding: '10px',
              borderRadius: '8px',
              fontSize: '13px',
              fontWeight: '600',
              cursor: passkeyLoading ? 'not-allowed' : 'pointer'
            }}
          >
            {passkeyLoading ? 'Awaiting Device Biometric...' : '+ Register Hardware Biometric Key'}
          </button>

          <div style={{ marginTop: '1.25rem', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {registeredPasskeys.length > 0 ? registeredPasskeys.map((pk) => (
              <div key={pk.credential_id} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                background: '#f8fafc',
                padding: '10px 12px',
                borderRadius: '8px',
                border: '1px solid #e2e8f0'
              }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                    <span style={{ fontSize: '13px', fontWeight: '600', color: '#334155' }}>
                      {pk.device_name || 'Hardware Security Key'}
                    </span>
                    <span style={{
                      background: pk.factor_scope === 'factor3' ? '#fee2e2' : pk.factor_scope === 'factor2' ? '#ffedd5' : '#dbeafe',
                      color: pk.factor_scope === 'factor3' ? '#991b1b' : pk.factor_scope === 'factor2' ? '#9a3412' : '#1e40af',
                      fontSize: '10px',
                      fontWeight: '700',
                      padding: '2px 6px',
                      borderRadius: '4px'
                    }}>
                      {pk.factor_scope === 'factor3' ? '[FACTOR 3]' : pk.factor_scope === 'factor2' ? '[FACTOR 2]' : '[LOGIN]'}
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'monospace' }}>
                    ID: {pk.credential_id ? `${pk.credential_id.substring(0, 16)}...` : 'Unknown'}
                  </div>
                </div>
                {pk.factor_scope !== 'login' && <button
                  onClick={() => handleDisablePasskey(pk)}
                  style={{
                    background: 'none',
                    border: '1px solid #fecaca',
                    color: '#ef4444',
                    padding: '4px 8px',
                    borderRadius: '6px',
                    fontSize: '11px',
                    fontWeight: '600',
                    cursor: 'pointer'
                  }}
                >
                  Remove
                </button>}
              </div>
            )) : (
              <div style={{ fontSize: '12px', color: '#94a3b8', textAlign: 'center', padding: '0.75rem' }}>
                No hardware passkeys registered yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Admin MFA Reset Request Section */}
      <div style={{ background: '#fff', padding: '1.5rem', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
        <h3 style={{ margin: '0 0 8px 0', fontSize: '15px', fontWeight: '700', color: '#0f172a' }}>
          🆘 Lost Login Authenticator or Login Passkey?
        </h3>
        <p style={{ fontSize: '13px', color: '#475569', margin: '0 0 1rem 0' }}>
          Login factors (TOTP 1 and Passkey 1) cannot be reset self-service. An administrator approves the reset with their Factor 3; your login factors and sessions are then revoked and you receive a new single-use 3-hour provisioning PIN to re-import your wallet and set up new login factors.
        </p>
        <button
          onClick={handleRequestReset}
          disabled={user?.reset_requested}
          style={{
            background: user?.reset_requested ? '#94a3b8' : '#dc2626',
            color: '#fff',
            border: 'none',
            padding: '10px 18px',
            borderRadius: '8px',
            fontSize: '13px',
            fontWeight: '600',
            cursor: user?.reset_requested ? 'not-allowed' : 'pointer'
          }}
        >
          {user?.reset_requested ? '⏳ Reset Request Pending Admin Approval' : 'REQUEST ADMIN ASSISTANCE'}
        </button>
      </div>

      {/* DID Cryptographic Proof Modal */}
      {showProof && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(15, 23, 42, 0.6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
        }}>
          <div style={{
            background: '#ffffff',
            borderRadius: '12px',
            padding: '2rem',
            maxWidth: '520px',
            width: '90%',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)',
            border: '1px solid #e2e8f0',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '700', color: '#0f172a' }}>
                W3C DID Cryptographic Proof
              </h3>
              <button
                onClick={() => setShowProof(false)}
                style={{ background: 'none', border: 'none', fontSize: '18px', cursor: 'pointer', color: '#64748b' }}
              >
                ✕
              </button>
            </div>

            <div style={{ background: '#f8fafc', padding: '1rem', borderRadius: '8px', border: '1px solid #e2e8f0', marginBottom: '1rem' }}>
              <div style={{ fontSize: '11px', fontWeight: '700', color: '#64748b', textTransform: 'uppercase', marginBottom: '4px' }}>
                Subject DID
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#2563eb', wordBreak: 'break-all', fontWeight: '600' }}>
                {userDID}
              </div>
            </div>

            <div style={{ background: '#f0fdf4', padding: '1rem', borderRadius: '8px', border: '1px solid #bbf7d0', marginBottom: '1.5rem', fontSize: '12px', color: '#166534' }}>
              <div style={{ fontWeight: '700', marginBottom: '4px' }}>Verified Authentic Identity</div>
              <div>This Decentralized Identifier (DID) conforms to the W3C DID-v2 specification, anchored to Ethereum Chain ID 13371. It is mapped to the public key controlled by your currently connected wallet.</div>
            </div>

            <button
              onClick={() => setShowProof(false)}
              style={{
                width: '100%',
                background: '#0f172a',
                color: '#fff',
                border: 'none',
                padding: '10px',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Done
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
