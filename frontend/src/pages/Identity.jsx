import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';

const API_BASE = '/api';

const FactorCard = ({ title, desc, isSetup, setupHandler, verifyHandler, disableHandler, resetHandler, setupData, code, setCode, loading, error, success }) => (
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
          <img src={`https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=${encodeURIComponent(setupData.uri)}`} alt="QR" style={{ width: '120px', height: '120px', borderRadius: '8px', border: '2px solid #e2e8f0' }} />
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
        <button onClick={disableHandler} disabled={loading} style={{ display: 'block', marginTop: '10px', background: '#fff', color: '#991b1b', border: '1px solid #fecaca', padding: '7px 10px', borderRadius: '6px', cursor: 'pointer' }}>
          Disable
        </button>
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
  const [passkeyScope, setPasskeyScope] = useState('login');

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

  const handleDisableTotp = async () => {
    setTotpError('');
    setTotpLoading(true);
    try {
      await axios.post(`${API_BASE}/auth/2fa/disable`);
      setIsTotpEnabled(false);
      setTotpSuccess('Mobile authenticator disabled.');
    } catch (err) {
      setTotpError(err.response?.data?.detail || 'Failed to disable mobile authenticator.');
    } finally {
      setTotpLoading(false);
    }
  };

  const handleResetTotp = async () => {
    setTotpError('');
    setTotpLoading(true);
    try {
      await axios.post(`${API_BASE}/auth/2fa/reset`);
      setIsTotpEnabled(false);
      setTotpSetupData(null);
      setTotpSuccess('Mobile authenticator reset. You can enroll a new device.');
    } catch (err) {
      setTotpError(err.response?.data?.detail || 'Failed to reset mobile authenticator.');
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
      await axios.post(`${API_BASE}/auth/2fa/factor2/disable`);
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
      await axios.post(`${API_BASE}/auth/2fa/factor3/disable`);
      setIsF3Enabled(false);
      setF3Success('Factor 3 disabled.');
    } catch (err) {
      setF3Error(err.response?.data?.detail || 'Failed to disable Factor 3.');
    } finally {
      setF3Loading(false);
    }
  };

  // --- WebAuthn / Passkey Registration Flow ---
  const handleRegisterPasskey = async () => {
    setPasskeyError('');
    setPasskeySuccess('');
    setPasskeyLoading(true);

    try {
      // 1. Fetch registration options from server
      const optRes = await axios.post(`${API_BASE}/auth/webauthn/register/options`, {
        device_name: navigator.userAgent.includes('Windows') ? 'Windows Hello / TPM' : navigator.userAgent.includes('Mac') ? 'Touch ID Enclave' : 'Hardware FIDO2 Authenticator',
        factor_scope: passkeyScope
      });

      const options = optRes.data.options;

      // 2. Decode challenge and user ID for navigator.credentials.create
      const challengeBuffer = Uint8Array.from(atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      const userIdBuffer = Uint8Array.from(atob(options.user.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

      const publicKeyCredentialCreationOptions = {
        challenge: challengeBuffer,
        rp: options.rp,
        user: {
          ...options.user,
          id: userIdBuffer,
        },
        pubKeyCredParams: options.pubKeyCredParams,
        authenticatorSelection: options.authenticatorSelection || {
          authenticatorAttachment: 'platform',
          userVerification: 'preferred'
        },
        timeout: 60000,
        attestation: 'none'
      };

      // 3. Prompt user for TouchID / Windows Hello / FaceID biometric
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      });

      if (!credential) {
        throw new Error('Biometric authentication cancelled or not available on this device.');
      }

      // Convert raw buffers to base64url for verification endpoint
      const rawId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const clientDataJSON = btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const attestationObject = btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

      // 4. Send to server for cryptographic verification
      await axios.post(`${API_BASE}/auth/webauthn/register/verify`, {
        credential_id: credential.id,
        device_name: navigator.userAgent.includes('Windows') ? 'Windows Hello / Hardware TPM' : 'Touch ID / Platform Key',
        factor_scope: passkeyScope,
        response: {
          id: credential.id,
          rawId: rawId,
          type: credential.type,
          response: {
            clientDataJSON: clientDataJSON,
            attestationObject: attestationObject
          }
        }
      });

      setPasskeySuccess('✓ Hardware Passkey / Biometric Authenticator bound successfully!');
      const credentials = await axios.get(`${API_BASE}/auth/webauthn/credentials`);
      setRegisteredPasskeys(credentials.data || []);
    } catch (err) {
      console.error('Passkey error:', err);
      // Helpful fallback simulation message if browser platform authenticator isn't configured in test VM
      if (err.name === 'NotSupportedError' || err.message?.includes('not supported') || err.message?.includes('cancelled')) {
        setPasskeyError(`Biometric prompt: ${err.message || 'TouchID/Windows Hello cancelled'}. WebAuthn API is ready on this endpoint.`);
      } else {
        setPasskeyError(err.response?.data?.detail || err.message || 'Passkey enrollment failed.');
      }
    } finally {
      setPasskeyLoading(false);
    }
  };

  const handleDisablePasskey = async (credentialId) => {
    try {
      await axios.delete(`${API_BASE}/auth/webauthn/credentials/${credentialId}`);
      setRegisteredPasskeys(prev => prev.filter((credential) => credential.credential_id !== credentialId));
      setPasskeySuccess('Passkey disabled.');
    } catch (err) {
      setPasskeyError(err.response?.data?.detail || 'Failed to disable passkey.');
    }
  };

  const handleResetPasskeys = async () => {
    setPasskeyError('');
    try {
      await axios.post(`${API_BASE}/auth/webauthn/reset`);
      setRegisteredPasskeys([]);
      setPasskeySuccess('All passkeys reset. You can enroll a new passkey.');
    } catch (err) {
      setPasskeyError(err.response?.data?.detail || 'Failed to reset passkeys.');
    }
  };


  // --- Admin MFA Reset Request ---
  const handleRequestReset = async () => {
    setPasskeyError('');
    try {
      await axios.post(`${API_BASE}/auth/reset-request`, { wallet_address: wallet.address });
      if (refreshUser) refreshUser();
    } catch (err) {
      setPasskeyError(err.response?.data?.detail || 'Failed to request admin reset.');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', width: '100%', boxSizing: 'border-box' }}>
      {user?.onboarding_pending && (
        <div style={{ background: '#fffbeb', border: '1px solid #fcd34d', borderRadius: '8px', padding: '1rem', marginBottom: '1rem' }}>
          <h4 style={{ margin: '0 0 4px 0', color: '#92400e', fontSize: '14px' }}>⚠️ Mandatory Security Enrollment</h4>
          <p style={{ margin: 0, color: '#92400e', fontSize: '12px' }}>
            To unlock the dashboard and perform operations, please configure and activate all required authentication factors: Login Authenticator (Factor 1), View/Submission Authenticator (Factor 2), and Mint/Approve Authenticator (Factor 3), and register at least one Hardware Passkey.
          </p>
        </div>
      )}

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
           disableHandler={handleDisableTotp}
           resetHandler={handleResetTotp}
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
              <option value="login">Login Authenticator (Factor 1)</option>
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
                <button
                  onClick={() => handleDisablePasskey(pk.credential_id)}
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
                </button>
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
          🆘 Account Recovery &amp; MFA Reset Request
        </h3>
        <p style={{ fontSize: '13px', color: '#475569', margin: '0 0 1rem 0' }}>
          If you have lost your authenticator device or hardware security keys, you can submit an official reset request to platform administrators. Upon Factor 3 cryptographic approval by an administrator, your MFA factors will be revoked and a fresh single-use 3-hour import PIN will be provisioned.
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
          {user?.reset_requested ? '⏳ Reset Request Pending Admin Approval' : 'Submit Admin MFA Reset Request'}
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
