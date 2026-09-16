import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getAssetVerifyData, getAssetCertificateUrl, recordAssetMaintenance } from '../services/api';
import { useAuth } from '../context/AuthContext';

export default function Verify() {
  const { serial } = useParams();
  const { user } = useAuth();
  const [asset, setAsset] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Field Maintenance Form State
  const [actionDesc, setActionDesc] = useState('');
  const [notes, setNotes] = useState('');
  const [submittingMaint, setSubmittingMaint] = useState(false);
  const [maintSuccess, setMaintSuccess] = useState(false);

  useEffect(() => {
    fetchVerificationData();
  }, [serial]);

  async function fetchVerificationData() {
    try {
      setLoading(true);
      setError(null);
      const data = await getAssetVerifyData(serial);
      setAsset(data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Asset verification failed or serial does not exist on Hyperledger Besu consortium.');
    } finally {
      setLoading(false);
    }
  }

  async function handleMaintenanceSubmit(e) {
    e.preventDefault();
    if (!actionDesc.trim()) return;

    try {
      setSubmittingMaint(true);
      const performerDid = user?.did || `did:ethr:13371:field-engineer-${Math.floor(Math.random()*1000)}`;
      await recordAssetMaintenance(serial, {
        performed_by_did: performerDid,
        action_description: actionDesc,
        notes: notes
      });
      setMaintSuccess(true);
      setActionDesc('');
      setNotes('');
      // Refresh timeline
      await fetchVerificationData();
      setTimeout(() => setMaintSuccess(false), 4000);
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to record maintenance event.');
    } finally {
      setSubmittingMaint(false);
    }
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0a0f1d', color: '#f8fafc', padding: '2rem 1rem', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      <div style={{ maxWidth: '850px', margin: '0 auto' }}>

        {/* Navigation & Header */}
        <header style={{ marginBottom: '2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '1.2rem' }}>
          <div>
            <Link to="/" style={{ color: '#38bdf8', textDecoration: 'none', fontSize: '13px', fontWeight: 'bold', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              ← Return to Defense Command Portal
            </Link>
            <h1 style={{ marginTop: '0.6rem', fontSize: '24px', fontWeight: '800', letterSpacing: '-0.02em', color: '#ffffff' }}>
              Field Asset Verification &amp; Inspection
            </h1>
            <p style={{ color: '#94a3b8', fontSize: '13px', margin: '2px 0 0' }}>
              Cryptographic verification over Hyperledger Besu QBFT Consortium (Chain ID: 13371)
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <span style={{ fontSize: '11px', background: 'rgba(251, 191, 36, 0.1)', color: '#fbbf24', padding: '4px 10px', borderRadius: '999px', border: '1px solid rgba(251, 191, 36, 0.3)', fontWeight: '700' }}>
              BEL SIH26125
            </span>
          </div>
        </header>

        {loading && (
          <div style={{ textAlign: 'center', padding: '4rem 2rem', background: '#0f172a', borderRadius: '16px', border: '1px solid #1e293b' }}>
            <div style={{ display: 'inline-block', width: '36px', height: '36px', border: '3px solid rgba(56, 189, 248, 0.2)', borderTopColor: '#38bdf8', borderRadius: '50%', animation: 'spin 1s linear infinite' }}></div>
            <p style={{ marginTop: '1rem', color: '#94a3b8', fontSize: '14px' }}>Verifying on-chain authenticity &amp; digital identity...</p>
            <style>{`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}</style>
          </div>
        )}

        {error && !loading && (
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '16px', padding: '2rem', textAlign: 'center' }}>
            <div style={{ fontSize: '32px', marginBottom: '0.5rem' }}>⚠️</div>
            <h2 style={{ fontSize: '18px', color: '#f87171', margin: '0 0 0.5rem 0' }}>Verification Failed / Asset Unregistered</h2>
            <p style={{ color: '#fca5a5', fontSize: '13px', margin: 0 }}>{error}</p>
          </div>
        )}

        {asset && !loading && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

            {/* Status Banner */}
            <div style={{
              background: 'linear-gradient(90deg, rgba(16, 185, 129, 0.15), rgba(6, 182, 212, 0.15))',
              border: '1px solid rgba(16, 185, 129, 0.4)',
              borderRadius: '16px',
              padding: '1.25rem 1.5rem',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '1rem'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: '#10b981', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#0f172a', fontWeight: '900', fontSize: '20px' }}>
                  ✓
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: '800', color: '#34d399' }}>
                    Authentic Defense Hardware Verified
                  </h3>
                  <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8' }}>
                    Anchored to Smart Contract <code style={{ color: '#38bdf8' }}>{asset.contract_address?.slice(0, 10)}...{asset.contract_address?.slice(-8)}</code>
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <a
                  href={getAssetCertificateUrl(asset.serial_number)}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    background: '#0284c7',
                    color: '#ffffff',
                    padding: '8px 14px',
                    borderRadius: '8px',
                    fontSize: '12px',
                    fontWeight: '700',
                    textDecoration: 'none',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}
                >
                  📄 View / Print Official Asset Card
                </a>
              </div>
            </div>

            {/* Asset Details Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>

              {/* Card 1: Identity & Technical Specs */}
              <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '1.5rem' }}>
                <h4 style={{ margin: '0 0 1rem 0', fontSize: '12px', fontWeight: '800', color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Hardware &amp; Cryptographic Identity
                </h4>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div>
                    <span style={{ color: '#64748b', fontSize: '11px', display: 'block' }}>Nomenclature</span>
                    <span style={{ fontWeight: '700', color: '#f8fafc' }}>{asset.name}</span>
                  </div>

                  <div style={{ display: 'flex', gap: '1rem' }}>
                    <div style={{ flex: 1 }}>
                      <span style={{ color: '#64748b', fontSize: '11px', display: 'block' }}>Serial Number</span>
                      <code style={{ color: '#00f2fe', fontWeight: 'bold' }}>{asset.serial_number}</code>
                    </div>
                    <div style={{ flex: 1 }}>
                      <span style={{ color: '#64748b', fontSize: '11px', display: 'block' }}>Token ID</span>
                      <span style={{ color: '#fbbf24', fontWeight: 'bold' }}>#{asset.token_id}</span>
                    </div>
                  </div>

                  <div>
                    <span style={{ color: '#64748b', fontSize: '11px', display: 'block' }}>Asset Classification</span>
                    <span style={{ background: '#1e293b', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: '700', color: '#94a3b8' }}>
                      {asset.asset_type}
                    </span>
                  </div>

                  {asset.file_hash && (
                    <div>
                      <span style={{ color: '#64748b', fontSize: '11px', display: 'block' }}>Anchored SHA-256 Hash</span>
                      <code style={{ fontSize: '10px', color: '#38bdf8', wordBreak: 'break-all', background: '#090d16', padding: '4px 8px', borderRadius: '4px', display: 'block', marginTop: '2px' }}>
                        {asset.file_hash}
                      </code>
                    </div>
                  )}
                </div>
              </div>

              {/* Card 2: Custody & Governance */}
              <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '1.5rem' }}>
                <h4 style={{ margin: '0 0 1rem 0', fontSize: '12px', fontWeight: '800', color: '#fbbf24', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Custody &amp; Operational Governance
                </h4>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div>
                    <span style={{ color: '#64748b', fontSize: '11px', display: 'block' }}>Lifecycle Status</span>
                    <span style={{
                      display: 'inline-block',
                      marginTop: '2px',
                      background: 'rgba(16, 185, 129, 0.2)',
                      color: '#34d399',
                      padding: '3px 10px',
                      borderRadius: '6px',
                      fontWeight: '800',
                      fontSize: '11px'
                    }}>
                      {asset.lifecycle_status}
                    </span>
                  </div>

                  <div>
                    <span style={{ color: '#64748b', fontSize: '11px', display: 'block' }}>Sovereign Owner (DID)</span>
                    <code style={{ fontSize: '11px', color: '#93c5fd', wordBreak: 'break-all' }}>
                      {asset.owner_did}
                    </code>
                  </div>

                  <div>
                    <span style={{ color: '#64748b', fontSize: '11px', display: 'block' }}>Active Custodian Department</span>
                    <span style={{ color: '#f8fafc', fontWeight: '600' }}>
                      {asset.custodian_department || 'BEL Radar Division (Default)'}
                    </span>
                    {asset.custodian_did && (
                      <code style={{ fontSize: '10px', color: '#64748b', display: 'block', wordBreak: 'break-all', marginTop: '2px' }}>
                        DID: {asset.custodian_did}
                      </code>
                    )}
                  </div>
                </div>
              </div>

            </div>

            {/* Field Maintenance & Calibration Log Section */}
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px', padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.2rem', flexWrap: 'wrap', gap: '8px' }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: '800', color: '#f8fafc' }}>
                    Field Maintenance &amp; Inspection Audit Log
                  </h3>
                  <p style={{ margin: '2px 0 0', fontSize: '12px', color: '#94a3b8' }}>
                    Immutable service records tied to hardware serial {asset.serial_number}
                  </p>
                </div>
              </div>

              {/* Log Entry Form */}
              <form onSubmit={handleMaintenanceSubmit} style={{ background: '#162032', padding: '1.25rem', borderRadius: '12px', border: '1px solid #1e293b', marginBottom: '1.5rem' }}>
                <h4 style={{ margin: '0 0 0.8rem 0', fontSize: '13px', fontWeight: '700', color: '#38bdf8' }}>
                  + Record New Field Service / Inspection Entry
                </h4>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div>
                    <input
                      type="text"
                      placeholder="Action Description (e.g., Annual Calibration, RF Transceiver Diagnostics, Firmware Patch)"
                      value={actionDesc}
                      onChange={(e) => setActionDesc(e.target.value)}
                      required
                      style={{
                        width: '100%',
                        padding: '10px 12px',
                        background: '#090d16',
                        border: '1px solid #334155',
                        borderRadius: '8px',
                        color: '#f8fafc',
                        fontSize: '13px',
                        boxSizing: 'border-box'
                      }}
                    />
                  </div>

                  <div>
                    <textarea
                      placeholder="Engineer Operational Notes & Diagnostic Results (Optional)"
                      value={notes}
                      onChange={(e) => setNotes(e.target.value)}
                      rows={2}
                      style={{
                        width: '100%',
                        padding: '10px 12px',
                        background: '#090d16',
                        border: '1px solid #334155',
                        borderRadius: '8px',
                        color: '#f8fafc',
                        fontSize: '13px',
                        boxSizing: 'border-box',
                        resize: 'vertical'
                      }}
                    />
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '11px', color: '#64748b' }}>
                      Signing as: {user?.did ? user.did.slice(0, 20) + '...' : 'Field Engineer Terminal'}
                    </span>
                    <button
                      type="submit"
                      disabled={submittingMaint}
                      style={{
                        background: '#10b981',
                        color: '#0f172a',
                        border: 'none',
                        padding: '8px 18px',
                        borderRadius: '8px',
                        fontWeight: '800',
                        fontSize: '12px',
                        cursor: submittingMaint ? 'not-allowed' : 'pointer',
                        opacity: submittingMaint ? 0.7 : 1
                      }}
                    >
                      {submittingMaint ? 'Recording Proof...' : 'Commit Service Record'}
                    </button>
                  </div>
                </div>

                {maintSuccess && (
                  <div style={{ marginTop: '10px', color: '#34d399', fontSize: '12px', fontWeight: 'bold' }}>
                    ✓ Field maintenance record committed with cryptographic proof!
                  </div>
                )}
              </form>

              {/* Chronological Log List */}
              <div>
                <h4 style={{ margin: '0 0 0.8rem 0', fontSize: '12px', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Historical Maintenance Timeline ({asset.maintenance_history?.length || 0} Records)
                </h4>

                {(!asset.maintenance_history || asset.maintenance_history.length === 0) ? (
                  <p style={{ fontSize: '12px', color: '#64748b', fontStyle: 'italic', margin: 0 }}>
                    No maintenance records logged yet. Use the form above to record inspection.
                  </p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {asset.maintenance_history.map((record) => (
                      <div key={record.id} style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '12px', fontSize: '12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                          <span style={{ fontWeight: '700', color: '#f8fafc' }}>{record.action_description}</span>
                          <span style={{ color: '#64748b', fontSize: '11px' }}>
                            {record.created_at ? new Date(record.created_at).toLocaleString() : 'Recent'}
                          </span>
                        </div>
                        {record.notes && (
                          <p style={{ margin: '4px 0', color: '#cbd5e1', fontSize: '12px' }}>{record.notes}</p>
                        )}
                        <div style={{ display: 'flex', gap: '1rem', marginTop: '6px', fontSize: '10px', color: '#64748b' }}>
                          <span>Inspector: <code style={{ color: '#94a3b8' }}>{record.performed_by_did?.slice(0, 18)}...</code></span>
                          <span>Proof: <code style={{ color: '#38bdf8' }}>{record.log_hash?.slice(0, 12)}...</code></span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

            </div>

          </div>
        )}

      </div>
    </div>
  );
}
