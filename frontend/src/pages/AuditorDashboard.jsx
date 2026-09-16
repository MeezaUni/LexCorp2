import { useState, useEffect } from 'react';
import { getAuditEvents, getAuditStats } from '../services/api';

export default function AuditorDashboard() {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedRisk, setSelectedRisk] = useState(null);

  const fetchAuditData = async () => {
    try {
      setLoading(true);
      const [eventsData, statsData] = await Promise.all([
        getAuditEvents({ limit: 50 }),
        getAuditStats()
      ]);
      setEvents(eventsData);
      setStats(statsData);
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditData();
  }, []);

  const getNormalizedScore = (rawScore) => {
    if (rawScore == null || isNaN(rawScore)) return 0;
    const num = Number(rawScore);
    if (num > 0 && num <= 1) {
      return Math.min(100, Math.max(0, Math.round(num * 100)));
    }
    return Math.min(100, Math.max(0, Math.round(num)));
  };

  const formatLocalDateTime = (isoStr, options) => {
    if (!isoStr) return '—';
    try {
      const utcStr = isoStr.endsWith('Z') ? isoStr : `${isoStr}Z`;
      const date = new Date(utcStr);
      if (isNaN(date.getTime())) return '—';
      return options ? date.toLocaleString([], options) : date.toLocaleString();
    } catch {
      return '—';
    }
  };

  const getRiskExplanation = (event) => {
    const score = getNormalizedScore(event.risk_score);
    const factors = event.risk_factors || {};

    const baseObj = (title, color, bg, border, reasons, rec) => ({
        title, color, bg, border, reasons: reasons.filter(Boolean), recommendation: rec
    });

    const isAccessAttempt = event.event_type === 'AccessAttempted';
    const isOwner = event.actor_did === event.target_did && event.actor_did;
    const shortOwner = event.target_did ? event.target_did.split(':').pop().slice(0, 10) : 'unknown';

    let specificContext = null;
    if (isAccessAttempt && event.target_did && !isOwner && !factors.is_granted) {
      specificContext = `Unauthorized action: Actor attempted to access an asset owned by ${shortOwner}... without valid on-chain permission.`;
    } else if (isAccessAttempt && factors.is_granted) {
      specificContext = `Verified on-chain read access clearance granted.`;
    } else if (event.event_type === 'AssetRevoked') {
      specificContext = `Permanent Asset Revocation: Highly sensitive destructive state transition on the smart contract.`;
    } else if (event.event_type === 'AssetTransferred') {
      specificContext = `Custody Transfer: Asset custody handed over to ${shortOwner} on the ledger.`;
    } else if (event.event_type === 'DigitalAssetMinted') {
      specificContext = `Digital Asset Genesis: Cryptographic SHA-256 hash securely anchored for owner ${shortOwner}.`;
    } else if (event.event_type === 'AssetMinted') {
      specificContext = `Physical Asset Genesis: Asset minted and securely anchored for owner ${shortOwner}.`;
    }

    let behavioralJustification = '';
    if (score >= 50) {
      behavioralJustification = `The elevated AI risk score of ${score}% was assigned because this transaction triggered multiple anomaly flags, `;
      if (factors.access_hour !== undefined && (factors.access_hour < 6 || factors.access_hour > 20)) {
        behavioralJustification += `including the operation occurring outside standard business hours (at ${factors.access_hour}:00 UTC), `;
      }
      if (factors.rolling_failure_rate_24h > 0) {
        behavioralJustification += `combined with a recent deviation in operational success rate (${(factors.rolling_failure_rate_24h * 100).toFixed(1)}% failure rate in the last 24h).`;
      } else {
        behavioralJustification += `deviating from the actor's historical baseline operation cluster.`;
      }
    }

    if (event.risk_label === 'HIGH') {
      return baseObj('High Risk Behavioral Anomaly Flagged', '#dc2626', '#fef2f2', '#fecaca', [
          behavioralJustification,
          factors.actor_role ? `Action executed by a user with the ${factors.actor_role} role.` : null,
          specificContext
      ], 'Immediate investigation required: Cross-reference actor DID and review asset transition log.');
    } else if (event.risk_label === 'MEDIUM') {
      return baseObj('Medium Risk Warning', '#d97706', '#fffbeb', '#fde68a', [
          `The risk score of ${score}% indicates a moderate deviation from typical baseline access schedule or historical frequency.`,
          factors.actor_role ? `Action executed by a user with the ${factors.actor_role} role.` : null,
          specificContext
      ], 'Log and monitor ongoing interactions from this DID.');
    } else {
      return baseObj('Low Risk — Nominal Operation', '#16a34a', '#f0fdf4', '#bbf7d0', [
        `AI Risk Score of ${score}% represents a standard access pattern within expected parameters.`,
        specificContext
      ], 'Nominal operation — no compliance action required.');
    }
  };

  const getEventBadge = (eventType) => {
    switch (eventType) {
      case 'AssetMinted':
        return { bg: '#dbeafe', color: '#1e40af', label: 'Physical Mint' };
      case 'DigitalAssetMinted':
        return { bg: '#ede9fe', color: '#6d28d9', label: 'Digital Mint' };
      case 'AssetTransferred':
        return { bg: '#ffedd5', color: '#c2410c', label: 'Transfer' };
      case 'AssetRevoked':
        return { bg: '#fee2e2', color: '#991b1b', label: 'Revoke' };
      case 'AccessPermissionGranted':
        return { bg: '#dcfce7', color: '#15803d', label: 'ACL Granted' };
      case 'AccessPermissionRevoked':
        return { bg: '#fef3c7', color: '#b45309', label: 'ACL Revoked' };
      case 'AccessAttempted':
        return { bg: '#e0e7ff', color: '#3730a3', label: 'Access Attempt' };
      default:
        return { bg: '#f1f5f9', color: '#475569', label: eventType };
    }
  };

  return (
    <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '12px', padding: '1.75rem', width: '100%', boxSizing: 'border-box' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', borderBottom: '1px solid #e2e8f0', paddingBottom: '1rem' }}>
        <div>
          <h2 style={{ margin: '0 0 4px 0', fontSize: '20px', fontWeight: '700', color: '#0f172a' }}>
            Immutable On-Chain Audit Logs & Compliance Ledger
          </h2>
          <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>
            Synchronized directly from Hyperledger Besu Consortium node events.
          </p>
        </div>
        <button
          onClick={fetchAuditData}
          style={{
            background: '#0f172a',
            color: '#fff',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '12px',
            fontWeight: '600'
          }}
        >
          Refresh Stream
        </button>
      </div>

      {/* RISK DETAIL MODAL */}
      {selectedRisk && (
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
            background: '#fff',
            borderRadius: '12px',
            padding: '2rem',
            maxWidth: '520px',
            width: '90%',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)',
            border: `1px solid ${getRiskExplanation(selectedRisk).border}`,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '700', color: getRiskExplanation(selectedRisk).color }}>
                {getRiskExplanation(selectedRisk).title}
              </h3>
              <button
                onClick={() => setSelectedRisk(null)}
                style={{ background: 'none', border: 'none', fontSize: '18px', cursor: 'pointer', color: '#64748b' }}
              >
                ✕
              </button>
            </div>

            <div style={{ background: getRiskExplanation(selectedRisk).bg, padding: '12px', borderRadius: '8px', marginBottom: '1rem', border: `1px solid ${getRiskExplanation(selectedRisk).border}` }}>
              <div style={{ fontSize: '12px', fontWeight: '700', color: getRiskExplanation(selectedRisk).color, marginBottom: '6px' }}>
                AI Behavioral Risk Engine (Random Forest & K-Means)
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '13px', color: '#334155' }}>
                {getRiskExplanation(selectedRisk).reasons.map((r, i) => (
                  <li key={i} style={{ marginBottom: '4px' }}>{r}</li>
                ))}
              </ul>
            </div>

            <div style={{ fontSize: '12px', color: '#475569', marginBottom: '1.5rem', lineHeight: '1.4' }}>
              <strong>Actionable Recommendation:</strong> {getRiskExplanation(selectedRisk).recommendation}
            </div>

            <div style={{ fontSize: '11px', color: '#64748b', borderTop: '1px solid #e2e8f0', paddingTop: '8px', marginBottom: '1rem' }}>
              <div><strong>Transaction Hash:</strong> <code style={{ wordBreak: 'break-all' }}>{selectedRisk.tx_hash}</code></div>
              <div><strong>Asset Identifier:</strong> {selectedRisk.asset_serial || 'N/A'} | <strong>Block:</strong> #{selectedRisk.block_number}</div>
              <div><strong>Timestamp:</strong> {formatLocalDateTime(selectedRisk.created_at)}</div>
            </div>

            <button
              onClick={() => setSelectedRisk(null)}
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
              Close Assessment
            </button>
          </div>
        </div>
      )}

      {stats && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
            <div style={{ background: '#f8fafc', padding: '1.25rem', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
              <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: '600', letterSpacing: '0.05em' }}>Total Indexed Events</span>
              <div style={{ fontSize: '26px', fontWeight: '700', color: '#0f172a', marginTop: '4px' }}>{stats.total_events || 0}</div>
            </div>
            <div style={{ background: '#f8fafc', padding: '1.25rem', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
              <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: '600', letterSpacing: '0.05em' }}>Consortium Block Height</span>
              <div style={{ fontSize: '26px', fontWeight: '700', color: '#0f172a', marginTop: '4px' }}>#{stats.latest_indexed_block || 0}</div>
            </div>
            <div style={{ background: '#f8fafc', padding: '1.25rem', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
              <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase', fontWeight: '600', letterSpacing: '0.05em' }}>Consensus Engine</span>
              <div style={{ fontSize: '16px', fontWeight: '700', color: '#0f172a', marginTop: '8px' }}>Hyperledger Besu (PoA/QBFT)</div>
              <span style={{ fontSize: '11px', color: '#10b981', fontWeight: 'bold' }}>● 3 Validator Nodes Active</span>
            </div>
          </div>

          <div style={{
            background: '#f0fdf4',
            border: '1px solid #bbf7d0',
            borderRadius: '8px',
            padding: '12px 16px',
            marginBottom: '1.5rem',
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            <div style={{ fontSize: '13px', color: '#166534', lineHeight: '1.5' }}>
              <strong>Air-Gapped AI Anomaly & Risk Detection:</strong> Classifies behavioral event features using embedded Isolation Forest anomaly detection. Completely air-gapped without public cloud telemetry. Click any risk badge below to inspect anomaly rationale.
            </div>
          </div>
        </>
      )}

      {loading ? (
        <p style={{ textAlign: 'center', color: '#64748b', padding: '2rem' }}>Loading audit events...</p>
      ) : events.length === 0 ? (
        <div style={{ textAlign: 'center', color: '#64748b', padding: '2rem', background: '#f8fafc', borderRadius: '8px', border: '1px solid #e2e8f0' }}>
          No on-chain events recorded yet. Mint or transfer an asset to generate logs.
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ background: '#f8fafc', borderBottom: '2px solid #e2e8f0', textAlign: 'left' }}>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Date & Time</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Event</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>AI Risk Assessment</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Block</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Serial / File</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Initiator Identity (DID)</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Tx Hash</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => {
                const isHigh = e.risk_label === 'HIGH';
                const isMed = e.risk_label === 'MEDIUM';
                const badgeBg = isHigh ? '#fee2e2' : isMed ? '#fef3c7' : '#dcfce7';
                const textColor = isHigh ? '#991b1b' : isMed ? '#92400e' : '#166534';
                const badge = getEventBadge(e.event_type);

                const formatAddress = (did) => did ? (did.length > 25 ? `${did.slice(0, 15)}...${did.slice(-6)}` : did) : '—';

                const score = getNormalizedScore(e.risk_score);

                return (
                  <tr key={e.id} style={{ borderBottom: '1px solid #f1f5f9', background: isHigh ? '#fef2f2' : 'transparent' }}>
                    <td style={{ padding: '10px 12px', color: '#64748b', fontSize: '11px', whiteSpace: 'nowrap' }}>
                      {formatLocalDateTime(e.created_at, { dateStyle: 'short', timeStyle: 'short' })}
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{
                        background: badge.bg,
                        color: badge.color,
                        padding: '3px 8px',
                        borderRadius: '4px',
                        fontWeight: '700',
                        fontSize: '11px',
                        whiteSpace: 'nowrap'
                      }}>
                        {badge.label}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      {e.risk_label ? (
                        <button
                          onClick={() => setSelectedRisk(e)}
                          style={{
                            background: badgeBg,
                            color: textColor,
                            border: 'none',
                            padding: '3px 10px',
                            borderRadius: '12px',
                            fontWeight: '700',
                            fontSize: '11px',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            cursor: 'pointer',
                            whiteSpace: 'nowrap'
                          }}
                          title="Click to view AI Risk details and explanation"
                        >
                          {e.risk_label} ({score}%) [Info]
                        </button>
                      ) : (
                        <span style={{ color: '#94a3b8', fontSize: '11px' }}>Nominal (0%)</span>
                      )}
                    </td>
                    <td style={{ padding: '10px 12px', color: '#334155', fontWeight: '500' }}>#{e.block_number}</td>
                    <td style={{ padding: '10px 12px', fontFamily: 'monospace', fontWeight: '600', color: '#0f172a' }}>
                      {e.asset_serial ? (e.asset_serial.length > 20 ? `${e.asset_serial.slice(0, 20)}...` : e.asset_serial) : '—'}
                    </td>
                    <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: '#475569' }} title={e.actor_did}>
                      {formatAddress(e.actor_did)}
                    </td>
                    <td style={{ padding: '10px 12px', fontFamily: 'monospace' }}>
                      <span style={{ color: '#2563eb', fontSize: '12px' }}>
                        {e.tx_hash ? `${e.tx_hash.slice(0, 8)}...${e.tx_hash.slice(-6)}` : '—'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
