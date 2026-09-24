import { useState, useEffect } from 'react';
import axios from 'axios';
import { getAuditEvents, getAuditStats } from '../services/api';

export default function AuditorDashboard() {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedRisk, setSelectedRisk] = useState(null);

  // Filter states
  const [filters, setFilters] = useState({
    event_type: '',
    actor_did: '',
    role: '',
    risk_label: '',
    alert_status: '',
    from_date: '',
    to_date: ''
  });

  const fetchAuditData = async () => {
    try {
      setLoading(true);
      // Construct params from active filters
      const params = { limit: 100 };
      Object.keys(filters).forEach(key => {
        if (filters[key]) params[key] = filters[key];
      });

      const [eventsData, statsData] = await Promise.all([
        getAuditEvents(params),
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
  }, [filters]);

  // Alert Actions
  const updateAlertStatus = async (eventId, status) => {
    try {
      await axios.patch(`/api/audit/alerts/${eventId}/status`, { alert_status: status });
      fetchAuditData();
    } catch (err) {
      console.error('Failed to update alert status:', err);
    }
  };

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
      <h2 style={{ margin: '0 0 1.5rem 0', fontSize: '20px', fontWeight: '700', color: '#0f172a' }}>
        Audit Trail & Security Triage
      </h2>

      {/* FILTERS */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.5rem', background: '#f8fafc', padding: '1rem', borderRadius: '8px' }}>
        <input placeholder="Wallet DID/Address" onChange={(e) => setFilters({...filters, actor_did: e.target.value})} style={{ padding: '8px', borderRadius: '4px', border: '1px solid #e2e8f0' }} />
        <select onChange={(e) => setFilters({...filters, role: e.target.value})} style={{ padding: '8px', borderRadius: '4px', border: '1px solid #e2e8f0' }}>
            <option value="">All Roles</option>
            <option value="USER">USER</option>
            <option value="MANAGER">MANAGER</option>
            <option value="ADMIN">ADMIN</option>
            <option value="AUDITOR">AUDITOR</option>
        </select>
        <select onChange={(e) => setFilters({...filters, risk_label: e.target.value})} style={{ padding: '8px', borderRadius: '4px', border: '1px solid #e2e8f0' }}>
            <option value="">All Risks</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
        </select>
        <input type="datetime-local" onChange={(e) => setFilters({...filters, from_date: e.target.value})} style={{ padding: '8px', borderRadius: '4px', border: '1px solid #e2e8f0' }} />
        <input type="datetime-local" onChange={(e) => setFilters({...filters, to_date: e.target.value})} style={{ padding: '8px', borderRadius: '4px', border: '1px solid #e2e8f0' }} />
      </div>

      {/* HIGH RISK ALERTS */}
      <div style={{ marginBottom: '2rem' }}>
        <h3 style={{ fontSize: '16px', fontWeight: 'bold', color: '#dc2626' }}>High-Risk Alerts (OPEN)</h3>
        {events.filter(e => e.risk_label === 'HIGH' && e.alert_status === 'OPEN').map(e => (
            <div key={e.id} style={{ background: '#fef2f2', border: '1px solid #fecaca', padding: '1rem', borderRadius: '8px', marginBottom: '0.5rem', display: 'flex', justifyContent: 'space-between' }}>
                <div><strong>Event:</strong> {e.event_type} | <strong>Actor:</strong> {e.actor_did} | <strong>Block:</strong> #{e.block_number}</div>
                <div>
                    <button onClick={() => updateAlertStatus(e.id, 'FORWARDED_TO_MANAGER')} style={{ marginRight: '0.5rem', cursor: 'pointer' }}>Forward to Manager</button>
                    <button onClick={() => updateAlertStatus(e.id, 'DISMISSED')} style={{ cursor: 'pointer' }}>Dismiss</button>
                </div>
            </div>
        ))}
      </div>

      {/* AUDIT TABLE */}
      {loading ? (
        <p>Loading...</p>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ background: '#f8fafc', borderBottom: '2px solid #e2e8f0', textAlign: 'left' }}>
                <th style={{ padding: '10px 12px' }}>Date</th>
                <th style={{ padding: '10px 12px' }}>Event</th>
                <th style={{ padding: '10px 12px' }}>Risk</th>
                <th style={{ padding: '10px 12px' }}>Status</th>
                <th style={{ padding: '10px 12px' }}>DID</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => {
                const badge = getEventBadge(e.event_type);
                return (
                  <tr key={e.id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                    <td style={{ padding: '10px 12px' }}>{formatLocalDateTime(e.created_at, {dateStyle: 'short', timeStyle: 'short'})}</td>
                    <td style={{ padding: '10px 12px' }}><span style={{ background: badge.bg, color: badge.color, padding: '2px 6px', borderRadius: '4px' }}>{badge.label}</span></td>
                    <td style={{ padding: '10px 12px' }}>{e.risk_label} ({getNormalizedScore(e.risk_score)}%)</td>
                    <td style={{ padding: '10px 12px' }}>{e.alert_status}</td>
                    <td style={{ padding: '10px 12px' }}>{e.actor_did}</td>
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
