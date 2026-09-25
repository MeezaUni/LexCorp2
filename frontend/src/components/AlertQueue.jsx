import { useCallback, useEffect, useState } from 'react';
import axios from 'axios';
import { stepUp } from '../services/api';

const STAGE = { AUDITOR: 'AUDITOR_REVIEW', MANAGER: 'MANAGER_REVIEW', ADMIN: 'ADMIN_REVIEW' };
const FORWARD_LABEL = { AUDITOR: 'Forward to Manager', MANAGER: 'Forward to Admin', ADMIN: 'Forward to Admin' };

/**
 * High-risk security alert queue for Auditor / Manager / Admin.
 * AI (or a security rule) raises -> Auditor dismisses or forwards -> Manager dismisses or
 * forwards -> Admin dismisses or revokes the identity (Factor 3). The server enforces
 * role, stage and department scope; this component only offers the relevant actions.
 */
export default function AlertQueue({ role, currentDid }) {
  const [alerts, setAlerts] = useState([]);
  const [showClosed, setShowClosed] = useState(false);
  const [history, setHistory] = useState(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState('');

  const load = useCallback(async () => {
    try {
      const { data } = await axios.get('/api/alerts');
      setAlerts(data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Could not load alerts.');
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const act = async (a, kind) => {
    setError(''); setMessage(''); setBusy(a.alert_id);
    try {
      if (kind === 'dismiss') {
        const note = window.prompt('Why is this a false alarm? (required, recorded in the audit trail)');
        if (!note) return;
        await axios.post(`/api/alerts/${a.alert_id}/dismiss`, { note });
        setMessage(`${a.alert_id} dismissed as a false alarm.`);
      } else if (kind === 'forward') {
        const note = window.prompt('Note for the next reviewer (optional):') ?? '';
        await axios.post(`/api/alerts/${a.alert_id}/forward`, { note });
        setMessage(`${a.alert_id} forwarded.`);
      } else if (kind === 'revoke') {
        if (!window.confirm(`Revoke the identity of ${a.subject.name || a.subject.did}? All their sessions end immediately and they cannot sign in again.`)) return;
        const note = window.prompt('Reason for revocation (recorded):');
        if (!note) return;
        const code = window.prompt('Factor 3 is required. Enter your Factor 3 TOTP code, or leave empty to use your Factor 3 passkey:');
        if (code === null) return;
        const grant = code.trim() ? null : await stepUp('factor3', 'identity.revoke', null);
        await axios.post(`/api/alerts/${a.alert_id}/revoke-identity`, { note, totp_code: code.trim() || null },
          grant ? { headers: { 'X-Step-Up-Token': grant.step_up_token } } : undefined);
        setMessage(`Identity revoked from ${a.alert_id}.`);
      }
      await load();
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Action failed.');
    } finally {
      setBusy('');
    }
  };

  const openHistory = async (a) => {
    const { data } = await axios.get(`/api/alerts/${a.alert_id}`);
    setHistory(data);
  };

  const mine = alerts.filter((a) => a.state === STAGE[role]);
  const shown = showClosed ? alerts : mine;
  const btn = (bg, fg = '#fff') => ({ background: bg, color: fg, border: 'none', padding: '5px 10px', borderRadius: '6px', fontSize: '12px', fontWeight: 600, cursor: 'pointer' });

  return (
    <div style={{ border: '2px solid #dc2626', borderRadius: '12px', padding: '16px', background: '#fef2f2', marginBottom: '2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3 style={{ margin: 0, fontSize: '16px', color: '#991b1b' }}>High-Risk Security Alerts — {STAGE[role].replace('_', ' ')} ({mine.length})</h3>
        <label style={{ fontSize: '12px' }}><input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} /> show all visible</label>
      </div>
      {error && <div style={{ color: '#991b1b', fontSize: '13px', margin: '8px 0' }}>{error}</div>}
      {message && <div style={{ color: '#166534', fontSize: '13px', margin: '8px 0' }}>{message}</div>}
      {shown.length === 0 && <div style={{ color: '#7f1d1d', fontSize: '13px', marginTop: '8px' }}>No alerts awaiting your review.</div>}
      {shown.map((a) => {
        const actionable = a.state === STAGE[role] && a.subject.did !== currentDid;
        return (
          <div key={a.alert_id} style={{ background: '#fff', border: '1px solid #fca5a5', borderRadius: '8px', padding: '10px 12px', marginTop: '8px', fontSize: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px', flexWrap: 'wrap' }}>
              <div>
                <strong>{a.alert_id}</strong> · {a.risk_level} {a.risk_score != null ? `(${Math.round(a.risk_score)})` : ''} · {a.source} · <em>{a.state}</em><br />
                <strong>{a.subject.name || 'Unknown identity'}</strong> ({a.subject.role || '—'}, {a.subject.department || 'no dept'}) · <code>{a.subject.wallet || a.subject.did}</code><br />
                {a.reason} · {a.event_type}{a.asset_serial ? ` · asset ${a.asset_serial}` : ''}{a.related_action_id ? ` · ${a.related_action_id}` : ''}{a.client_ip ? ` · IP ${a.client_ip}` : ''} · {a.created_at?.slice(0, 19).replace('T', ' ')}
              </div>
              <div style={{ display: 'flex', gap: '6px', alignItems: 'flex-start' }}>
                {actionable && role !== 'ADMIN' && <button disabled={busy === a.alert_id} style={btn('#b91c1c')} onClick={() => act(a, 'forward')}>{FORWARD_LABEL[role]}</button>}
                {actionable && role === 'ADMIN' && <button disabled={busy === a.alert_id} style={btn('#7f1d1d')} onClick={() => act(a, 'revoke')}>Revoke Identity</button>}
                {actionable && <button disabled={busy === a.alert_id} style={btn('#e2e8f0', '#0f172a')} onClick={() => act(a, 'dismiss')}>Dismiss — False Alarm</button>}
                <button style={btn('#fff', '#334155')} onClick={() => openHistory(a)}>History</button>
              </div>
            </div>
          </div>
        );
      })}
      {history && (
        <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '10px', marginTop: '10px', fontSize: '12px' }}>
          <strong>{history.alert_id} escalation history</strong> <button style={{ float: 'right' }} onClick={() => setHistory(null)}>✕</button>
          {history.history.map((h, i) => (
            <div key={i}>{h.at?.slice(0, 19).replace('T', ' ')} · {h.action} · {h.from || '—'} → {h.to} · {h.actor_role || 'system'} {h.note ? `· “${h.note}”` : ''}</div>
          ))}
        </div>
      )}
    </div>
  );
}
