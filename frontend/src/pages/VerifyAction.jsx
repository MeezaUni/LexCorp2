import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import axios from 'axios';

const FIELDS = ['Viewed by', 'Downloaded by', 'Wallet', 'IP', 'Date', 'View ID', 'Download ID'];

/**
 * Landing page for the QR on every protected copy. The QR carries only the action
 * reference; everything shown here comes from the authoritative LexCorp record.
 * Anyone can confirm the record exists; signed-in employees see what their role allows.
 */
export default function VerifyAction() {
  const { actionId } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [claimed, setClaimed] = useState({});
  const [result, setResult] = useState(null);

  useEffect(() => {
    axios.get(`/api/verify/action/${encodeURIComponent(actionId)}`)
      .then((r) => setData(r.data))
      .catch((e) => setError(e.response?.data?.detail || 'Verification failed.'));
  }, [actionId]);

  const compareTyped = async (e) => {
    e.preventDefault();
    const fields = Object.fromEntries(Object.entries(claimed).filter(([, v]) => v && v.trim()));
    const r = await axios.post(`/api/verify/action/${encodeURIComponent(actionId)}/compare`, { fields });
    setResult(r.data);
  };

  const compareFile = async (file) => {
    if (!file) return;
    const form = new FormData();
    form.append('file', file);
    try {
      const r = await axios.post(`/api/verify/action/${encodeURIComponent(actionId)}/compare-file`, form);
      setResult(r.data);
    } catch (err) {
      setResult({ verdict: 'ERROR', error: err.response?.data?.detail || 'Could not read that file.' });
    }
  };

  const box = { background: '#fff', border: '1px solid #e2e8f0', borderRadius: '12px', padding: '1.25rem', marginBottom: '1rem' };
  const row = (k, v) => (v === undefined || v === null ? null : (
    <div style={{ display: 'flex', gap: '12px', fontSize: '13px', padding: '4px 0', borderBottom: '1px solid #f1f5f9' }}>
      <span style={{ width: '220px', color: '#64748b' }}>{k}</span>
      <span style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{String(v)}</span>
    </div>
  ));

  return (
    <div style={{ minHeight: '100vh', background: '#f1f5f9', padding: '2rem 1rem', fontFamily: 'Inter, system-ui, sans-serif' }}>
      <div style={{ maxWidth: '760px', margin: '0 auto' }}>
        <h2 style={{ margin: '0 0 4px' }}>LexCorp Record Verification</h2>
        <p style={{ margin: '0 0 1rem', color: '#475569', fontSize: '14px' }}>Reference <code>{actionId}</code></p>

        {error && <div style={{ ...box, borderColor: '#fecaca', color: '#991b1b' }}>✗ {error}</div>}

        {data && (
          <div style={box}>
            <div style={{ fontWeight: 700, color: '#166534', marginBottom: '8px' }}>✓ Authentic LexCorp record ({data.detail_level === 'AUTHORIZED' ? 'authorized detail' : 'public view'})</div>
            {row('Action', `${data.action_type} · ${data.action_id}`)}
            {row('Action date', data.action_date)}
            {row('Document version', data.document_version)}
            {row('Document status', data.document_status)}
            {row('Latest approved version', data.is_latest_approved_version ? 'yes' : 'no — a newer approved version exists')}
            {row('Version SHA-256', data.version_sha256)}
            {row('Modifications in history', data.modifications_in_lineage)}
            {row('Asset serial', data.asset_serial)}
            {row('Creation ID', data.creation_id)}
            {row('Creator', data.creator && `${data.creator} (${data.creator_wallet})`)}
            {row('Performed by', data.action_actor && `${data.action_actor} (${data.action_actor_wallet})`)}
            {row('Client IP (restricted)', data.action_client_ip)}
            {data.modification_trail?.length > 0 && (
              <div style={{ marginTop: '10px' }}>
                <strong style={{ fontSize: '13px' }}>Modification trail</strong>
                {data.modification_trail.map((m) => (
                  <div key={m.modification_id} style={{ fontSize: '12px', fontFamily: 'monospace', padding: '4px 0' }}>
                    v{m.version} · {m.modification_id} · {m.modifier} ({m.modifier_wallet}) · {m.modified_at?.slice(0, 10)} · {m.status} · from {m.download_id}
                  </div>
                ))}
              </div>
            )}
            {data.detail_level === 'PUBLIC' && (
              <p style={{ fontSize: '12px', color: '#64748b', marginTop: '10px' }}>Sign in as an authorized employee to see creator, history and hashes for every version.</p>
            )}
          </div>
        )}

        {data && (
          <div style={box}>
            <strong>Check a copy against this record</strong>
            <p style={{ fontSize: '12px', color: '#475569' }}>Type the values exactly as printed on the watermark, or upload the PDF/text copy. Any edited field is flagged.</p>
            <form onSubmit={compareTyped} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              {FIELDS.map((f) => (
                <label key={f} style={{ fontSize: '12px' }}>{f}
                  <input value={claimed[f] || ''} onChange={(e) => setClaimed({ ...claimed, [f]: e.target.value })}
                    style={{ width: '100%', padding: '6px', border: '1px solid #cbd5e1', borderRadius: '6px', boxSizing: 'border-box' }} />
                </label>
              ))}
              <button type="submit" style={{ gridColumn: '1 / -1', background: '#0f172a', color: '#fff', border: 'none', padding: '9px', borderRadius: '8px', cursor: 'pointer' }}>Compare typed values</button>
            </form>
            <div style={{ marginTop: '10px', fontSize: '12px' }}>Or upload the copy: <input type="file" accept=".pdf,.txt" onChange={(e) => compareFile(e.target.files?.[0])} /></div>
            {result && (
              <div style={{ marginTop: '12px', padding: '10px', borderRadius: '8px', background: result.verdict === 'MATCH' ? '#f0fdf4' : '#fef2f2', fontSize: '13px' }}>
                <strong>{result.verdict === 'MATCH' ? '✓ Matches the authoritative record' : result.verdict === 'MISMATCH' ? '✗ Does NOT match the record — possible tampering' : result.error || 'Nothing to compare'}</strong>
                {result.results?.map((r) => (
                  <div key={r.field}>{r.matches_record ? '✓' : '✗'} {r.field}: {r.shown}</div>
                ))}
                {result.mismatches?.filter((m) => !result.results?.some((r) => r.field === m)).map((m) => <div key={m}>✗ {m}</div>)}
              </div>
            )}
          </div>
        )}
        <Link to="/" style={{ fontSize: '13px' }}>← LexCorp</Link>
      </div>
    </div>
  );
}
