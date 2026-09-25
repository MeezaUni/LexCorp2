import { useCallback, useEffect, useState } from 'react';
import {
  getMyDownloads,
  getPendingDownloadRequests,
  fetchControlledDownload,
  ownerDownloadDecision,
  uploadRevisionFile,
  readBlobError,
} from '../services/api';

const askCode = (label) =>
  window.prompt(`${label}\nEnter the 6-digit TOTP code, or leave empty to use your passkey for this factor:`);

const badge = (status) => {
  const colors = { PENDING: ['#fef3c7', '#92400e'], APPROVED: ['#dcfce7', '#166534'], COMPLETED: ['#e0e7ff', '#3730a3'], REJECTED: ['#fee2e2', '#991b1b'] };
  const [bg, fg] = colors[status] || ['#f1f5f9', '#334155'];
  return { background: bg, color: fg, padding: '2px 8px', borderRadius: '999px', fontSize: '11px', fontWeight: 700 };
};

/**
 * Controlled downloads and modifications for the signed-in user:
 *  - My downloads: approved ones are fetched once with Factor 3 (watermarked copy).
 *  - Completed MODIFICATION downloads can be followed by one revision upload (Factor 3).
 *  - Owner consent: approve/reject others' download requests for my documents (Factor 3).
 */
export default function DocumentWorkflowPanel({ user }) {
  const [mine, setMine] = useState([]);
  const [ownerQueue, setOwnerQueue] = useState([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');

  const load = useCallback(async () => {
    try {
      const [my, pending] = await Promise.all([getMyDownloads(), getPendingDownloadRequests()]);
      setMine(my);
      setOwnerQueue(pending.filter((a) => a.details?.requires_owner_approval && !a.details?.owner_approved_by && a.actor_did !== user?.did));
    } catch (err) {
      setError(err.response?.data?.detail || 'Could not load download requests.');
    }
  }, [user]);

  useEffect(() => { load(); }, [load]);

  const run = async (key, fn) => {
    setBusy(key); setError(''); setMessage('');
    try { await fn(); await load(); } catch (err) { setError(await readBlobError(err, 'Operation failed.')); } finally { setBusy(''); }
  };

  const download = (a) => run(a.action_id, async () => {
    const code = askCode(`Factor 3 (Mint/Approve/Modify) is required to download ${a.action_id}.`);
    if (code === null) return;
    const { blob, filename } = await fetchControlledDownload(a.action_id, code.trim() || null);
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = filename; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    setMessage(`Downloaded ${filename}. The copy is watermarked with ${a.action_id}; the original is unchanged.`);
  });

  const uploadRevision = (a, file) => run(a.action_id, async () => {
    if (!file) return;
    const code = askCode('Factor 3 (Mint/Approve/Modify) is required to submit a revision.');
    if (code === null) return;
    const mod = await uploadRevisionFile(a.asset_serial, a.action_id, file, code.trim() || null);
    setMessage(`Revision ${mod.action_id} submitted as version ${mod.details?.version} (pending approval). SHA-256 ${mod.details?.file_hash?.slice(0, 16)}…`);
  });

  const decide = (a, decision) => run(a.action_id, async () => {
    const code = askCode(`Factor 3 is required to ${decision === 'APPROVE' ? 'approve' : 'reject'} ${a.action_id}.`);
    if (code === null) return;
    const reason = decision === 'REJECT' ? window.prompt('Reason for rejection (optional):') : null;
    await ownerDownloadDecision(a.action_id, decision, code.trim() || null, reason);
    setMessage(`${a.action_id} ${decision === 'APPROVE' ? 'approved by owner; awaiting Manager/Admin approval' : 'rejected'}.`);
  });

  const card = { background: '#fff', border: '1px solid #e2e8f0', borderRadius: '12px', padding: '1.25rem', marginBottom: '1rem' };
  const btn = (bg) => ({ background: bg, color: '#fff', border: 'none', padding: '6px 12px', borderRadius: '6px', fontSize: '12px', fontWeight: 600, cursor: 'pointer' });

  return (
    <div>
      {error && <div style={{ background: '#fef2f2', border: '1px solid #fecaca', color: '#991b1b', padding: '0.75rem', borderRadius: '8px', fontSize: '13px', marginBottom: '1rem' }}>{error}</div>}
      {message && <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', color: '#166534', padding: '0.75rem', borderRadius: '8px', fontSize: '13px', marginBottom: '1rem' }}>{message}</div>}

      {ownerQueue.length > 0 && (
        <div style={card}>
          <h3 style={{ margin: '0 0 8px', fontSize: '15px' }}>Download requests awaiting your consent (owner)</h3>
          {ownerQueue.map((a) => (
            <div key={a.action_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderTop: '1px solid #f1f5f9', fontSize: '13px' }}>
              <div><strong>{a.action_id}</strong> · {a.asset_serial} · {a.details?.mode} · by <code>{a.actor_did?.slice(-10)}</code></div>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button disabled={busy === a.action_id} style={btn('#059669')} onClick={() => decide(a, 'APPROVE')}>Approve</button>
                <button disabled={busy === a.action_id} style={btn('#dc2626')} onClick={() => decide(a, 'REJECT')}>Reject</button>
              </div>
            </div>
          ))}
        </div>
      )}

      <div style={card}>
        <h3 style={{ margin: '0 0 8px', fontSize: '15px' }}>My download &amp; modification requests</h3>
        {mine.length === 0 && <div style={{ color: '#64748b', fontSize: '13px' }}>No requests yet. Use “Request Download” or “Request Modification” on a document.</div>}
        {mine.map((a) => {
          const isMod = a.details?.mode === 'MODIFICATION';
          const canUpload = isMod && a.status === 'COMPLETED' && !a.details?.revision_mod_id;
          return (
            <div key={a.action_id} style={{ padding: '10px 0', borderTop: '1px solid #f1f5f9', fontSize: '13px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <div>
                  <strong>{a.action_id}</strong> · {a.asset_serial} (v{a.asset_version}) · {isMod ? 'MODIFICATION' : 'DOWNLOAD'}{' '}
                  <span style={badge(a.status)}>{a.status}</span>
                  {a.details?.requires_owner_approval && a.status === 'PENDING' && (
                    <span style={{ marginLeft: 6, color: '#92400e' }}>{a.details?.owner_approved_by ? 'owner approved · awaiting Manager/Admin' : 'awaiting owner consent'}</span>
                  )}
                  {a.details?.revision_mod_id && <span style={{ marginLeft: 6, color: '#3730a3' }}>→ {a.details.revision_mod_id}</span>}
                </div>
                {a.status === 'APPROVED' && (
                  <button disabled={busy === a.action_id} style={btn('#7c3aed')} onClick={() => download(a)}>Download (Factor 3)</button>
                )}
              </div>
              {canUpload && (
                <label style={{ display: 'block', marginTop: '6px', fontSize: '12px', color: '#334155' }}>
                  Upload revised file for {a.asset_serial}:{' '}
                  <input type="file" disabled={busy === a.action_id} onChange={(e) => uploadRevision(a, e.target.files?.[0])} />
                </label>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
