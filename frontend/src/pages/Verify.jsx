import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Mark } from '../components/Shell';
import { Button, Facts, Field, Id, Loading, Notice, errorText, formatDate } from '../components/ui';
import * as api from '../services/api';
import { humanEvent } from './Dashboard';

function VerifyFrame({ title, reference, children }) {
  return (
    <div className="verify-page">
      <header className="verify-top">
        <div className="inner">
          <Mark size={32} />
          <div><div className="brand-name">LexCorp</div><div className="brand-sub">Record verification</div></div>
        </div>
      </header>
      <main className="verify-body stack">
        <div>
          <h1 className="page-title">{title}</h1>
          <p className="page-lede">Reference <Id>{reference}</Id></p>
        </div>
        {children}
        <p className="small muted">This page reads the authoritative LexCorp record. Nothing printed on a label, card or document is trusted on its own. <Link to="/">Sign in</Link> as an authorized employee to see more detail.</p>
      </main>
    </div>
  );
}

/** Asset QR (NFT card or asset label): /verify/:serial and /verify/token/:tokenId */
export function VerifyAsset() {
  const { serial, tokenId } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  useEffect(() => {
    (tokenId ? api.getVerifyDataByToken(tokenId) : api.getVerifyData(serial)).then(setData).catch((e) => setError(errorText(e, 'Verification failed.')));
  }, [serial, tokenId]);
  const ref = serial || `token #${tokenId}`;
  return (
    <VerifyFrame title="Asset verification" reference={ref}>
      {error && <div className="verdict bad" role="alert">Not verified: {error}</div>}
      {!data && !error && <Loading label="Checking the registry and ledger" />}
      {data && (
        <>
          <div className={`verdict ${data.on_chain_verified ? 'ok' : 'bad'}`} role="status">
            {data.on_chain_verified ? 'Registered LexCorp asset, confirmed on the ledger' : 'Registered in LexCorp, but not confirmed on the ledger'}
          </div>
          <section className="panel"><div className="panel-body">
            <Facts items={[
              ['Serial number', <Id key="s">{data.serial_number}</Id>],
              ['NFT / token ID', data.token_id != null ? `#${data.token_id}` : 'Not minted'],
              ['Kind', data.is_digital ? 'Digital document' : 'Physical asset'],
              ['Department', data.department],
              ['Approval', data.approval_status && data.approval_status.replace(/_/g, ' ').toLowerCase()],
              ['Lifecycle', data.lifecycle_status && data.lifecycle_status.replace(/_/g, ' ').toLowerCase()],
              ['Registered', formatDate(data.created_at, false)],
              ['Detail level', data.detail_level === 'AUTHORIZED' ? 'Authorized employee view' : 'Public view'],
              ['Name', data.name],
              ['Custodian department', data.custodian_department],
              ['MAC address', data.mac_address && <Id key="m">{data.mac_address}</Id>],
              ['Unique device address', data.device_unique_address && <Id key="u">{data.device_unique_address}</Id>],
              ['Location', data.location],
              ['Contract', data.contract_address && <Id key="c">{data.contract_address}</Id>],
              ['Creation ID', data.creation_id && <Id key="i">{data.creation_id}</Id>],
            ]} />
          </div></section>
          {data.lifecycle?.length > 0 && (
            <section className="panel"><div className="panel-head"><h2>Lifecycle</h2></div>
              <ul className="timeline">{data.lifecycle.map((e, i) => <li key={i}><time>{formatDate(e.at)}</time><span>{humanEvent(e.event)}</span></li>)}</ul>
            </section>
          )}
        </>
      )}
    </VerifyFrame>
  );
}

const FIELDS = ['Viewed by', 'Downloaded by', 'Wallet', 'IP', 'Date', 'View ID', 'Download ID', 'Owner'];

/** Watermark QR on every protected copy: /verify/action/:actionId */
export function VerifyAction() {
  const { actionId } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [claimed, setClaimed] = useState({});
  const [sha, setSha] = useState('');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.verifyAction(actionId).then(setData).catch((e) => setError(errorText(e, 'Verification failed.'))); }, [actionId]);

  const compare = async (fn) => { setBusy(true); try { setResult(await fn()); } catch (e) { setResult({ verdict: 'ERROR', error: errorText(e) }); } finally { setBusy(false); } };

  return (
    <VerifyFrame title="Document copy verification" reference={actionId}>
      {error && <div className="verdict bad" role="alert">Not verified: {error}</div>}
      {!data && !error && <Loading label="Checking the record" />}
      {data && (
        <>
          <div className="verdict ok" role="status">Authentic LexCorp record ({data.detail_level === 'AUTHORIZED' ? 'authorized detail' : 'public view'})</div>
          <section className="panel"><div className="panel-body">
            <Facts items={[
              ['Action', `${data.action_type?.toLowerCase()} ${data.action_id}`],
              ['Action date', data.action_date],
              ['Document version', data.document_version],
              ['Document status', data.document_status],
              ['Latest approved version', data.is_latest_approved_version === undefined ? undefined : data.is_latest_approved_version ? 'Yes' : 'No, a newer approved version exists'],
              ['Version SHA-256', data.version_sha256 && <Id key="h">{data.version_sha256}</Id>],
              ['Modifications in history', data.modifications_in_lineage],
              ['Asset ID', data.asset_serial && <Id key="s">{data.asset_serial}</Id>],
              ['Creation ID', data.creation_id && <Id key="c">{data.creation_id}</Id>],
              ['Creator', data.creator && `${data.creator} (${data.creator_wallet})`],
              ['Performed by', data.action_actor && `${data.action_actor} (${data.action_actor_wallet})`],
              ['Network address (restricted)', data.action_client_ip],
            ]} />
            {data.modification_trail?.length > 0 && (
              <ul className="timeline" style={{ marginTop: 12, border: '1px solid var(--rule)' }}>
                {data.modification_trail.map((m) => (
                  <li key={m.modification_id}><time>{m.modified_at?.slice(0, 10)}</time>
                    <span>v{m.version} <Id>{m.modification_id}</Id> by {m.modifier} <Id>{m.modifier_wallet}</Id>, {m.status?.toLowerCase()}</span></li>
                ))}
              </ul>
            )}
          </div></section>
          <section className="panel">
            <div className="panel-head"><h2>Check a copy against this record</h2></div>
            <div className="panel-body stack">
              <p className="small muted">Type the values exactly as printed in the watermark and the file's SHA-256, or upload the copy itself. Any edited field, and any change to the file, is flagged.</p>
              <form className="form-grid" onSubmit={(e) => { e.preventDefault(); compare(() => api.compareAction(actionId, Object.fromEntries(Object.entries(claimed).filter(([, v]) => v?.trim())), sha.trim())); }}>
                {FIELDS.map((f) => (
                  <Field key={f} label={f}><input className="input" value={claimed[f] || ''} onChange={(e) => setClaimed({ ...claimed, [f]: e.target.value })} /></Field>
                ))}
                <Field label="File SHA-256" hint="The hash of the file you hold, for example from certutil -hashfile <file> SHA256" className="span-2">
                  <input className="input mono" value={sha} onChange={(e) => setSha(e.target.value)} placeholder="64 hexadecimal characters" />
                </Field>
                <div className="span-2 row">
                  <Button type="submit" variant="primary" busy={busy}>Compare typed values</Button>
                  <label className="btn btn-secondary">Upload copy<input type="file" hidden onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) compare(() => api.compareActionFile(actionId, f)); }} /></label>
                </div>
              </form>
              {result && (
                <Notice tone={result.verdict === 'MATCH' ? 'success' : 'error'}
                  title={result.verdict === 'MATCH' ? 'Matches the authoritative record' : result.verdict === 'MISMATCH' ? 'Does not match the record: possible tampering' : result.error || 'Nothing to compare'}>
                  {(result.results || []).map((r) => <div key={r.field}>{r.matches_record ? 'Matches' : 'Differs'}: {r.field} “{r.shown}”</div>)}
                  {result.hash && <div>{result.hash.result === 'match' ? 'Matches' : result.hash.result === 'differs' ? 'Differs' : 'Not checked'}: file SHA-256. {result.hash.message}</div>}
                  {result.verdict === 'MISMATCH' && !(result.results || []).some((r) => !r.matches_record) && result.hash?.result !== 'differs' && <div>The copy does not match the record.</div>}
                </Notice>
              )}
            </div>
          </section>
        </>
      )}
    </VerifyFrame>
  );
}
