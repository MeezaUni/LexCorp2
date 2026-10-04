import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Button, Facts, Field, Id, Notice, PageHeader, Panel, errorText } from '../components/ui';
import { Contradictions, IssuedCopy, VerificationChecks } from '../components/Checks';
import * as api from '../services/api';

const FIELDS = ['Viewed by', 'Downloaded by', 'Wallet', 'IP', 'Date', 'View ID', 'Download ID', 'Owner'];
const TABS = [['copy', 'Copy reference'], ['file', 'Identify a file'], ['asset', 'Asset']];

function Verdict({ result }) {
  if (!result) return null;
  if (result.error) return <Notice tone="error" title="Verification failed">{result.error}</Notice>;
  const bad = result.verdict === 'MISMATCH';
  return (
    <div className="stack">
      <div className={`verdict ${bad ? 'bad' : result.verdict === 'MATCH' ? 'ok' : ''}`} role="status">
        {bad ? 'Does not match the record' : result.verdict === 'MATCH' ? 'Matches the record on every check' : 'Nothing was compared'}
      </div>
      {bad && <Notice tone="error" title="What contradicts the record"><Contradictions checks={result.checks} /></Notice>}
      {result.file && (
        <Facts items={[
          ['File checked', result.file.name || 'uploaded file'],
          ['Size', `${result.file.size.toLocaleString()} bytes`],
          ['File SHA-256', <Id key="h">{result.file.sha256}</Id>],
        ]} />
      )}
      <VerificationChecks checks={result.checks} foundLabel={result.method === 'asset' ? 'On the ledger' : 'In the copy'} />
    </div>
  );
}

function CopyCheck({ initial }) {
  const [ref, setRef] = useState(initial || '');
  const [record, setRecord] = useState(null);
  const [error, setError] = useState('');
  const [claimed, setClaimed] = useState({});
  const [sha, setSha] = useState('');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState('');

  const lookup = async (e) => {
    e?.preventDefault();
    setBusy('lookup'); setError(''); setRecord(null); setResult(null);
    try { setRecord(await api.auditVerifyAction(ref.trim().toUpperCase())); } catch (err) { setError(errorText(err, 'Lookup failed.')); } finally { setBusy(''); }
  };
  const run = async (kind, fn) => {
    setBusy(kind);
    try { setResult(await fn()); } catch (err) { setResult({ error: errorText(err) }); } finally { setBusy(''); }
  };
  const id = record?.action_id;

  return (
    <div className="stack">
      <Panel title="Reference">
        <form className="row" onSubmit={lookup} style={{ alignItems: 'flex-end' }}>
          <Field label="Action reference (View, Download, Creation or Modification ID)" className="grow">
            <input className="input mono" value={ref} onChange={(e) => setRef(e.target.value)} placeholder="VW-20261004-0001" />
          </Field>
          <Button type="submit" variant="primary" busy={busy === 'lookup'} disabled={!ref.trim()}>Look up</Button>
        </form>
        {error && <Notice tone="error">{error}</Notice>}
      </Panel>
      {record && (
        <>
          <Panel title="The copy issued under this reference">
            <IssuedCopy copy={record.issued_copy} />
            <Facts items={[
              ['Document status', record.document_status],
              ['Latest approved version', record.is_latest_approved_version ? 'Yes' : 'No, a newer approved version exists'],
              ['Version SHA-256 (original, no watermark)', record.version_sha256 && <Id key="v">{record.version_sha256}</Id>],
            ]} />
            {record.recorded_watermark && Object.keys(record.recorded_watermark).length > 0 && (
              <>
                <h3>Watermark as issued</h3>
                <Facts items={Object.entries(record.recorded_watermark)} />
              </>
            )}
          </Panel>
          <Panel title="Check a copy against it">
            <div className="stack">
              <p className="small muted">Type what the copy shows and, if you have it, the file's SHA-256, or upload the file itself. Uploads are also checked for the copy's invisible mark.</p>
              <form className="form-grid" onSubmit={(e) => { e.preventDefault(); run('typed', () => api.auditCompareAction(id, Object.fromEntries(Object.entries(claimed).filter(([, v]) => v?.trim())), sha.trim())); }}>
                {FIELDS.map((f) => (
                  <Field key={f} label={f}><input className="input" value={claimed[f] || ''} onChange={(e) => setClaimed({ ...claimed, [f]: e.target.value })} /></Field>
                ))}
                <Field label="File SHA-256" className="span-2"><input className="input mono" value={sha} onChange={(e) => setSha(e.target.value)} placeholder="64 hexadecimal characters" /></Field>
                <div className="span-2 row">
                  <Button type="submit" variant="primary" busy={busy === 'typed'}>Compare typed values</Button>
                  <label className="btn btn-secondary">{busy === 'file' ? 'Checking…' : 'Upload copy'}
                    <input type="file" hidden onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) run('file', () => api.auditCompareActionFile(id, f)); }} />
                  </label>
                </div>
              </form>
              <Verdict result={result} />
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}

function FileIdentify() {
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const pick = async (file) => {
    setBusy(true);
    try { setResult(await api.auditIdentifyFile(file)); } catch (err) { setResult({ error: errorText(err) }); } finally { setBusy(false); }
  };
  const found = result && !result.error && (result.exact_copy_of || result.hidden_mark_of?.length || result.unwatermarked_original_of);
  return (
    <Panel title="Which copy is this file?">
      <div className="stack">
        <p className="small muted">For a file with no reference, or one you don't trust: it is matched by its SHA-256 against every issued copy and every document version, and by the invisible mark inside it.</p>
        <div><label className="btn btn-primary">{busy ? 'Checking…' : 'Choose a file'}
          <input type="file" hidden onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) pick(f); }} /></label></div>
        {result?.error && <Notice tone="error">{result.error}</Notice>}
        {result && !result.error && (
          <>
            <div className={`verdict ${found ? 'ok' : 'bad'}`} role="status">{found ? 'This file is known to LexCorp' : 'No LexCorp copy or document matches this file'}</div>
            <Facts items={[
              ['File SHA-256', <Id key="h">{result.sha256}</Id>],
              ['Invisible marks found', result.marks_found.length ? result.marks_found.join(', ') : 'None'],
              ['Unwatermarked original of', result.unwatermarked_original_of && `${result.unwatermarked_original_of.serial} version ${result.unwatermarked_original_of.version}`],
            ]} />
            {result.exact_copy_of && <><h3>Identical to the issued copy</h3><IssuedCopy copy={result.exact_copy_of} /></>}
            {result.hidden_mark_of?.map((c) => (
              <div key={c.action_id}><h3>The invisible mark belongs to</h3><IssuedCopy copy={c} /></div>
            ))}
          </>
        )}
      </div>
    </Panel>
  );
}

function AssetCheck({ initial }) {
  const [serial, setSerial] = useState(initial || '');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const run = async (e) => {
    e.preventDefault(); setBusy(true);
    try { setResult(await api.auditVerifyAsset(serial.trim())); } catch (err) { setResult({ error: errorText(err) }); } finally { setBusy(false); }
  };
  return (
    <Panel title="Asset (QR label, NFT card or serial)">
      <div className="stack">
        <form className="row" onSubmit={run} style={{ alignItems: 'flex-end' }}>
          <Field label="Asset ID / serial" className="grow"><input className="input mono" value={serial} onChange={(e) => setSerial(e.target.value)} /></Field>
          <Button type="submit" variant="primary" busy={busy} disabled={!serial.trim()}>Verify asset</Button>
        </form>
        {result?.asset && (
          <Facts items={[
            ['Name', result.asset.name],
            ['Kind', result.asset.is_physical == null ? undefined : result.asset.is_physical ? 'Physical asset' : 'Digital document'],
            ['Department', result.asset.department],
            ['Token', result.asset.token_id != null ? `#${result.asset.token_id}` : 'Not minted'],
          ]} />
        )}
        <Verdict result={result} />
      </div>
    </Panel>
  );
}

/** Auditor verification: the verify page's checks, with every check shown in detail. */
export default function Verification() {
  const [params] = useSearchParams();
  const [tab, setTab] = useState(params.get('serial') ? 'asset' : 'copy');
  return (
    <>
      <PageHeader crumbs={[['Dashboard', '/'], ['Verification']]} title="Verification"
        lede="The same checks as the public verify page, in full: every check, what the record says, what was found, and what contradicts it. Each check is recorded in the audit trail." />
      <div className="content stack">
        <div className="tabs" role="tablist" aria-label="What to verify">
          {TABS.map(([k, l]) => <button key={k} type="button" role="tab" aria-selected={tab === k} onClick={() => setTab(k)}>{l}</button>)}
        </div>
        {tab === 'copy' && <CopyCheck initial={params.get('ref')} />}
        {tab === 'file' && <FileIdentify />}
        {tab === 'asset' && <AssetCheck initial={params.get('serial')} />}
      </div>
    </>
  );
}
