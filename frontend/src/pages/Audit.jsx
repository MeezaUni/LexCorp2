import { useState } from 'react';
import { Button, Dialog, Facts, Field, Id, Notice, PageHeader, Panel, Register, Status, formatDate, useAsync } from '../components/ui';
import { humanEvent } from './Dashboard';
import { useAuth } from '../context/AuthContext';
import { roleName } from '../components/Shell';
import * as api from '../services/api';

const CATEGORIES = [['', 'All categories'], ['AUTH', 'Sign-in and sessions'], ['IDENTITY', 'Identity administration'], ['VIEW', 'Document views'],
  ['DOWNLOAD', 'Downloads'], ['MODIFICATION', 'Modifications'], ['DIGITAL', 'Digital assets'], ['PHYSICAL', 'Physical assets'],
  ['ACCESS', 'Access delegation'], ['ALERT', 'Alert decisions'], ['CHAIN', 'Ledger and roles']];
const PAGE = 50;
// Where an event's risk level came from: the local AI model, an integrity/security rule, or the
// event type's baseline (events neither scores; see backend/app/models/audit_levels.py).
const riskBasis = (e) => (e.risk_factors?.risk_basis ? 'type' : e.risk_factors?.ai ? 'AI' : 'rule');
const riskBasisLong = (e) => ({ type: 'level from the event type, not scored by the AI', AI: 'scored by the AI model', rule: 'set by an integrity or security rule' }[riskBasis(e)]);

const EMPTY = { category: '', risk_label: '', result: '', asset_serial: '', actor_did: '', from_date: '', to_date: '', escalation_state: '' };

export default function Audit() {
  const { user } = useAuth();
  const [draft, setDraft] = useState(EMPTY);
  const [filters, setFilters] = useState(EMPTY);
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState(null);
  const params = Object.fromEntries(Object.entries({ ...filters, limit: PAGE, offset }).filter(([, v]) => v !== '' && v !== null));
  const { data, error, loading } = useAsync(() => api.auditEvents(params), [JSON.stringify(params)]);
  const stats = useAsync(api.auditStats, []);
  const set = (k) => (e) => setDraft({ ...draft, [k]: e.target.value });

  return (
    <>
      <PageHeader crumbs={[['Dashboard', '/'], ['Audit trail']]} title="Audit trail"
        lede={`Append-only record of security and asset events${user.role === 'MANAGER' ? ' for your departments' : ''}. Ledger events carry their transaction hash.`}
        ribbon={stats.data && [
          { content: <><strong>{stats.data.total_events}</strong> events in your scope</> },
          { content: <><strong>{stats.data.events_24h}</strong> in the last 24 hours</> },
          { content: <><strong>{stats.data.high_risk_7d}</strong> high-risk in 7 days</>, warn: stats.data.high_risk_7d > 0 },
          { content: <><strong>{stats.data.denied_7d}</strong> denied or failed in 7 days</> },
        ]} />
      <div className="content">
        {error && <Notice tone="error">{error}</Notice>}
        <Panel flush>
          <form className="filters" onSubmit={(e) => { e.preventDefault(); setOffset(0); setFilters(draft); }}>
            <Field label="Category"><select className="select" value={draft.category} onChange={set('category')}>{CATEGORIES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></Field>
            <Field label="Risk"><select className="select" value={draft.risk_label} onChange={set('risk_label')}>
              <option value="">Any</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select></Field>
            <Field label="Result"><select className="select" value={draft.result} onChange={set('result')}><option value="">Any</option><option value="SUCCESS">Succeeded</option><option value="DENIED">Denied or failed</option></select></Field>
            <Field label="Escalation"><select className="select" value={draft.escalation_state} onChange={set('escalation_state')}>
              <option value="">Any</option><option value="AUDITOR_REVIEW">Auditor review</option><option value="MANAGER_REVIEW">Manager review</option>
              <option value="ADMIN_REVIEW">Admin review</option><option value="DISMISSED">Dismissed</option><option value="IDENTITY_REVOKED">Identity revoked</option></select></Field>
            <Field label="Asset ID"><input className="input mono" value={draft.asset_serial} onChange={set('asset_serial')} /></Field>
            <Field label="Identity (wallet or DID)"><input className="input mono" value={draft.actor_did} onChange={set('actor_did')} /></Field>
            <Field label="From"><input className="input" type="date" value={draft.from_date} onChange={set('from_date')} /></Field>
            <Field label="To"><input className="input" type="date" value={draft.to_date} onChange={set('to_date')} /></Field>
            <div className="row" style={{ alignSelf: 'flex-end' }}>
              <Button type="submit" variant="primary">Apply filters</Button>
              <Button onClick={() => { setDraft(EMPTY); setFilters(EMPTY); setOffset(0); }}>Clear</Button>
            </div>
          </form>
          <Register rows={loading && !data ? null : data} rowKey={(e) => e.id} onRowClick={setOpen}
            empty={<div className="empty"><strong>No events match these filters</strong></div>}
            foot={data && <div className="row" style={{ justifyContent: 'space-between' }}>
              <span>Showing {data.length ? `${offset + 1}–${offset + data.length}` : '0'}</span>
              <span className="row"><Button size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</Button>
                <Button size="sm" disabled={data.length < PAGE} onClick={() => setOffset(offset + PAGE)}>Next</Button></span></div>}
            columns={[
              { key: 't', label: 'When', render: (e) => <span className="nowrap">{formatDate(e.created_at)}</span> },
              { key: 'e', label: 'Event', render: (e) => <><strong>{humanEvent(e.event_type)}</strong><div className="small muted">{e.event_type}</div></> },
              { key: 'a', label: 'Actor', render: (e) => (e.actor_did ? <Id>{e.actor_did.split(':').pop().slice(0, 10)}…</Id> : '—') },
              { key: 's', label: 'Asset', render: (e) => (e.asset_serial ? <Id>{e.asset_serial}</Id> : '—') },
              { key: 'r', label: 'Risk', render: (e) => (e.risk_label ? <span><Status value={e.risk_label} /> <span className="small muted">{riskBasis(e)}</span></span> : '—') },
              { key: 'al', label: 'Alert', render: (e) => (e.alert_status ? <Status value={e.alert_status} /> : '—') },
              { key: 'src', label: 'Source', render: (e) => (e.block_number > 0 ? `Ledger block ${e.block_number}` : 'LexCorp') },
            ]} />
        </Panel>
      </div>
      {open && (
        <Dialog title={humanEvent(open.event_type)} wide onClose={() => setOpen(null)}>
          <Facts items={[
            ['Event type', <Id key="t">{open.event_type}</Id>],
            ['Recorded', formatDate(open.created_at)],
            ['Actor', open.actor_did && <Id key="a">{open.actor_did}</Id>],
            ['Actor role at the time', open.actor_role && roleName(open.actor_role)],
            ['Target', open.target_did && <Id key="g">{open.target_did}</Id>],
            ['Asset', open.asset_serial && <Id key="s">{open.asset_serial}</Id>],
            ['Network address', open.client_ip],
            ['Risk', open.risk_label && <span key="r"><Status value={open.risk_label} /> {open.risk_score != null ? Number(open.risk_score).toFixed(2) : ''} <span className="small muted">({riskBasisLong(open)})</span></span>],
            ['Alert state', open.alert_status && <Status key="al" value={open.alert_status} />],
            [open.block_number > 0 ? 'Transaction hash' : 'Record reference', <Id key="h">{open.tx_hash}</Id>],
            ['Ledger block', open.block_number > 0 ? open.block_number : 'Not a ledger event'],
          ]} />
          {open.risk_factors && Object.keys(open.risk_factors).length > 0 && (
            <>
              <h3>Recorded details</h3>
              <pre className="secret-box" style={{ userSelect: 'text', whiteSpace: 'pre-wrap', maxHeight: 280, overflow: 'auto' }}>{JSON.stringify(open.risk_factors, null, 2)}</pre>
            </>
          )}
        </Dialog>
      )}
    </>
  );
}
