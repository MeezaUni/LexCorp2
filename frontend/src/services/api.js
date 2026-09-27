import axios from 'axios';

/*
 * LexCorp API client.
 *
 * - The session is an HttpOnly cookie set by the server; this code never sees or stores it.
 * - Purpose-bound step-up: a factor (TOTP code or passkey) is exchanged for a single-use
 *   token bound server-side to ONE action, then sent only with that action's request.
 * - The server is authoritative for every permission; nothing here grants access.
 */

export const http = axios.create({ baseURL: '/api', withCredentials: true });

// A refused code or factor on these calls is an answer to that step, never the end of the session.
const AUTH_FLOW = ['/auth/login', '/auth/provision', '/auth/webauthn', '/auth/step-up', '/auth/nonce', '/auth/reset-request', '/auth/me', '/auth/2fa', '/auth/factors'];
http.interceptors.response.use(
  (r) => r,
  (error) => {
    const status = error?.response?.status;
    const url = error?.config?.url || '';
    if ((status === 401 || (status === 403 && /disabled|revoked/i.test(error?.response?.data?.detail || '')))
      && !AUTH_FLOW.some((u) => url.includes(u))) {
      window.dispatchEvent(new CustomEvent('lexcorp:session-ended', { detail: error.response?.data?.detail }));
    }
    return Promise.reject(error);
  },
);

const data = (p) => p.then((r) => r.data);

/* ------------------------------------------------------------------ WebAuthn */

const b64urlToBytes = (v) => Uint8Array.from(atob(v.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const bytesToB64url = (v) => btoa(String.fromCharCode(...new Uint8Array(v))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

async function getAssertion(options) {
  const a = await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: b64urlToBytes(options.challenge),
      allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) })),
    },
  });
  if (!a) throw new Error('The passkey prompt was cancelled.');
  return {
    id: a.id, rawId: bytesToB64url(a.rawId), type: a.type, authenticatorAttachment: a.authenticatorAttachment,
    response: {
      authenticatorData: bytesToB64url(a.response.authenticatorData),
      clientDataJSON: bytesToB64url(a.response.clientDataJSON),
      signature: bytesToB64url(a.response.signature),
      userHandle: a.response.userHandle ? bytesToB64url(a.response.userHandle) : null,
    },
  };
}

async function createCredential(options) {
  const c = await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: b64urlToBytes(options.challenge),
      user: { ...options.user, id: b64urlToBytes(options.user.id) },
      excludeCredentials: (options.excludeCredentials || []).map((x) => ({ ...x, id: b64urlToBytes(x.id) })),
    },
  });
  if (!c) throw new Error('Passkey registration was cancelled.');
  return {
    id: c.id, rawId: bytesToB64url(c.rawId), type: c.type,
    response: {
      clientDataJSON: bytesToB64url(c.response.clientDataJSON),
      attestationObject: bytesToB64url(c.response.attestationObject),
      transports: c.response.getTransports ? c.response.getTransports() : [],
    },
  };
}

/* ------------------------------------------------------------------ step-up */

const FACTOR_OF = {
  'document.view': 'factor2', 'document.submit': 'factor2', 'access.request': 'factor2', 'download.request': 'factor2',
  'asset.mint': 'factor3', 'asset.approve': 'factor3', 'document.modify': 'factor3', 'document.download': 'factor3',
  'admin.reset': 'factor3', 'identity.revoke': 'factor3', 'identity.provision': 'factor3', 'identity.role': 'factor3',
  'asset.manage': 'factor3', 'factor2.manage': 'factor2', 'factor3.manage': 'factor3',
  'factor2.link': 'login', 'factor3.link': 'login', 'login.manage': 'login',
};
export const factorFor = (action) => FACTOR_OF[action];

/** Exchange a TOTP code (or, with no code, the purpose's passkey) for a single-use token for `action`. */
export async function stepUp(action, code) {
  const factor = FACTOR_OF[action];
  if (code) {
    const r = await http.post('/auth/step-up/totp', { action, code });
    return r.data.step_up_token;
  }
  const { data: opt } = await http.post(`/auth/webauthn/${factor}/options`, { action });
  const response = await getAssertion(opt.options);
  const r = await http.post(`/auth/webauthn/${factor}/verify`, { response });
  return r.data.step_up_token;
}
const su = (token) => ({ headers: { 'X-Step-Up-Token': token } });

/* ------------------------------------------------------------------ identity & session */

export const getNonce = (address) => data(http.post(`/auth/nonce?address=${encodeURIComponent(address)}`));
export const provisionWallet = (message, signature, nonce, pin) => data(http.post('/auth/provision', { message, signature, nonce, pin }));
export const loginWithTotp = (wallet_address, token) => data(http.post('/auth/login/totp', { wallet_address, token }));
export async function loginWithPasskey(wallet_address) {
  const { data: opt } = await http.post('/auth/login/passkey/options', { wallet_address });
  const response = await getAssertion(opt.options);
  return data(http.post('/auth/login/passkey/verify', { wallet_address, response }));
}
export const getMe = () => data(http.get('/auth/me'));
export const getSession = () => data(http.get('/auth/session'));
export const getWalletKey = () => http.get('/auth/wallet-key').then((r) => r.data.wallet_key);
export const logoutSession = () => http.post('/auth/logout').catch(() => null);
export const requestResetSignedIn = (reason) => data(http.post('/auth/reset-request', { reason }));
export const requestResetWithWallet = (message, signature, nonce, reason) =>
  data(http.post('/auth/reset-request/wallet', { message, signature, nonce, reason }));

export const startTotp = (purpose, stepUpToken = null) =>
  data(http.post(purpose === 'login' ? '/auth/2fa/setup' : `/auth/2fa/${purpose}/setup`, purpose === 'login' ? undefined : { step_up_token: stepUpToken }));
export const verifyTotp = (purpose, token) => data(http.post(purpose === 'login' ? '/auth/2fa/verify' : `/auth/2fa/${purpose}/verify`, { token }));
export const resetFactorTotp = (factor, stepUpToken) => data(http.post(`/auth/2fa/${factor}/reset`, { step_up_token: stepUpToken }));

export async function registerPasskey(factorScope, deviceName, stepUpToken = null) {
  const { data: opt } = await http.post('/auth/webauthn/register/options', { factor_scope: factorScope, device_name: deviceName, step_up_token: stepUpToken });
  const response = await createCredential(opt.options);
  return data(http.post('/auth/webauthn/register/verify', { factor_scope: factorScope, device_name: deviceName, response }));
}
export const listPasskeys = () => data(http.get('/auth/webauthn/credentials'));
export const disablePasskey = (credentialId, stepUpToken) =>
  data(http.delete(`/auth/webauthn/credentials/${encodeURIComponent(credentialId)}`, { data: { step_up_token: stepUpToken } }));

/* ------------------------------------------------------------------ users & departments */

export const listUsers = (params) => data(http.get('/users', { params }));
export const createUser = (body, stepUpToken) => data(http.post('/users', body, su(stepUpToken)));
export const changeRole = (id, role, stepUpToken) => data(http.patch(`/users/${id}/role`, { role }, su(stepUpToken)));
export const revokeUser = (id, stepUpToken) => data(http.delete(`/users/${id}`, su(stepUpToken)));
export const assignableDepartments = () => http.get('/users/departments').then((r) => r.data.departments);
export const createDepartment = (name) => data(http.post('/users/departments', { name }));
export const setManagedDepartments = (id, departments) => data(http.put(`/users/${id}/managed-departments`, { departments }));
export const useLoginFactorsFor = (factor, stepUpToken) => data(http.post(`/auth/factors/${factor}/use-login`, {}, su(stepUpToken)));
export const useSeparateFactorsFor = (factor, stepUpToken) => data(http.post(`/auth/factors/${factor}/use-separate`, {}, su(stepUpToken)));
export const listResetRequests = () => data(http.get('/auth/reset-requests'));
export const approveReset = (userId, stepUpToken) => data(http.post(`/auth/reset-approve/${userId}`, {}, su(stepUpToken)));

/* ------------------------------------------------------------------ registry */

export const getRegistry = () => data(http.get('/assets/registry'));
export const getAssetOnChain = (serial) => data(http.get(`/assets/serial/${encodeURIComponent(serial)}`));
export const getLineage = (serial) => data(http.get(`/assets/document/lineage/${encodeURIComponent(serial)}`));
export const getDocumentLogs = (serial) => data(http.get(`/assets/document/logs/${encodeURIComponent(serial)}`));
export const getVerifyData = (serial) => data(http.get(`/assets/serial/${encodeURIComponent(serial)}/verify-data`));
export const getVerifyDataByToken = (tokenId) => data(http.get(`/assets/token/${encodeURIComponent(tokenId)}/verify-data`));
export const getMaintenance = (serial) => data(http.get(`/assets/serial/${encodeURIComponent(serial)}/maintenance`));
export const addMaintenance = (serial, body) => data(http.post(`/assets/serial/${encodeURIComponent(serial)}/maintenance`, body));
export const assignCustodian = (serial, body) => data(http.post(`/assets/serial/${encodeURIComponent(serial)}/assign`, body));
export const changePhysicalStatus = (serial, status, reason, stepUpToken) =>
  data(http.post(`/assets/physical/${encodeURIComponent(serial)}/status`, { status, reason }, su(stepUpToken)));
export const qrImageUrl = (serial) => `/api/assets/serial/${encodeURIComponent(serial)}/qr`;
export async function fetchImage(url) {
  const r = await http.get(url.replace(/^\/api/, ''), { responseType: 'blob' });
  return URL.createObjectURL(r.data);
}
export async function fetchCard(serial) {
  const r = await http.get(`/assets/serial/${encodeURIComponent(serial)}/card`, { responseType: 'blob' });
  return { blob: r.data, type: r.headers['content-type'] || '' };
}

export async function uploadDocument(file) {
  const form = new FormData();
  form.append('file', file);
  return data(http.post('/assets/upload-document', form));
}
export const proposeDocument = (body, stepUpToken) => data(http.post('/assets/document/propose', body, su(stepUpToken)));
export const proposePhysical = (body, stepUpToken) => data(http.post('/assets/physical/propose', body, su(stepUpToken)));
export const proposeShare = (body, stepUpToken) => data(http.post('/assets/document/share/propose', body, su(stepUpToken)));

/* ------------------------------------------------------------------ approvals */

export const pendingDocuments = () => data(http.get('/assets/document/pending'));
export const pendingPhysical = () => data(http.get('/assets/physical/pending'));
export const pendingDownloads = () => data(http.get('/assets/document/download/pending'));
export const decideAction = (action, body, stepUpToken) => {
  const path = action.action_type === 'DOWNLOAD' ? `/assets/document/download/approval/${action.action_id}`
    : action.is_physical ? `/assets/physical/approval/${action.action_id}` : `/assets/document/approval/${action.action_id}`;
  return data(http.post(path, body, su(stepUpToken)));
};
export const ownerDownloadDecision = (actionId, decision, reason, stepUpToken) =>
  data(http.post(`/assets/document/download/${actionId}/owner-approval`, { decision, rejection_reason: reason }, su(stepUpToken)));
export const confirmChainEffect = (serial, txHash) => data(http.post(`/assets/chain-confirm/${encodeURIComponent(serial)}`, { tx_hash: txHash }));
export const prepareMintPhysical = (body, stepUpToken) => data(http.post('/assets/mint/prepare', body, su(stepUpToken)));

/* ------------------------------------------------------------------ viewing, downloads, revisions */

export async function viewDocument(serial, stepUpToken) {
  const r = await http.get(`/assets/document/view/${encodeURIComponent(serial)}`, { responseType: 'blob', ...su(stepUpToken) });
  return { blob: r.data, type: r.headers['content-type'] || r.data.type, actionId: r.headers['x-lexcorp-action-id'] };
}
export const requestDownload = (serial, mode, purpose, stepUpToken) =>
  data(http.post('/assets/document/download/request', { asset_serial: serial, mode, purpose }, su(stepUpToken)));
export const myDownloads = () => data(http.get('/assets/document/downloads/mine'));
export async function fetchDownload(actionId, stepUpToken) {
  const r = await http.post(`/assets/document/download/${actionId}/fetch`, {}, { responseType: 'blob', ...su(stepUpToken) });
  const m = (r.headers['content-disposition'] || '').match(/filename="([^"]+)"/);
  return { blob: r.data, filename: m ? m[1] : `${actionId}.bin` };
}
export async function ownerDownload(serial, stepUpToken, mode = 'STANDARD') {
  const r = await http.post(`/assets/document/${encodeURIComponent(serial)}/owner-download?mode=${mode}`, {}, { responseType: 'blob', ...su(stepUpToken) });
  const m = (r.headers['content-disposition'] || '').match(/filename="([^"]+)"/);
  return { blob: r.data, filename: m ? m[1] : `${serial}.bin`, actionId: r.headers['x-lexcorp-action-id'] };
}
export async function uploadRevision(parentSerial, modificationDownloadId, file, purpose, stepUpToken) {
  const form = new FormData();
  form.append('file', file);
  form.append('parent_asset_serial', parentSerial);
  form.append('modification_download_id', modificationDownloadId);
  form.append('purpose', purpose || 'Revision');
  return data(http.post('/assets/document/revise/upload', form, su(stepUpToken)));
}
export const listGrants = () => data(http.get('/assets/access-grants'));
export const revokeGrant = (id) => data(http.post(`/assets/access-grants/${id}/revoke`));

/** Blob error bodies (e.g. a refused view) carry JSON; extract its detail. */
export async function blobError(err, fallback = 'The request failed.') {
  let detail = err?.response?.data?.detail;
  if (!detail && err?.response?.data instanceof Blob) {
    try { detail = JSON.parse(await err.response.data.text()).detail; } catch { detail = null; }
  }
  return detail || err?.message || fallback;
}

/* ------------------------------------------------------------------ security & audit */

export const listAlerts = () => data(http.get('/alerts'));
export const getAlert = (id) => data(http.get(`/alerts/${id}`));
export const forwardAlert = (id, note) => data(http.post(`/alerts/${id}/forward`, { note }));
export const dismissAlert = (id, note) => data(http.post(`/alerts/${id}/dismiss`, { note }));
export async function alertEvidence(id) {
  const r = await http.get(`/alerts/${id}/evidence`, { responseType: 'blob' });
  return { blob: r.data, type: r.headers['content-type'] || r.data.type, actionId: r.headers['x-lexcorp-action-id'] };
}
export const revokeFromAlert = (id, note, stepUpToken) => data(http.post(`/alerts/${id}/revoke-identity`, { note }, su(stepUpToken)));
export const auditEvents = (params) => data(http.get('/audit/events', { params }));
export const auditStats = () => data(http.get('/audit/stats'));
export const chainStatus = () => data(http.get('/chain/status'));
export const chainInfo = () => data(http.get('/chain/info'));
export const reconcileRoles = () => data(http.post('/chain/roles/reconcile'));
export const indexerStatus = () => data(http.get('/indexer/status'));
export const health = () => fetch('/api/../health').then((r) => r.json()).catch(() => null);

/* ------------------------------------------------------------------ public verification */

export const verifyAction = (id) => data(http.get(`/verify/action/${encodeURIComponent(id)}`));
export const compareAction = (id, fields) => data(http.post(`/verify/action/${encodeURIComponent(id)}/compare`, { fields }));
export async function compareActionFile(id, file) {
  const form = new FormData();
  form.append('file', file);
  return data(http.post(`/verify/action/${encodeURIComponent(id)}/compare-file`, form));
}
