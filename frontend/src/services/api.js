import axios from 'axios';

axios.defaults.withCredentials = true;

/*
 * Purpose-bound step-up tokens. A passkey (or TOTP) step-up returns a single-use
 * token bound server-side to ONE action. It is attached only to the request that
 * performs that action, and dropped once sent or after it expires.
 */
const STEP_UP_ROUTES = [
  [/\/assets\/(document|physical)\/propose$/, 'document.submit'],
  [/\/assets\/document\/share\/propose$/, 'access.request'],
  [/\/assets\/(document|physical)\/approval\//, 'asset.approve'],
  [/\/assets\/document\/download\/(approve|approval)\//, 'asset.approve'],
  [/\/assets\/(mint|mint-digital)\/prepare$/, 'asset.mint'],
  [/\/assets\/update-digital\/prepare$/, 'document.modify'],
  [/\/assets\/document\/revise/, 'document.modify'],
  [/\/assets\/document\/view\//, 'document.view'],
  [/\/assets\/document\/download\/request$/, 'download.request'],
  [/\/auth\/reset-approve\//, 'admin.reset'],
  [/\/assets\/document\/download\/[^/]+\/fetch$/, 'document.download'],
  [/\/assets\/document\/download\/[^/]+\/owner-approval$/, 'asset.approve'],
];
const pendingStepUp = {};

export function rememberStepUp(action, token, expiresAt) {
  pendingStepUp[action] = { token, expiresAt: expiresAt ? Date.parse(expiresAt) : Date.now() + 5 * 60 * 1000 };
}

function takeStepUp(url) {
  const route = STEP_UP_ROUTES.find(([re]) => re.test((url || '').split('?')[0]));
  if (!route) return null;
  const entry = pendingStepUp[route[1]];
  delete pendingStepUp[route[1]];
  return entry && entry.expiresAt > Date.now() ? entry.token : null;
}

axios.interceptors.request.use((config) => {
  try {
    const token = localStorage.getItem('lexcorp_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  } catch (e) {}
  if (!config.headers['X-Step-Up-Token']) {
    const stepUp = takeStepUp(config.url);
    if (stepUp) config.headers['X-Step-Up-Token'] = stepUp;
  }
  return config;
});

// A revoked / expired / IP-changed session sends the user back to sign-in.
const AUTH_FLOW_URLS = ['/auth/login', '/auth/provision', '/auth/webauthn', '/auth/step-up', '/auth/nonce', '/auth/reset-request'];
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status;
    const url = error?.config?.url || '';
    if (status === 401 && !AUTH_FLOW_URLS.some((u) => url.includes(u))) {
      window.dispatchEvent(new CustomEvent('lexcorp:session-ended', { detail: error.response?.data?.detail }));
    }
    return Promise.reject(error);
  }
);

const API_BASE = '/api';

// Asset Proposal & Workflow
export async function proposeDocument(data) {
  const response = await axios.post(`${API_BASE}/assets/document/propose`, data);
  return response.data;
}

export async function proposePhysicalAsset(data) {
  const response = await axios.post(`${API_BASE}/assets/physical/propose`, data);
  return response.data;
}

export async function prepareMintDigital(data) {
  const response = await axios.post(`${API_BASE}/assets/mint-digital/prepare`, data);
  return response.data;
}

export async function prepareMintPhysical(data) {
  const response = await axios.post(`${API_BASE}/assets/mint/prepare`, data);
  return response.data;
}

export async function proposeDocumentShare(data) {
  const response = await axios.post(`${API_BASE}/assets/document/share/propose`, data);
  return response.data;
}

export async function getPendingDocuments() {
  const response = await axios.get(`${API_BASE}/assets/document/pending`);
  return response.data;
}

export async function getPendingPhysicalAssets() {
  const response = await axios.get(`${API_BASE}/assets/physical/pending`);
  return response.data;
}

export async function approveDocument(actionId, data) {
  const response = await axios.post(`${API_BASE}/assets/document/approval/${actionId}`, data);
  return response.data;
}

export async function approvePhysicalAsset(actionId, data) {
  const response = await axios.post(`${API_BASE}/assets/physical/approval/${actionId}`, data);
  return response.data;
}

/**
 * Controlled view: Factor 2 step-up (TOTP 2 code, or Passkey 2 when no code is given)
 * bound to 'document.view', then an authenticated fetch of the watermarked copy.
 */
export async function viewDocument(identifier, totpCode = null) {
  if (totpCode) {
    await stepUpWithTotp('document.view', totpCode);
  } else {
    await authenticateWithPasskey('factor2', 'document.view');
  }
  const response = await axios.get(`${API_BASE}/assets/document/view/${encodeURIComponent(identifier)}`, { responseType: 'blob' });
  return response.data;
}

export function getViewDocumentUrl(identifier, totpCode = null) {
  let url = `${API_BASE}/assets/document/view/${identifier}`;
  if (totpCode) url += `?totp_code=${totpCode}`;
  return url;
}

export async function requestDocumentDownload(data) {
  const response = await axios.post(`${API_BASE}/assets/document/download/request`, data);
  return response.data;
}

export async function getPendingDownloadRequests() {
  const response = await axios.get(`${API_BASE}/assets/document/download/pending`);
  return response.data;
}

export async function approveDownloadRequest(actionId, data) {
  const response = await axios.post(`${API_BASE}/assets/document/download/approval/${actionId}`, data);
  return response.data;
}

export function getDownloadDocumentUrl(token) {
  return `${API_BASE}/assets/document/download-token/${token}`;
}

// ---------------------------------------------------------------- WebAuthn helpers

const b64urlToBytes = (value) => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const bytesToB64url = (value) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

export async function getAssertion(options) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: b64urlToBytes(options.challenge),
      allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) })),
    },
  });
  if (!assertion) throw new Error('Passkey prompt was cancelled.');
  return {
    id: assertion.id,
    rawId: bytesToB64url(assertion.rawId),
    type: assertion.type,
    authenticatorAttachment: assertion.authenticatorAttachment,
    response: {
      authenticatorData: bytesToB64url(assertion.response.authenticatorData),
      clientDataJSON: bytesToB64url(assertion.response.clientDataJSON),
      signature: bytesToB64url(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bytesToB64url(assertion.response.userHandle) : null,
    },
  };
}

export async function createPasskeyCredential(options) {
  const credential = await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: b64urlToBytes(options.challenge),
      user: { ...options.user, id: b64urlToBytes(options.user.id) },
      excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBytes(c.id) })),
    },
  });
  if (!credential) throw new Error('Passkey registration was cancelled.');
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
      attestationObject: bytesToB64url(credential.response.attestationObject),
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
    },
  };
}

/** Register a passkey for 'login', 'factor2' or 'factor3'. */
export async function registerPasskey(factorScope, deviceName = 'Platform Authenticator', totpCode = null) {
  // Adding a passkey to an already-protected purpose requires a current code of that purpose.
  const { data } = await axios.post(`${API_BASE}/auth/webauthn/register/options`, { factor_scope: factorScope, device_name: deviceName, totp_code: totpCode });
  const response = await createPasskeyCredential(data.options);
  const res = await axios.post(`${API_BASE}/auth/webauthn/register/verify`, { factor_scope: factorScope, device_name: deviceName, response });
  return res.data;
}

const DEFAULT_ACTION = { factor2: 'document.submit', factor3: 'asset.approve' };

/**
 * Passkey step-up for one action (e.g. 'document.view', 'asset.approve').
 * The resulting single-use token is attached automatically to that action's request.
 */
export async function authenticateWithPasskey(factor, action = DEFAULT_ACTION[factor]) {
  const { data } = await axios.post(`${API_BASE}/auth/webauthn/${factor}/options`, { action });
  const response = await getAssertion(data.options);
  const res = await axios.post(`${API_BASE}/auth/webauthn/${factor}/verify`, { response });
  rememberStepUp(res.data.action, res.data.step_up_token, res.data.expires_at);
  return res.data;
}

/** TOTP step-up for one action (for requests that cannot carry totp_code in their body). */
export async function stepUpWithTotp(action, code) {
  const res = await axios.post(`${API_BASE}/auth/step-up/totp`, { action, code });
  rememberStepUp(res.data.action, res.data.step_up_token, res.data.expires_at);
  return res.data;
}

// ---------------------------------------------------------------- Identity / session

export async function provisionWallet(message, signature, nonce, pin) {
  const response = await axios.post(`${API_BASE}/auth/provision`, { message, signature, nonce, pin });
  return response.data;
}

export async function loginWithTotp(walletAddress, token) {
  const response = await axios.post(`${API_BASE}/auth/login/totp`, { wallet_address: walletAddress, token });
  return response.data;
}

export async function loginWithPasskey(walletAddress) {
  const { data } = await axios.post(`${API_BASE}/auth/login/passkey/options`, { wallet_address: walletAddress });
  const response = await getAssertion(data.options);
  const res = await axios.post(`${API_BASE}/auth/login/passkey/verify`, { wallet_address: walletAddress, response });
  return res.data;
}

export async function getWalletKey() {
  const response = await axios.get(`${API_BASE}/auth/wallet-key`);
  return response.data.wallet_key;
}

export async function getMe() {
  const response = await axios.get(`${API_BASE}/auth/me`);
  return response.data;
}

export async function logoutSession() {
  try {
    await axios.post(`${API_BASE}/auth/logout`);
  } catch (e) {}
}

export async function requestAdminAssistance(reason) {
  const response = await axios.post(`${API_BASE}/auth/reset-request`, { reason });
  return response.data;
}

export async function requestAdminAssistanceWithWallet(message, signature, nonce, reason) {
  const response = await axios.post(`${API_BASE}/auth/reset-request/wallet`, { message, signature, nonce, reason });
  return response.data;
}

export async function getNonce(address) {
  const response = await axios.post(`${API_BASE}/auth/nonce?address=${address}`);
  return response.data;
}

export async function issueVC(subjectDID) {
  const response = await axios.post(`${API_BASE}/auth/vc/issue?subject_did=${subjectDID}`);
  return response.data;
}

export async function getAsset(tokenId) {
  const response = await axios.get(`${API_BASE}/assets/${tokenId}`);
  return response.data;
}

export async function getAssetBySerial(serial) {
  const response = await axios.get(`${API_BASE}/assets/serial/${serial}`);
  return response.data;
}

export function getAssetQRUrl(serial) {
  const host = typeof window !== 'undefined' ? window.location.host : 'localhost:5173';
  return `${API_BASE}/assets/serial/${serial}/qr?host=${host}`;
}

export async function getAuditEvents(params = {}) {
  const response = await axios.get(`${API_BASE}/audit/events`, { params });
  return response.data;
}

export async function getAuditStats() {
  const response = await axios.get(`${API_BASE}/audit/stats`);
  return response.data;
}

export async function getAssetVerifyData(serial) {
  const response = await axios.get(`${API_BASE}/assets/${serial.includes('/') ? serial : `serial/${serial}`}/verify-data`);
  return response.data;
}

export function getAssetCertificateUrl(serial) {
  const host = typeof window !== 'undefined' ? window.location.host : 'localhost:5173';
  return `${API_BASE}/assets/serial/${serial}/card?host=${host}`;
}

export async function assignAssetCustodian(serial, custodianData) {
  const response = await axios.post(`${API_BASE}/assets/serial/${serial}/assign`, custodianData);
  return response.data;
}

export async function recordAssetMaintenance(serial, maintenanceData) {
  const response = await axios.post(`${API_BASE}/assets/serial/${serial}/maintenance`, maintenanceData);
  return response.data;
}

export async function getAssetsByOwner(ownerAddress) {
  const response = await axios.get(`${API_BASE}/assets/by-owner/${ownerAddress}`);
  return response.data;
}

export async function getAllAssets() {
  const response = await axios.get(`${API_BASE}/assets/registry`);
  return response.data;
}

export async function uploadDocument(formData) {
  const response = await axios.post(`${API_BASE}/assets/upload-document`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
}

export async function proposeDocumentRevision(data) {
  const response = await axios.post(`${API_BASE}/assets/document/revise/propose`, data);
  return response.data;
}


export async function deleteAsset(tokenId) {
  const response = await axios.delete(`${API_BASE}/assets/${tokenId}`);
  return response.data;
}

// ---------------------------------------------------------------- Controlled downloads & revisions

/** Step-up for one action: a TOTP code of that purpose, or (no code) that purpose's passkey. */
export async function stepUp(factor, action, code) {
  if (code) return stepUpWithTotp(action, code);
  return authenticateWithPasskey(factor, action);
}

export async function requestControlledDownload(serial, mode = 'STANDARD', purpose = '', code = null) {
  await stepUp('factor2', 'download.request', code);
  const response = await axios.post(`${API_BASE}/assets/document/download/request`, { asset_serial: serial, mode, purpose });
  return response.data;
}

export async function getMyDownloads() {
  const response = await axios.get(`${API_BASE}/assets/document/downloads/mine`);
  return response.data;
}

export async function ownerDownloadDecision(actionId, decision, code = null, rejectionReason = null) {
  await stepUp('factor3', 'asset.approve', code);
  const response = await axios.post(`${API_BASE}/assets/document/download/${actionId}/owner-approval`, { decision, rejection_reason: rejectionReason });
  return response.data;
}

/** Requester-only, single-use, Factor 3. Returns { blob, filename }. */
export async function fetchControlledDownload(actionId, code = null) {
  await stepUp('factor3', 'document.download', code);
  const response = await axios.post(`${API_BASE}/assets/document/download/${actionId}/fetch`, {}, { responseType: 'blob' });
  const disposition = response.headers['content-disposition'] || '';
  const match = disposition.match(/filename="([^"]+)"/);
  return { blob: response.data, filename: match ? match[1] : `${actionId}.bin` };
}

/** Upload an externally modified file as a pending revision (Factor 3), bound to a modification download. */
export async function uploadRevisionFile(parentSerial, modificationDownloadId, file, code = null, purpose = 'Revision') {
  await stepUp('factor3', 'document.modify', code);
  const form = new FormData();
  form.append('file', file);
  form.append('parent_asset_serial', parentSerial);
  form.append('modification_download_id', modificationDownloadId);
  form.append('purpose', purpose);
  const response = await axios.post(`${API_BASE}/assets/document/revise/upload`, form, { headers: { 'Content-Type': 'multipart/form-data' } });
  return response.data;
}

export async function readBlobError(err, fallback) {
  let detail = err?.response?.data?.detail;
  if (!detail && err?.response?.data instanceof Blob) {
    try { detail = JSON.parse(await err.response.data.text()).detail; } catch (e) { detail = null; }
  }
  return detail || err?.message || fallback;
}

/** Record an on-chain mint / revision anchor after the server verifies the receipt and chain state. */
export async function confirmChainEffect(serial, txHash) {
  const response = await axios.post(`${API_BASE}/assets/chain-confirm/${encodeURIComponent(serial)}`, { tx_hash: txHash });
  return response.data;
}
