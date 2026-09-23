import axios from 'axios';

axios.defaults.withCredentials = true;

// Attach Bearer token from localStorage for all API requests
axios.interceptors.request.use((config) => {
  try {
    const token = localStorage.getItem('lexcorp_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  } catch (e) {}
  return config;
});

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

// Passkey/MFA
export async function getPasskeyOptions(factor) {
  const response = await axios.post(`${API_BASE}/auth/webauthn/${factor}/options`);
  return response.data;
}

export async function verifyPasskey(factor, data) {
  const response = await axios.post(`${API_BASE}/auth/webauthn/${factor}/verify`, data);
  return response.data;
}


export async function getNonce(address) {
  const response = await axios.post(`${API_BASE}/auth/nonce?address=${address}`);
  return response.data;
}

export async function login(message, signature, nonce) {
  const response = await axios.post(`${API_BASE}/auth/login`, {
    message,
    signature,
    nonce,
  });
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

export async function deleteAsset(tokenId) {
  const response = await axios.delete(`${API_BASE}/assets/${tokenId}`);
  return response.data;
}
