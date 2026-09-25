import { useState, useEffect } from 'react';
import axios from 'axios';
import { ethers } from 'ethers';
import { useAuth } from '../context/AuthContext';
import {
  getAssetsByOwner,
  getAssetCertificateUrl,
  uploadDocument,
  proposeDocument,
  proposePhysicalAsset,
  proposeDocumentShare,
  prepareMintDigital,
  prepareMintPhysical,
  viewDocument,
  requestControlledDownload,
  getMyDownloads,
  uploadRevisionFile,
  requestDocumentDownload,
  authenticateWithPasskey,
  proposeDocumentRevision
} from '../services/api';
import DocumentWorkflowPanel from '../components/DocumentWorkflowPanel';
import {
  checkAssetAccess,
  recordAccessAttempt,
  updateDigitalAsset,
  mintDigitalAsset,
  mintAsset,
  grantAssetAccess,
  revokeAssetAccess,
  revokeAsset,
  addTokenToMetaMask
} from '../services/web3';
import deployment from '../../../contracts/deployments/localhost.json';

export default function UserDashboard() {
  const { wallet, signer, user } = useAuth();
  const [assets, setAssets] = useState([]);
  const [permissionsData, setPermissionsData] = useState({
    shared_by_user: [],
    shared_with_user: [],
    total_shared_by_count: 0,
    total_shared_with_count: 0
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeSubTab, setActiveSubTab] = useState('portfolio'); // 'portfolio' | 'mint' | 'mint_phys' | 'share' | 'verify'

  // Sharing Modal
  const [showSharesModal, setShowSharesModal] = useState(false);
  const [sharesModalType, setSharesModalType] = useState('by_me'); // 'by_me' | 'with_me'

  // Digital Propose State (Phase 4 / Phase 14)
  const [docName, setDocName] = useState('');
  const [digitalSerial, setDigitalSerial] = useState('');
  const [docPurpose, setDocPurpose] = useState('');
  const [docRecipientAddress, setDocRecipientAddress] = useState('');
  const [docTotpCode, setDocTotpCode] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileHash, setFileHash] = useState('');
  const [offchainURI, setOffchainURI] = useState('');
  const [uploading, setUploading] = useState(false);
  const [proposing, setProposing] = useState(false);
  const [proposalStatus, setProposalStatus] = useState('');
  const [proposalResult, setProposalResult] = useState(null);

  // Physical Propose State (Phase 14)
  const [physName, setPhysName] = useState('');
  const [physSerial, setPhysSerial] = useState('');
  const [physType, setPhysType] = useState('EQUIPMENT');
  const [hasMac, setHasMac] = useState(false);
  const [physMac, setPhysMac] = useState('');
  const [physDevAddr, setPhysDevAddr] = useState('');
  const [physLocation, setPhysLocation] = useState('');
  const [physPurpose, setPhysPurpose] = useState('');
  const [physRecipientAddress, setPhysRecipientAddress] = useState('');
  const [physTotpCode, setPhysTotpCode] = useState('');
  const [proposingPhys, setProposingPhys] = useState(false);
  const [physProposalStatus, setPhysProposalStatus] = useState('');
  const [physProposalResult, setPhysProposalResult] = useState(null);

  // Grant Access State
  const [shareTokenId, setShareTokenId] = useState('');
  const [shareTargetAddress, setShareTargetAddress] = useState('');
  const [shareLevel, setShareLevel] = useState(1); // 1 = READ, 2 = READ_WRITE
  const [sharePurpose, setSharePurpose] = useState('');
  const [shareRequestDownload, setShareRequestDownload] = useState(false);
  const [shareTotpCode, setShareTotpCode] = useState('');
  const [sharing, setSharing] = useState(false);
  const [shareSuccessMsg, setShareSuccessMsg] = useState('');

  // Access Request / Verification State
  const [requestTokenId, setRequestTokenId] = useState('');
  const [checkingAccess, setCheckingAccess] = useState(false);
  const [accessResult, setAccessResult] = useState(null);

  // Document Revision / Update State (for READ_WRITE holders)
  const [editingAsset, setEditingAsset] = useState(null);
  const [revisionFile, setRevisionFile] = useState(null);
  const [revisionTotpCode, setRevisionTotpCode] = useState('');
  const [isUpdating, setIsUpdating] = useState(false);
  const [actionSuccessMsg, setActionSuccessMsg] = useState('');

  // Revoke state
  const [revokingTokenId, setRevokingTokenId] = useState(null);

  // Revoke Access Permission State
  const [revokeAccessTokenId, setRevokeAccessTokenId] = useState('');
  const [revokeTargetDID, setRevokeTargetDID] = useState('');
  const [revokingAccess, setRevokingAccess] = useState(false);
  const [revokeSuccessMsg, setRevokeSuccessMsg] = useState('');

  const walletAddress = wallet?.address || (typeof wallet === 'string' ? wallet : '');
  const userDID = `did:ethr:13371:${walletAddress.toLowerCase()}`;

  async function fetchDashboardData() {
    if (!walletAddress) return;
    try {
      setLoading(true);
      setError(null);

      // Fetch user assets
      const assetData = await getAssetsByOwner(walletAddress);
      const assetList = Array.isArray(assetData) ? assetData : [];
      setAssets(assetList);

      // Fetch user permissions activity
      try {
        const permRes = await axios.get(`/api/audit/user-permissions/${walletAddress}`);
        if (permRes.data) {
          setPermissionsData(permRes.data);
        }
      } catch (permErr) {
        console.warn('Could not load user permissions stats:', permErr);
      }
    } catch (err) {
      console.error('Failed to load user dashboard:', err);
      setError(err.response?.data?.detail || 'Failed to load user asset data');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchDashboardData();
  }, [walletAddress]);

  // Handle File Upload for Digital Mint
  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setSelectedFile(file);
    setUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', file);
      const data = await uploadDocument(formData);
      setFileHash(data.file_hash);
      setOffchainURI(data.offchain_uri);
      if (!digitalSerial) {
        setDigitalSerial(`DOC-${Date.now()}-${file.name.toUpperCase().replace(/[^A-Z0-9]/g, '-').substring(0, 20)}`);
      }
    } catch (err) {
      console.error('File upload error:', err);
      setError('Failed to upload file to off-chain vault.');
    } finally {
      setUploading(false);
    }
  };

  // Handle Proposing / Minting Digital Document
  const handleDocumentPropose = async (e, usePasskey = false) => {
    if (e) e.preventDefault();
    setError(null);
    setProposing(true);
    setProposalStatus('Initializing...');
    setProposalResult(null);

    try {
      if (!fileHash || !offchainURI) {
        throw new Error('Please select and upload a document first.');
      }
      if (!docName.trim()) {
        throw new Error('Please enter a document title.');
      }
      if (!digitalSerial.trim()) {
        throw new Error('Please enter a document serial number.');
      }
      if (!docRecipientAddress.trim()) {
        throw new Error('Recipient Address is mandatory.');
      }

      let currentTotp = docTotpCode;

      // Handle Passkey vs TOTP Factor Check
      if (usePasskey) {
        try {
          const factor = 'factor2';
          setProposalStatus(`Verifying ${factor === 'factor3' ? 'Factor 3' : 'Factor 2'} Passkey...`);
          await authenticateWithPasskey('factor2', 'document.submit');
          currentTotp = '';
        } catch (pkErr) {
          throw new Error('Passkey verification failed. Please use TOTP fallback. ' + pkErr.message);
        }
      } else {
        if (!currentTotp || currentTotp.trim() === '') {
          const factorName = 'Factor 2';
          throw new Error(`${factorName} TOTP code is required if passkey is not used.`);
        }
        setProposalStatus('Verifying TOTP credentials...');
      }

      {
        // User/Auditor Proposal Submission
        setProposalStatus('Submitting document proposal to server...');
        const payload = {
          name: docName,
          serial_number: digitalSerial,
          file_hash: fileHash,
          offchain_uri: offchainURI,
          recipient_address: docRecipientAddress,
          purpose: docPurpose || 'Defense Technical Documentation',
          totp_code: currentTotp || null,
        };

        const result = await proposeDocument(payload);
        setProposalResult(result);
        setActionSuccessMsg(`Document proposal ${result.action_id} submitted! Pending Manager/Admin Factor 3 approval.`);
      }

      setDocName('');
      setDigitalSerial('');
      setDocPurpose('');
      setDocRecipientAddress('');
      setDocTotpCode('');
      setSelectedFile(null);
      setFileHash('');
      setOffchainURI('');

      setProposalStatus('Refreshing dashboard...');
      setTimeout(() => fetchDashboardData(), 1500);
    } catch (err) {
      console.error('Document action error:', err);
      // Immediately surface minting errors (e.g. invalid TOTP) explicitly and stop the process
      const errorDetail = err.response?.data?.detail || err.message || 'Document operation failed';
      setError(errorDetail);
      setProposalResult(null);
    } finally {
      setProposing(false);
      setProposalStatus('');
    }
  };

  // Handle Proposing / Minting Physical Hardware
  const handlePhysicalPropose = async (e, usePasskey = false) => {
    if (e) e.preventDefault();
    setError(null);
    setProposingPhys(true);
    setPhysProposalStatus('Initializing...');
    setPhysProposalResult(null);

    try {
      if (!physName.trim()) throw new Error('Please enter a hardware name.');
      if (!physSerial.trim()) throw new Error('Please enter a hardware serial number.');
      if (hasMac && !physMac.trim()) throw new Error('Please enter the MAC Address.');
      if (!hasMac && !physDevAddr.trim()) throw new Error('Please enter the Unique Hardware Address.');
      if (!physRecipientAddress.trim()) throw new Error('Recipient Address is mandatory.');

      let currentTotp = physTotpCode;

      if (usePasskey) {
        try {
          const factor = 'factor2';
          setPhysProposalStatus(`Verifying ${factor === 'factor3' ? 'Factor 3' : 'Factor 2'} Passkey...`);
          await authenticateWithPasskey('factor2', 'document.submit');
          currentTotp = '';
        } catch (pkErr) {
          throw new Error('Passkey verification failed. Please use TOTP fallback. ' + pkErr.message);
        }
      } else {
        if (!currentTotp || currentTotp.trim() === '') {
          const factorName = 'Factor 2';
          throw new Error(`${factorName} TOTP code is required if passkey is not used.`);
        }
        setPhysProposalStatus('Verifying TOTP credentials...');
      }

      {
        setPhysProposalStatus('Submitting physical proposal to server...');
        const payload = {
          name: physName,
          serial_number: physSerial,
          asset_type: physType,
          has_mac_address: hasMac,
          mac_address: hasMac ? physMac : null,
          device_unique_address: !hasMac ? physDevAddr : null,
          location: physLocation || 'HQ Security Vault',
          purpose: physPurpose || 'Authorized Asset Allocation',
          recipient_address: physRecipientAddress,
          totp_code: currentTotp || null,
        };

        const result = await proposePhysicalAsset(payload);
        setPhysProposalResult(result);
        setActionSuccessMsg(`Physical Hardware proposal ${result.action_id} submitted! Pending Manager/Admin Factor 3 approval.`);
      }

      setPhysName('');
      setPhysSerial('');
      setPhysType('EQUIPMENT');
      setHasMac(false);
      setPhysMac('');
      setPhysDevAddr('');
      setPhysLocation('');
      setPhysPurpose('');
      setPhysRecipientAddress('');
      setPhysTotpCode('');

      setPhysProposalStatus('Refreshing dashboard...');
      setTimeout(() => fetchDashboardData(), 1500);
    } catch (err) {
      console.error('Physical proposal error:', err);
      const errorDetail = err.response?.data?.detail || err.message || 'Physical hardware operation failed';
      setError(errorDetail);
      setPhysProposalResult(null);
    } finally {
      setProposingPhys(false);
      setPhysProposalStatus('');
    }
  };

  // Handle Proposing Access Share (Factor 2 protected)
  const handleViewDocument = async (serial) => {
    setError(null);
    // Open the tab synchronously (popup blockers), then load the protected copy into it.
    const tab = window.open('', '_blank');
    try {
      const code = window.prompt('Viewing requires Factor 2. Enter your Factor 2 (View/Submission) TOTP code, or leave empty to use your Factor 2 passkey:');
      const blob = await viewDocument(serial, code ? code.trim() : null);
      const url = URL.createObjectURL(blob);
      if (tab) tab.location.href = url; else window.open(url, '_blank');
    } catch (err) {
      if (tab) tab.close();
      let detail = err.response?.data?.detail;
      if (!detail && err.response?.data instanceof Blob) {
        try { detail = JSON.parse(await err.response.data.text()).detail; } catch (e) { detail = null; }
      }
      setError(detail || err.message || 'Document could not be viewed.');
    }
  };

  const handleGrantAccess = async (e, usePasskey = false) => {
    if (e) e.preventDefault();
    setError(null);
    setSharing(true);
    setShareSuccessMsg('');

    try {
      let targetDID = shareTargetAddress.trim();
      if (targetDID.startsWith('0x')) {
        targetDID = `did:ethr:13371:${targetDID.toLowerCase()}`;
      } else if (!targetDID.startsWith('did:ethr:')) {
        throw new Error('Enter a valid Ethereum address (0x...) or W3C DID string');
      }

      const tId = parseInt(shareTokenId);
      if (!tId) throw new Error('Please enter a valid Token ID');

      const assetObj = assets.find(a => a.token_id === tId);
      if (!assetObj) throw new Error('Asset not found');

      let currentTotp = shareTotpCode;
      if (usePasskey) {
        try {
          await authenticateWithPasskey('factor2', 'access.request');
          currentTotp = '';
        } catch (pkErr) {
          throw new Error('Passkey verification failed. Please use TOTP fallback. ' + pkErr.message);
        }
      } else if (!currentTotp || currentTotp.trim() === '') {
        throw new Error('Factor 2 TOTP code is required if passkey is not used.');
      }

      const payload = {
        asset_serial: assetObj.serial_number,
        target_did: targetDID,
        access_level: parseInt(shareLevel),
        purpose: sharePurpose || 'Share access permission',
        request_download: shareRequestDownload,
        totp_code: currentTotp || null
      };

      const result = await proposeDocumentShare(payload);

      setShareSuccessMsg(`Share proposal ${result.action_id} submitted! Pending Manager/Admin Factor 3 approval.`);
      setShareTokenId('');
      setShareTargetAddress('');
      setShareTotpCode('');
      setSharePurpose('');

      setTimeout(() => fetchDashboardData(), 1500);
    } catch (err) {
      console.error('Grant access error:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to submit share proposal');
    } finally {
      setSharing(false);
    }
  };

  // Handle Revoking Access Permission
  const handleRevokeAccessPermission = async (e) => {
    e.preventDefault();
    setError(null);
    setRevokingAccess(true);
    setRevokeSuccessMsg('');

    try {
      let targetDID = revokeTargetDID.trim();
      if (targetDID.startsWith('0x')) {
        targetDID = `did:ethr:13371:${targetDID.toLowerCase()}`;
      } else if (!targetDID.startsWith('did:ethr:')) {
        throw new Error('Enter a valid Ethereum address (0x...) or W3C DID string');
      }

      const tId = parseInt(revokeAccessTokenId);
      if (!tId) throw new Error('Please select a valid Token ID');

      const tx = await revokeAssetAccess(signer, tId, targetDID);
      setRevokeSuccessMsg(`Access permission revoked for ${targetDID.slice(0, 24)}... (Tx: ${tx.txHash.slice(0, 10)}...)`);
      setRevokeAccessTokenId('');
      setRevokeTargetDID('');
      await fetchDashboardData();
    } catch (err) {
      console.error('Revoke access error:', err);
      setError(err.message || 'Failed to revoke access on blockchain');
    } finally {
      setRevokingAccess(false);
    }
  };

  // Handle Revoking Own Asset
  const handleRevokeOwnAsset = async (tokenId) => {
    if (!window.confirm(`Are you sure you want to permanently revoke/burn Asset #${tokenId}? This action is irreversible on the blockchain.`)) {
      return;
    }

    setRevokingTokenId(tokenId);
    setError(null);
    try {
      const tx = await revokeAsset(signer, tokenId);
      setActionSuccessMsg(`Asset #${tokenId} permanently revoked on-chain. Tx: ${tx.txHash.slice(0, 10)}...`);
      await fetchDashboardData();
    } catch (err) {
      console.error('Revoke error:', err);
      setError(err.message || 'Failed to revoke asset on-chain');
    } finally {
      setRevokingTokenId(null);
    }
  };

  // Handle Document Revision Update
  const handleUploadRevision = async (e, usePasskey = false) => {
    if (e) e.preventDefault();
    if (!editingAsset || !revisionFile) return;

    setIsUpdating(true);
    setActionSuccessMsg('');
    setError(null);

    try {
      if (!usePasskey && (!revisionTotpCode || revisionTotpCode.trim() === '')) {
        throw new Error('Factor 3 (Mint/Approve/Modify) TOTP code is required if passkey is not used.');
      }
      // A revision must come from an approved, fetched MODIFICATION download of this version.
      const mine = await getMyDownloads();
      const modDl = mine.find((a) => a.asset_serial === editingAsset.serial_number && a.details?.mode === 'MODIFICATION'
        && a.status === 'COMPLETED' && !a.details?.revision_mod_id);
      if (!modDl) {
        throw new Error('Request a modification, wait for approval and download it (Factor 3) before uploading a revision.');
      }
      await uploadRevisionFile(editingAsset.serial_number, modDl.action_id, revisionFile, usePasskey ? null : revisionTotpCode.trim(), 'Updating document revision');

      setActionSuccessMsg(`Revision proposed successfully for Token #${editingAsset.token_id}. Pending Manager Approval.`);
      setEditingAsset(null);
      setRevisionFile(null);
      setRevisionTotpCode('');
      await fetchDashboardData();
    } catch (err) {
      console.error('Document update error:', err);
      setError(err.response?.data?.detail || err.message || 'Transaction rejected');
    } finally {
      setIsUpdating(false);
    }
  };

  // Request Access & Verify Against Smart Contract
  const handleRequestDocumentAccess = async (e) => {
    e.preventDefault();
    if (!requestTokenId) return;
    setCheckingAccess(true);
    setAccessResult(null);
    setError(null);

    try {
      const check = await checkAssetAccess(signer, parseInt(requestTokenId), userDID, walletAddress);

      const res = await fetch(`/api/assets/${requestTokenId}`);
      let docInfo = null;
      if (res.ok) {
        docInfo = await res.json();
      }

      try {
        await recordAccessAttempt(
          signer,
          parseInt(requestTokenId),
          userDID,
          check.authorized,
          check.authorized ? 'Authorized by On-Chain ACL' : 'Permission Denied by Contract'
        );
      } catch (logErr) {
        console.warn('Failed to record on-chain access log:', logErr);
      }

      setAccessResult({
        tokenId: requestTokenId,
        authorized: check.authorized,
        level: check.level === 1 ? 'READ' : (check.level === 2 ? 'READ_WRITE' : 'NONE'),
        doc: docInfo,
      });
    } catch (err) {
      console.error('Access check error:', err);
      setAccessResult({
        tokenId: requestTokenId,
        authorized: false,
        error: err.message || 'Token does not exist or verification failed',
      });
    } finally {
      setCheckingAccess(false);
    }
  };

  const panelStyle = {
    background: '#ffffff',
    border: '1px solid #e2e8f0',
    borderRadius: '12px',
    padding: '1.75rem',
    marginBottom: '2rem',
    boxShadow: '0 1px 3px rgba(0,0,0,0.05)'
  };

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', width: '100%' }}>
      {/* Action Messages */}
      {actionSuccessMsg && (
        <div style={{ background: '#ecfdf5', border: '1px solid #10b981', color: '#065f46', padding: '14px 18px', borderRadius: '8px', marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontWeight: '600' }}>✓ {actionSuccessMsg}</span>
          <button onClick={() => setActionSuccessMsg('')} style={{ background: 'transparent', border: 'none', cursor: 'pointer', fontWeight: 'bold' }}>✕</button>
        </div>
      )}

      {error && (
        <div style={{ background: '#fef2f2', border: '1px solid #ef4444', color: '#991b1b', padding: '14px 18px', borderRadius: '8px', marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>⚠ {error}</span>
          <button onClick={() => setError(null)} style={{ background: 'transparent', border: 'none', cursor: 'pointer', fontWeight: 'bold' }}>✕</button>
        </div>
      )}

      {/* USER OVERVIEW METRICS CARDS */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
        {/* Card 1: Assets in Custody / Owned */}
        <div style={panelStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '10px' }}>
            <div style={{ fontSize: '12px', fontWeight: '600', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
              My Active Assets
            </div>
            <button
              onClick={fetchDashboardData}
              disabled={loading}
              style={{ padding: '6px 10px', background: '#0f172a', color: '#fff', border: 'none', borderRadius: '5px', fontSize: '11px', fontWeight: '700', cursor: loading ? 'wait' : 'pointer' }}
            >
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
          <div style={{ fontSize: '32px', fontWeight: '700', color: '#0f172a' }}>
            {loading ? '...' : assets.length}
          </div>
          <div style={{ fontSize: '12px', color: '#10b981', marginTop: '6px', fontWeight: '500' }}>
            {assets.filter(a => a.is_digital).length} Digital Documents · {assets.filter(a => !a.is_digital).length} Physical Items
          </div>
        </div>

        {/* Card 2: Shared Permissions Given */}
        <div style={panelStyle}>
          <div style={{ fontSize: '12px', fontWeight: '600', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
            Access Permissions Granted
          </div>
          <div style={{ fontSize: '32px', fontWeight: '700', color: '#0f172a' }}>
            {loading ? '...' : permissionsData.total_shared_by_count}
          </div>
          <div style={{ marginTop: '8px' }}>
            <button
              onClick={() => {
                setSharesModalType('by_me');
                setShowSharesModal(true);
              }}
              style={{ padding: '4px 10px', background: '#e0e7ff', color: '#4338ca', border: 'none', borderRadius: '4px', fontSize: '11px', fontWeight: '700', cursor: 'pointer' }}
            >
              View Granted Shares List →
            </button>
          </div>
        </div>

        {/* Card 3: Shared With Me */}
        <div style={panelStyle}>
          <div style={{ fontSize: '12px', fontWeight: '600', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
            Shared With Me
          </div>
          <div style={{ fontSize: '32px', fontWeight: '700', color: '#0f172a' }}>
            {loading ? '...' : permissionsData.total_shared_with_count}
          </div>
          <div style={{ marginTop: '8px' }}>
            <button
              onClick={() => {
                setSharesModalType('with_me');
                setShowSharesModal(true);
              }}
              style={{ padding: '4px 10px', background: '#fef3c7', color: '#92400e', border: 'none', borderRadius: '4px', fontSize: '11px', fontWeight: '700', cursor: 'pointer' }}
            >
              View Inbound Shares →
            </button>
          </div>
        </div>

        {/* Card 4: Identity & Cryptographic DID */}
        <div style={panelStyle}>
          <div style={{ fontSize: '12px', fontWeight: '600', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
            Cryptographic Identity
          </div>
          <div style={{ fontSize: '13px', fontWeight: '700', color: '#0f172a', fontFamily: 'monospace', wordBreak: 'break-all' }}>
            {walletAddress ? `${walletAddress.slice(0, 10)}...${walletAddress.slice(-6)}` : 'Connecting...'}
          </div>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '6px', fontFamily: 'monospace' }}>
            Role: <span style={{ fontWeight: 'bold', color: '#2563eb' }}>{user?.role || 'USER'}</span>
          </div>
          <div style={{ fontSize: '10px', color: '#94a3b8', marginTop: '4px', fontFamily: 'monospace' }}>
            DID: {userDID ? `${userDID.slice(0, 20)}...` : '—'}
          </div>
        </div>
      </div>

      {/* SUB-NAVIGATION BAR */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '1.5rem', borderBottom: '1px solid #e2e8f0', paddingBottom: '0.75rem' }}>
        <button
          onClick={() => setActiveSubTab('portfolio')}
          style={{
            padding: '8px 16px',
            borderRadius: '6px',
            border: 'none',
            background: activeSubTab === 'portfolio' ? '#0f172a' : '#f1f5f9',
            color: activeSubTab === 'portfolio' ? '#ffffff' : '#475569',
            fontWeight: '600',
            fontSize: '13px',
            cursor: 'pointer'
          }}
        >
          My Asset Portfolio ({assets.length})
        </button>

        <button
          onClick={() => setActiveSubTab('mint')}
          style={{
            padding: '8px 16px',
            borderRadius: '6px',
            border: 'none',
            background: activeSubTab === 'mint' ? '#0f172a' : '#f1f5f9',
            color: activeSubTab === 'mint' ? '#ffffff' : '#475569',
            fontWeight: '600',
            fontSize: '13px',
            cursor: 'pointer'
          }}
        >
          + Propose Document
        </button>

        <button
          onClick={() => setActiveSubTab('propose-phys')}
          style={{
            padding: '8px 16px',
            borderRadius: '6px',
            border: 'none',
            background: activeSubTab === 'propose-phys' ? '#0f172a' : '#f1f5f9',
            color: activeSubTab === 'propose-phys' ? '#ffffff' : '#475569',
            fontWeight: '600',
            fontSize: '13px',
            cursor: 'pointer'
          }}
        >
          + Propose Hardware
        </button>

        <button
          onClick={() => setActiveSubTab('share')}
          style={{
            padding: '8px 16px',
            borderRadius: '6px',
            border: 'none',
            background: activeSubTab === 'share' ? '#0f172a' : '#f1f5f9',
            color: activeSubTab === 'share' ? '#ffffff' : '#475569',
            fontWeight: '600',
            fontSize: '13px',
            cursor: 'pointer'
          }}
        >
          Manage Access Sharing
        </button>

        <button
          onClick={() => setActiveSubTab('verify')}
          style={{
            padding: '8px 16px',
            borderRadius: '6px',
            border: 'none',
            background: activeSubTab === 'verify' ? '#0f172a' : '#f1f5f9',
            color: activeSubTab === 'verify' ? '#ffffff' : '#475569',
            fontWeight: '600',
            fontSize: '13px',
            cursor: 'pointer'
          }}
        >
          Verify External Document
        </button>
      </div>

      {/* 1. PROPOSE DIGITAL DOCUMENT TAB */}
      {activeSubTab === 'mint' && (
        <div style={panelStyle}>
          <h3 style={{ margin: '0 0 6px', fontSize: '18px', color: '#0f172a' }}>
            Propose Secure Digital Document (Factor 2 Protected)
          </h3>
          <p style={{ margin: '0 0 1.5rem', fontSize: '13px', color: '#64748b' }}>
            Submit a classified document creation proposal to your department. Proposals require Manager or Administrator Factor 3 approval before on-chain minting to Hyperledger Besu.
          </p>

          <form onSubmit={handleDocumentPropose}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.2rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Document Title / Name *
                </label>
                <input
                  type="text"
                  value={docName}
                  onChange={(e) => setDocName(e.target.value)}
                  placeholder="e.g. Radar Guidance Protocol Specs"
                  required
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Document Serial Number *
                </label>
                <input
                  type="text"
                  value={digitalSerial}
                  onChange={(e) => setDigitalSerial(e.target.value)}
                  placeholder="e.g. BEL-DOC-AVIONICS-0042"
                  required
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Forward to Recipient Address *
                </label>
                <input
                  type="text"
                  value={docRecipientAddress}
                  onChange={(e) => setDocRecipientAddress(e.target.value)}
                  placeholder="e.g. 0x123... or DID"
                  required
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Purpose / Justification
                </label>
                <input
                  type="text"
                  value={docPurpose}
                  onChange={(e) => setDocPurpose(e.target.value)}
                  placeholder="e.g. Avionics System Architecture Verification"
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Factor {user?.role === 'ADMIN' || user?.role === 'MANAGER' ? '3' : '2'} TOTP Code *
                </label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    value={docTotpCode}
                    onChange={(e) => setDocTotpCode(e.target.value)}
                    placeholder="6-digit TOTP"
                    maxLength={6}
                    style={{ flex: 1, padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace' }}
                  />
                  <button
                    type="button"
                    onClick={() => handleDocumentPropose(null, true)}
                    style={{ padding: '8px 12px', background: '#e2e8f0', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '12px' }}
                  >
                    🔑 Use Passkey
                  </button>
                </div>
              </div>
            </div>

            <div style={{ marginBottom: '1.2rem' }}>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                Select Confidential Document File *
              </label>
              <input
                type="file"
                required
                onChange={handleFileUpload}
                style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', background: '#f8fafc' }}
              />
              {uploading && <p style={{ fontSize: '12px', color: '#3b82f6', marginTop: '6px' }}>Hashing file and uploading to off-chain vault...</p>}
              {fileHash && (
                <div style={{ marginTop: '8px', padding: '8px 12px', background: '#f0fdf4', border: '1px solid #86efac', borderRadius: '6px', fontSize: '12px', fontFamily: 'monospace', color: '#166534' }}>
                  <strong>Computed SHA-256 Hash:</strong> {fileHash}
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={proposing || uploading || !fileHash}
              style={{
                padding: '12px 24px',
                background: '#0f172a',
                color: '#fff',
                border: 'none',
                borderRadius: '6px',
                fontWeight: 'bold',
                fontSize: '13px',
                cursor: proposing || uploading || !fileHash ? 'not-allowed' : 'pointer',
                opacity: proposing || uploading || !fileHash ? 0.6 : 1
              }}
            >
              {proposing
                ? (proposalStatus || 'Processing...')
                : (user?.role === 'ADMIN' || user?.role === 'MANAGER'
                  ? 'Submit Document for Approval (CRT-)'
                  : 'Submit Document Proposal (CRT-)')
              }
            </button>
          </form>
        </div>
      )}

      {/* 1b. PROPOSE PHYSICAL HARDWARE TAB */}
      {activeSubTab === 'propose-phys' && (
        <div style={panelStyle}>
          <h3 style={{ margin: '0 0 6px', fontSize: '18px', color: '#0f172a' }}>
            Propose Physical Hardware Asset (Factor 2 Protected)
          </h3>
          <p style={{ margin: '0 0 1.5rem', fontSize: '13px', color: '#64748b' }}>
            Submit a classified hardware tracking proposal. Proposals require Manager or Administrator Factor 3 approval before anchoring to the registry.
          </p>

          <form onSubmit={handlePhysicalPropose}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.2rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>Hardware Name *</label>
                <input type="text" value={physName} onChange={(e) => setPhysName(e.target.value)} placeholder="e.g. GPU Node Alpha" required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }} />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>Serial Number *</label>
                <input type="text" value={physSerial} onChange={(e) => setPhysSerial(e.target.value)} placeholder="e.g. SN-9988-XYZ" required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }} />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>Does device have a MAC Address? *</label>
                <select value={hasMac} onChange={(e) => setHasMac(e.target.value === 'true')} style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }}>
                  <option value={false}>No</option>
                  <option value={true}>Yes</option>
                </select>
              </div>

              {hasMac ? (
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>MAC Address *</label>
                  <input type="text" value={physMac} onChange={(e) => setPhysMac(e.target.value)} placeholder="e.g. 00:1A:2B:3C:4D:5E" required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }} />
                </div>
              ) : (
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>Unique Hardware Address *</label>
                  <input type="text" value={physDevAddr} onChange={(e) => setPhysDevAddr(e.target.value)} placeholder="e.g. HASH-123456" required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }} />
                </div>
              )}

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>Recipient Address (DID or Wallet) *</label>
                <input type="text" value={physRecipientAddress} onChange={(e) => setPhysRecipientAddress(e.target.value)} placeholder="Recipient DID or Wallet" required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }} />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>Factor {user?.role === 'ADMIN' || user?.role === 'MANAGER' ? '3' : '2'} TOTP Code *</label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input type="text" value={physTotpCode} onChange={(e) => setPhysTotpCode(e.target.value)} placeholder="6-digit TOTP" maxLength={6} required style={{ flex: 1, padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace' }} />
                  <button type="button" onClick={() => handlePhysicalPropose(null, true)} style={{ padding: '8px 12px', background: '#e2e8f0', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '12px' }}>🔑 Use Passkey</button>
                </div>
              </div>
            </div>

            <button type="submit" disabled={proposingPhys} style={{ padding: '12px 24px', background: '#0f172a', color: '#fff', borderRadius: '6px', fontWeight: 'bold', cursor: proposingPhys ? 'not-allowed' : 'pointer' }}>
              {proposingPhys
                ? (physProposalStatus || 'Processing...')
                : (user?.role === 'ADMIN' || user?.role === 'MANAGER'
                  ? 'Submit Hardware for Approval (CRT-)'
                  : 'Submit Hardware Proposal (CRT-)')
              }
            </button>
          </form>
        </div>
      )}

      {/* 2. MANAGE ACCESS SHARING TAB */}
      {activeSubTab === 'share' && (
        <div style={panelStyle}>
          <h3 style={{ margin: '0 0 6px', fontSize: '18px', color: '#0f172a' }}>
            Grant Document Access Permission
          </h3>
          <p style={{ margin: '0 0 1.5rem', fontSize: '13px', color: '#64748b' }}>
            Grant authorized engineers or departments granular cryptographic access to view or update your digital documents.
          </p>

          {shareSuccessMsg && (
            <div style={{ background: '#ecfdf5', border: '1px solid #10b981', color: '#065f46', padding: '10px 14px', borderRadius: '6px', marginBottom: '1.2rem', fontSize: '13px' }}>
              ✓ {shareSuccessMsg}
            </div>
          )}

          <form onSubmit={handleGrantAccess}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.2rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Select Owned Document *
                </label>
                <select
                  value={shareTokenId}
                  onChange={(e) => setShareTokenId(e.target.value)}
                  required
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }}
                >
                  <option value="">-- Choose an asset to share --</option>
                  {assets.filter(a => a.is_digital).map(a => (
                    <option key={a.token_id} value={a.token_id}>
                      #{a.token_id} - {a.serial_number}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Recipient Wallet Address or DID *
                </label>
                <input
                  type="text"
                  value={shareTargetAddress}
                  onChange={(e) => setShareTargetAddress(e.target.value)}
                  placeholder="0x... or did:ethr:13371:0x..."
                  required
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Access Permission Level
                </label>
                <select
                  value={shareLevel}
                  onChange={(e) => setShareLevel(e.target.value)}
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }}
                >
                  <option value={1}>READ (Download & View Only)</option>
                  <option value={2}>READ_WRITE (Download + Upload Revisions)</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Forwarding Purpose / Justification *
                </label>
                <input
                  type="text"
                  value={sharePurpose}
                  onChange={(e) => setSharePurpose(e.target.value)}
                  placeholder="e.g. Authorized Access for Audit"
                  required
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }}
                />
              </div>
              <label style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: '10px 0', fontSize: '13px' }}>
                <input type="checkbox" checked={shareRequestDownload} onChange={(e) => setShareRequestDownload(e.target.checked)} />
                Also request download permission (a Manager/Admin decides; view is always separate from download)
              </label>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Factor 2 TOTP Code *
                </label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    value={shareTotpCode}
                    onChange={(e) => setShareTotpCode(e.target.value)}
                    placeholder="6-digit TOTP"
                    maxLength={6}
                    required
                    style={{ flex: 1, padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace' }}
                  />
                  <button
                    type="button"
                    onClick={() => handleGrantAccess(null, true)}
                    style={{ padding: '8px 12px', background: '#e2e8f0', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '12px' }}
                  >
                    🔑 Use Passkey
                  </button>
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={sharing || !shareTokenId}
              style={{
                padding: '10px 20px',
                background: sharing ? '#94a3b8' : '#2563eb',
                color: '#ffffff',
                border: 'none',
                borderRadius: '6px',
                fontWeight: '700',
                fontSize: '13px',
                cursor: sharing ? 'not-allowed' : 'pointer'
              }}
            >
              {sharing ? 'Submitting Share Proposal...' : 'Submit Share Proposal (SHR-)'}
            </button>
          </form>

          {/* REVOKE ACCESS PERMISSION SECTION */}
          <div style={{ marginTop: '3rem', paddingTop: '2rem', borderTop: '2px solid #e2e8f0' }}>
            <h3 style={{ margin: '0 0 6px', fontSize: '18px', color: '#0f172a' }}>
              Revoke Document Access Permission
            </h3>
            <p style={{ margin: '0 0 1.5rem', fontSize: '13px', color: '#64748b' }}>
              Remove previously granted access permissions from specific users or departments for your digital documents.
            </p>

            {revokeSuccessMsg && (
              <div style={{ background: '#fef3c7', border: '1px solid #f59e0b', color: '#92400e', padding: '10px 14px', borderRadius: '6px', marginBottom: '1.2rem', fontSize: '13px' }}>
                ✓ {revokeSuccessMsg}
              </div>
            )}

            <form onSubmit={handleRevokeAccessPermission}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.2rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                    Select Owned Document *
                  </label>
                  <select
                    value={revokeAccessTokenId}
                    onChange={(e) => setRevokeAccessTokenId(e.target.value)}
                    required
                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1' }}
                  >
                    <option value="">-- Choose an asset --</option>
                    {assets.filter(a => a.is_digital).map(a => (
                      <option key={a.token_id} value={a.token_id}>
                        #{a.token_id} - {a.serial_number}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                    Target DID or Wallet Address *
                  </label>
                  <input
                    type="text"
                    value={revokeTargetDID}
                    onChange={(e) => setRevokeTargetDID(e.target.value)}
                    placeholder="0x... or did:ethr:13371:0x..."
                    required
                    style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace' }}
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={revokingAccess || !revokeAccessTokenId}
                style={{
                  padding: '10px 20px',
                  background: revokingAccess ? '#94a3b8' : '#dc2626',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  fontWeight: '700',
                  fontSize: '13px',
                  cursor: revokingAccess ? 'not-allowed' : 'pointer'
                }}
              >
                {revokingAccess ? 'Revoking on Blockchain...' : 'Revoke Access Permission on-Chain'}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* 3. VERIFY EXTERNAL DOCUMENT TAB */}
      {activeSubTab === 'verify' && (
        <div style={panelStyle}>
          <h3 style={{ margin: '0 0 6px', fontSize: '18px', color: '#0f172a' }}>
            Verify & Request External Document Access
          </h3>
          <p style={{ margin: '0 0 1.5rem', fontSize: '13px', color: '#64748b' }}>
            Check if your DID has been granted access permissions to an asset owned by another department.
          </p>

          <form onSubmit={handleRequestDocumentAccess} style={{ display: 'flex', gap: '10px', marginBottom: '1.2rem' }}>
            <input
              type="number"
              value={requestTokenId}
              onChange={(e) => setRequestTokenId(e.target.value)}
              placeholder="Enter Token ID (e.g. 201, 202, 301)"
              required
              style={{ flex: 1, padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace' }}
            />
            <button
              type="submit"
              disabled={checkingAccess}
              style={{ padding: '10px 20px', background: checkingAccess ? '#94a3b8' : '#059669', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}
            >
              {checkingAccess ? 'Querying Blockchain...' : 'Verify Access Permission'}
            </button>
          </form>

          {accessResult && (
            <div style={{ padding: '1.25rem', borderRadius: '8px', background: accessResult.authorized ? '#ecfdf5' : '#fef2f2', border: `1px solid ${accessResult.authorized ? '#a7f3d0' : '#fecaca'}` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                <span style={{ fontSize: '11px', fontWeight: 'bold', padding: '2px 8px', borderRadius: '4px', background: accessResult.authorized ? '#d1fae5' : '#fee2e2', color: accessResult.authorized ? '#065f46' : '#991b1b' }}>
                  {accessResult.authorized ? 'ACCESS AUTHORIZED' : 'ACCESS DENIED'}
                </span>
                <h4 style={{ margin: 0, fontSize: '15px', color: accessResult.authorized ? '#065f46' : '#991b1b' }}>
                  {accessResult.authorized ? 'Verified on Hyperledger Besu Smart Contract' : 'No Valid On-Chain Permission Found'}
                </h4>
              </div>

              <div style={{ fontSize: '12px', fontFamily: 'monospace', color: accessResult.authorized ? '#047857' : '#b91c1c' }}>
                <strong>Token ID:</strong> #{accessResult.tokenId}<br />
                <strong>Permission Level:</strong> {accessResult.level || 'NONE'}<br />
                {accessResult.doc && (
                  <>
                    <strong>Identifier:</strong> {accessResult.doc.serial_number}<br />
                    {accessResult.doc.file_hash && <span><strong>SHA-256 Hash:</strong> {accessResult.doc.file_hash}<br /></span>}
                  </>
                )}
              </div>

              {accessResult.authorized && accessResult.doc?.offchain_uri && (
                <div style={{ marginTop: '1rem', fontSize: '12px', color: '#475569' }}>
                  Downloads are controlled: use “Request Download” on the document (approval + Factor 3 + Download ID).
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 4. MY ASSET PORTFOLIO GRID */}
      {activeSubTab === 'portfolio' && <DocumentWorkflowPanel user={user} />}
      {activeSubTab === 'portfolio' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <h3 style={{ margin: 0, fontSize: '18px', color: '#0f172a' }}>
              My Assigned & Owned Assets
            </h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '12px', color: '#64748b' }}>
                Showing {assets.length} Item{assets.length !== 1 ? 's' : ''}
              </span>
              <button
                onClick={fetchDashboardData}
                disabled={loading}
                style={{ padding: '7px 11px', background: '#0f172a', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '11px', fontWeight: '700', cursor: loading ? 'wait' : 'pointer' }}
              >
                {loading ? 'Refreshing...' : 'Refresh Portfolio'}
              </button>
            </div>
          </div>

          {loading && <p style={{ color: '#64748b' }}>Querying on-chain asset registry...</p>}

          {!loading && assets.length === 0 && (
            <div style={{ textAlign: 'center', padding: '3.5rem', background: '#ffffff', borderRadius: '12px', border: '1px dashed #cbd5e1' }}>
              <p style={{ margin: '0 0 10px', color: '#64748b', fontSize: '14px' }}>No assets assigned to your DID yet.</p>
              <button
                onClick={() => setActiveSubTab('mint')}
                style={{ padding: '8px 16px', background: '#0f172a', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
              >
                + Mint Your First Digital Document
              </button>
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1.5rem' }}>
            {assets.map((asset) => (
              <div key={asset.token_id} style={{ background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '12px', padding: '1.5rem', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                  <span style={{ fontSize: '11px', fontWeight: 'bold', color: asset.is_digital ? '#7c3aed' : '#2563eb', textTransform: 'uppercase', background: asset.is_digital ? '#f3e8ff' : '#eff6ff', padding: '2px 8px', borderRadius: '4px' }}>
                    {asset.is_digital ? 'Digital Document' : 'Physical Hardware'}
                  </span>
                  <span style={{ fontSize: '12px', fontFamily: 'monospace', color: '#64748b' }}>#{asset.token_id}</span>
                </div>

                <h4 style={{ margin: '0 0 8px', fontSize: '16px', color: '#0f172a', fontFamily: 'monospace' }}>
                  {asset.serial_number}
                </h4>

                {asset.file_hash && (
                  <div style={{ fontSize: '11px', fontFamily: 'monospace', color: '#475569', background: '#f8fafc', padding: '6px 8px', borderRadius: '4px', marginBottom: '10px', wordBreak: 'break-all' }}>
                    <strong>SHA-256:</strong> {asset.file_hash.substring(0, 20)}...
                  </div>
                )}

                <div style={{ display: 'flex', gap: '8px', marginTop: '1rem', flexWrap: 'wrap' }}>
                  <button
                        onClick={() => window.open(`/verify/token/${asset.token_id}`, '_blank')}
                    style={{ flex: '1 1 120px', padding: '8px', background: '#3b82f6', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
                  >
                    Verify on Chain
                  </button>

                  {asset.is_digital && asset.offchain_uri && (
                    <div style={{ display: 'flex', gap: '8px', flex: '1 1 100%' }}>
                      <button
                        onClick={() => handleViewDocument(asset.serial_number)}
                        style={{ flex: 1, padding: '8px', background: '#059669', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
                      >
                        View (Watermarked)
                      </button>
                      <button
                        onClick={async () => {
                          try {
                            const code = window.prompt('Factor 2 (View/Submission) is required to request a download. Enter the TOTP code, or leave empty to use your Factor 2 passkey:');
                            if (code === null) return;
                            const purpose = window.prompt('Purpose of this download:') || 'Download';
                            const r = await requestControlledDownload(asset.serial_number, 'STANDARD', purpose, code.trim() || null);
                            alert(`${r.action_id} submitted. It needs approval before you can download it with Factor 3.`);
                          } catch (err) {
                            alert(err.response?.data?.detail || err.message || 'Download request failed.');
                          }
                        }}
                        style={{ flex: 1, padding: '8px', background: '#7c3aed', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
                      >
                        Request Download
                      </button>
                    </div>
                  )}

                  {asset.is_digital && (asset.permission_level === 'READ_WRITE' || asset.permission_level === 'OWNER' || asset.is_owner) && (
                    <button
                      onClick={() => {
                        setEditingAsset(asset);
                        setRevisionFile(null);
                      }}
                      style={{ flex: '1 1 100%', padding: '8px', background: '#f59e0b', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer', marginTop: '4px' }}
                    >
                      Upload Revised Version (after approved modification download)
                    </button>
                  )}
                  {asset.is_digital && (
                    <button
                      onClick={async () => {
                        try {
                          const code = window.prompt('Factor 2 (View/Submission) is required to request a modification. Enter the TOTP code, or leave empty to use your Factor 2 passkey:');
                          if (code === null) return;
                          const purpose = window.prompt('What will you change?') || 'Modification';
                          const r = await requestControlledDownload(asset.serial_number, 'MODIFICATION', purpose, code.trim() || null);
                          alert(`${r.action_id} submitted. After approval, download it (Factor 3), edit it externally, then upload the revision.`);
                        } catch (err) {
                          alert(err.response?.data?.detail || err.message || 'Modification request failed.');
                        }
                      }}
                      style={{ flex: '1 1 100%', padding: '8px', background: '#0f766e', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer', marginTop: '4px' }}
                    >
                      Request Modification
                    </button>
                  )}

                  <a
                    href={getAssetCertificateUrl(asset.serial_number)}
                    target="_blank"
                    rel="noreferrer"
                    style={{ flex: '1 1 100%', padding: '8px', background: '#0284c7', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', textDecoration: 'none', textAlign: 'center', marginTop: '4px' }}
                  >
                    Printable Defense Certificate (SVG)
                  </a>

                  {/* Revoke Own Asset */}
                  {(asset.is_owner || asset.owner_did?.toLowerCase() === userDID.toLowerCase()) && (
                    <button
                      disabled={revokingTokenId === asset.token_id}
                      onClick={() => handleRevokeOwnAsset(asset.token_id)}
                      style={{
                        flex: '1 1 100%',
                        padding: '8px',
                        background: '#dc2626',
                        color: '#ffffff',
                        border: 'none',
                        borderRadius: '6px',
                        fontSize: '12px',
                        fontWeight: 'bold',
                        cursor: revokingTokenId === asset.token_id ? 'not-allowed' : 'pointer',
                        marginTop: '4px'
                      }}
                    >
                      {revokingTokenId === asset.token_id ? 'Revoking on Chain...' : 'Revoke / Burn Asset'}
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SHARED PERMISSIONS AUDIT MODAL */}
      {showSharesModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000 }}>
          <div style={{ background: '#ffffff', padding: '2rem', borderRadius: '12px', maxWidth: '680px', width: '90%', maxHeight: '80vh', overflowY: 'auto', boxShadow: '0 25px 50px -12px rgba(0,0,0,0.25)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #e2e8f0', paddingBottom: '0.75rem' }}>
              <h3 style={{ margin: 0, fontSize: '18px', color: '#0f172a' }}>
                {sharesModalType === 'by_me' ? 'Active Access Grants Given to Others' : 'Documents Shared With Me'}
              </h3>
              <button onClick={() => setShowSharesModal(false)} style={{ background: 'transparent', border: 'none', fontSize: '18px', cursor: 'pointer', fontWeight: 'bold' }}>✕</button>
            </div>

            {sharesModalType === 'by_me' && (
              <div>
                {permissionsData.shared_by_user.length === 0 ? (
                  <p style={{ color: '#64748b', fontSize: '13px' }}>You have not granted access permissions on any documents yet.</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {permissionsData.shared_by_user.map((p, idx) => (
                      <div key={idx} style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '12px', fontSize: '12px', fontFamily: 'monospace' }}>
                        <div><strong>Asset Serial:</strong> {p.asset_serial}</div>
                        <div><strong>Granted To DID:</strong> {p.target_did}</div>
                        <div><strong>Block #:</strong> {p.block_number} · <strong>Tx:</strong> {p.tx_hash?.slice(0, 14)}...</div>
                        {p.timestamp && <div style={{ color: '#64748b', fontSize: '11px', marginTop: '4px' }}>Granted on: {new Date(p.timestamp).toLocaleString()}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {sharesModalType === 'with_me' && (
              <div>
                {permissionsData.shared_with_user.length === 0 ? (
                  <p style={{ color: '#64748b', fontSize: '13px' }}>No documents have been shared with your DID yet.</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {permissionsData.shared_with_user.map((p, idx) => (
                      <div key={idx} style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '12px', fontSize: '12px', fontFamily: 'monospace' }}>
                        <div><strong>Asset Serial:</strong> {p.asset_serial}</div>
                        <div><strong>Shared By DID:</strong> {p.actor_did}</div>
                        <div><strong>Block #:</strong> {p.block_number}</div>
                        {p.timestamp && <div style={{ color: '#64748b', fontSize: '11px', marginTop: '4px' }}>Shared on: {new Date(p.timestamp).toLocaleString()}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div style={{ marginTop: '1.5rem', textAlign: 'right' }}>
              <button
                onClick={() => setShowSharesModal(false)}
                style={{ padding: '8px 16px', background: '#0f172a', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* DOCUMENT REVISION MODAL */}
      {editingAsset && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000 }}>
          <div style={{ background: '#ffffff', padding: '2rem', borderRadius: '12px', maxWidth: '500px', width: '90%', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1)' }}>
            <h3 style={{ margin: '0 0 10px', fontSize: '18px', color: '#0f172a' }}>
              Update Document Revision
            </h3>
            <p style={{ margin: '0 0 1.2rem', fontSize: '13px', color: '#64748b' }}>
              Token <strong>#{editingAsset.token_id}</strong> ({editingAsset.serial_number}). Uploading a new file recalculates its SHA-256 hash and updates the on-chain metadata.
            </p>

            <form onSubmit={handleUploadRevision}>
              <div style={{ marginBottom: '1.2rem' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Select Updated Document File
                </label>
                <input
                  type="file"
                  required
                  onChange={(e) => setRevisionFile(e.target.files[0])}
                  style={{ width: '100%', padding: '8px', border: '1px solid #cbd5e1', borderRadius: '6px' }}
                />
              </div>

              <div style={{ marginBottom: '1.2rem' }}>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Factor 3 (Mint/Approve/Modify) TOTP Code *
                </label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    value={revisionTotpCode}
                    onChange={(e) => setRevisionTotpCode(e.target.value)}
                    placeholder="6-digit TOTP"
                    maxLength={6}
                    style={{ flex: 1, padding: '8px', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace' }}
                  />
                  <button
                    type="button"
                    onClick={() => handleUploadRevision(null, true)}
                    style={{ padding: '8px 12px', background: '#e2e8f0', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '12px' }}
                  >
                    🔑 Use Passkey
                  </button>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  disabled={isUpdating}
                  onClick={() => setEditingAsset(null)}
                  style={{ padding: '8px 16px', background: '#e2e8f0', color: '#334155', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isUpdating || !revisionFile}
                  style={{ padding: '8px 16px', background: isUpdating ? '#94a3b8' : '#d97706', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}
                >
                  {isUpdating ? 'Submitting Proposal...' : 'Propose Revision'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
