import { useState, useEffect } from 'react';
import axios from 'axios';
import { ethers } from 'ethers';
import { useAuth } from '../context/AuthContext';
import { getAssetsByOwner, getAssetCertificateUrl, uploadDocument } from '../services/api';
import {
  checkAssetAccess,
  recordAccessAttempt,
  updateDigitalAsset,
  mintDigitalAsset,
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
  const [activeSubTab, setActiveSubTab] = useState('portfolio'); // 'portfolio' | 'mint' | 'share' | 'verify'

  // Sharing Modal
  const [showSharesModal, setShowSharesModal] = useState(false);
  const [sharesModalType, setSharesModalType] = useState('by_me'); // 'by_me' | 'with_me'

  // Digital Mint State
  const [digitalTokenId, setDigitalTokenId] = useState('');
  const [digitalSerial, setDigitalSerial] = useState('');
  const [digitalRecipient, setDigitalRecipient] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileHash, setFileHash] = useState('');
  const [offchainURI, setOffchainURI] = useState('');
  const [uploading, setUploading] = useState(false);
  const [minting, setMinting] = useState(false);
  const [mintResult, setMintResult] = useState(null);

  // Grant Access State
  const [shareTokenId, setShareTokenId] = useState('');
  const [shareTargetAddress, setShareTargetAddress] = useState('');
  const [shareLevel, setShareLevel] = useState(1); // 1 = READ, 2 = READ_WRITE
  const [sharing, setSharing] = useState(false);
  const [shareSuccessMsg, setShareSuccessMsg] = useState('');

  // Access Request / Verification State
  const [requestTokenId, setRequestTokenId] = useState('');
  const [checkingAccess, setCheckingAccess] = useState(false);
  const [accessResult, setAccessResult] = useState(null);

  // Document Revision / Update State (for READ_WRITE holders)
  const [editingAsset, setEditingAsset] = useState(null);
  const [revisionFile, setRevisionFile] = useState(null);
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

  // Handle Minting Digital Asset NFT
  const handleDigitalMint = async (e) => {
    e.preventDefault();
    setError(null);
    setMinting(true);
    setMintResult(null);

    try {
      if (!signer) {
        throw new Error('Unlock your wallet again before minting or changing assets.');
      }
      if (!fileHash || !offchainURI) {
        throw new Error('Please select and upload a document first.');
      }
      const tId = parseInt(digitalTokenId);
      if (!tId || tId <= 0) {
        throw new Error('Please enter a valid numeric Token ID (e.g., 301, 401, 701).');
      }
      if (!ethers.isAddress(digitalRecipient)) {
        throw new Error('Enter a valid recipient wallet address (0x...).');
      }

      const tx = await mintDigitalAsset(
        signer,
        digitalRecipient,
        tId,
        digitalSerial,
        `did:ethr:13371:${digitalRecipient.toLowerCase()}`,
        fileHash,
        offchainURI
      );

      setMintResult({
        tokenId: tId,
        serialNumber: digitalSerial,
        txHash: tx.txHash,
        fileHash,
      });

      setActionSuccessMsg(`Digital Asset #${tId} successfully minted and anchored on Hyperledger Besu!`);
      setDigitalTokenId('');
      setDigitalSerial('');
      setDigitalRecipient('');
      setSelectedFile(null);
      setFileHash('');
      setOffchainURI('');

      await addTokenToMetaMask(deployment.address, tId);
      await fetchDashboardData();
    } catch (err) {
      console.error('Digital mint error:', err);
      setError(err.message || 'Digital minting failed');
    } finally {
      setMinting(false);
    }
  };

  // Handle Granting Access Permission
  const handleGrantAccess = async (e) => {
    e.preventDefault();
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

      const tx = await grantAssetAccess(signer, tId, targetDID, parseInt(shareLevel));
      setShareSuccessMsg(`Access permission successfully granted to ${targetDID.slice(0, 24)}... (Tx: ${tx.txHash.slice(0, 10)}...)`);
      setShareTokenId('');
      setShareTargetAddress('');
      await fetchDashboardData();
    } catch (err) {
      console.error('Grant access error:', err);
      setError(err.message || 'Failed to grant access on blockchain');
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
  const handleUploadRevision = async (e) => {
    e.preventDefault();
    if (!editingAsset || !revisionFile) return;

    setIsUpdating(true);
    setActionSuccessMsg('');
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', revisionFile);

      const uploadData = await uploadDocument(formData);

      const tx = await updateDigitalAsset(
        signer,
        editingAsset.token_id,
        userDID,
        uploadData.file_hash,
        uploadData.offchain_uri
      );

      setActionSuccessMsg(`Successfully updated Token #${editingAsset.token_id} on-chain. Tx: ${tx.txHash.slice(0, 10)}...`);
      setEditingAsset(null);
      setRevisionFile(null);
      await fetchDashboardData();
    } catch (err) {
      console.error('Document update error:', err);
      setError(err.message || 'Transaction rejected');
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
          + Mint Digital Document
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

      {/* 1. MINT DIGITAL ASSET TAB */}
      {activeSubTab === 'mint' && (
        <div style={panelStyle}>
          <h3 style={{ margin: '0 0 6px', fontSize: '18px', color: '#0f172a' }}>
            Mint Secure Digital Document NFT
          </h3>
          <p style={{ margin: '0 0 1.5rem', fontSize: '13px', color: '#64748b' }}>
            Upload sensitive defense files or blueprints. The file is hashed with SHA-256 and anchored directly to the Hyperledger Besu consortium with your decentralized identifier (DID).
          </p>

          <form onSubmit={handleDigitalMint}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.2rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Document Token ID *
                </label>
                <input
                  type="number"
                  value={digitalTokenId}
                  onChange={(e) => setDigitalTokenId(e.target.value)}
                  placeholder="e.g. 701, 702, 801"
                  required
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Document Serial / Reference *
                </label>
                <input
                  type="text"
                  value={digitalSerial}
                  onChange={(e) => setDigitalSerial(e.target.value)}
                  placeholder="e.g. DOC-RADAR-SPECS-2026"
                  required
                  style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 'bold', color: '#334155', marginBottom: '6px' }}>
                  Recipient Wallet Address *
                </label>
                <input type="text" value={digitalRecipient} onChange={(e) => setDigitalRecipient(e.target.value)} placeholder="0x..." required style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontFamily: 'monospace' }} />
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
              disabled={minting || uploading || !fileHash}
              style={{
                padding: '12px 24px',
                background: (minting || uploading || !fileHash) ? '#94a3b8' : '#0f172a',
                color: '#ffffff',
                border: 'none',
                borderRadius: '8px',
                fontWeight: '700',
                fontSize: '13px',
                cursor: (minting || uploading || !fileHash) ? 'not-allowed' : 'pointer'
              }}
            >
              {minting ? 'Anchoring to Hyperledger Besu...' : 'Mint & Anchor Digital Document'}
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
              {sharing ? 'Registering on Blockchain...' : 'Grant Access Permission on-Chain'}
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
                <div style={{ marginTop: '1rem' }}>
                  <button
                    onClick={() => {
                      const filename = accessResult.doc.offchain_uri.split('/').pop();
                      const url = `/api/assets/document/download/${filename}?token_id=${accessResult.tokenId}&wallet_address=${walletAddress}&did=${encodeURIComponent(userDID)}`;
                      window.open(url, '_blank');
                    }}
                    style={{ padding: '8px 16px', background: '#059669', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
                  >
                    Download Authorized Document from Vault
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 4. MY ASSET PORTFOLIO GRID */}
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
                    <button
                      onClick={async () => {
                        try {
                          await recordAccessAttempt(signer, asset.token_id, userDID, true, 'Authorized File Download');
                          const filename = asset.offchain_uri.split('/').pop();
                          const url = `/api/assets/document/download/${filename}?token_id=${asset.token_id}&wallet_address=${walletAddress}&did=${encodeURIComponent(userDID)}`;
                          window.open(url, '_blank');
                        } catch (err) {
                          console.error('Audit log failed', err);
                          alert('Download transaction log required.');
                        }
                      }}
                      style={{ flex: '1 1 120px', padding: '8px', background: '#059669', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
                    >
                      Download File
                    </button>
                  )}

                  {asset.is_digital && (asset.permission_level === 'READ_WRITE' || asset.permission_level === 'OWNER' || asset.is_owner) && (
                    <button
                      onClick={() => {
                        setEditingAsset(asset);
                        setRevisionFile(null);
                      }}
                      style={{ flex: '1 1 100%', padding: '8px', background: '#f59e0b', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer', marginTop: '4px' }}
                    >
                      Upload Revised Version (READ_WRITE)
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
                  {isUpdating ? 'Committing to Blockchain...' : 'Sign & Update On-Chain'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
