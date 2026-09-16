import { useState, useRef } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { uploadDocument } from '../services/api';
import {
  mintAsset,
  mintDigitalAsset,
  grantAssetAccess,
  revokeAssetAccess,
  transferAsset,
  revokeAsset,
  getAsset,
  addTokenToMetaMask,
  checkManagerRole,
  recordAccessAttempt
} from '../services/web3';
import deployment from '../../../contracts/deployments/localhost.json';

export default function ManagerDashboard() {
  const { signer, user } = useAuth();
  const [activeTab, setActiveTab] = useState('digital'); // 'digital' | 'physical' | 'access' | 'lifecycle'

  // Digital Mint State
  const [digitalTokenId, setDigitalTokenId] = useState('');
  const [digitalSerial, setDigitalSerial] = useState('');
  const [digitalRecipient, setDigitalRecipient] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileHash, setFileHash] = useState('');
  const [offchainURI, setOffchainURI] = useState('');
  const [uploading, setUploading] = useState(false);
  const [digitalMinting, setDigitalMinting] = useState(false);
  const [digitalMintResult, setDigitalMintResult] = useState(null);

  // Physical Mint State
  const [mintTokenId, setMintTokenId] = useState('');
  const [mintSerial, setMintSerial] = useState('');
  const [mintRecipient, setMintRecipient] = useState('');
  const [minting, setMinting] = useState(false);
  const [mintedAsset, setMintedAsset] = useState(null);

  // Access Control State
  const [accessDocTokenId, setAccessDocTokenId] = useState('');
  const [accessTargetDID, setAccessTargetDID] = useState('');
  const [accessLevel, setAccessLevel] = useState(1); // 1 = READ
  const [granting, setGranting] = useState(false);
  const [accessResult, setAccessResult] = useState(null);

  // Transfer State
  const [transferTokenId, setTransferTokenId] = useState('');
  const [transferRecipient, setTransferRecipient] = useState('');
  const [transferring, setTransferring] = useState(false);
  const [transferResult, setTransferResult] = useState(null);

  // Revoke State
  const [revokeTokenId, setRevokeTokenId] = useState('');
  const [revoking, setRevoking] = useState(false);
  const [revokeResult, setRevokeResult] = useState(null);

  const [error, setError] = useState('');

  // Handle File Upload & Off-chain SHA-256 generation
  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setSelectedFile(file);
    setUploading(true);
    setError('');

    try {
      const formData = new FormData();
      formData.append('file', file);

      const data = await uploadDocument(formData);

      setFileHash(data.file_hash);
      setOffchainURI(data.offchain_uri);
      if (!digitalSerial) setDigitalSerial(`DOC-${Date.now()}-${file.name.toUpperCase().substring(0, 30)}`);
    } catch (err) {
      console.error('File upload error:', err);
      setError(err.response?.data?.detail || 'File processing failed');
    } finally {
      setUploading(false);
    }
  };

  const handleDigitalMint = async (e) => {
    e.preventDefault();
    setError('');
    setDigitalMinting(true);
    setDigitalMintResult(null);

    try {
      if (!fileHash || !offchainURI) {
        throw new Error('Please upload a document to generate its SHA-256 hash first.');
      }

      const callerAddress = await signer.getAddress();
      const isMgr = await checkManagerRole(signer, callerAddress);
      const userDID = `did:ethr:13371:${callerAddress.toLowerCase()}`;

      if (!isMgr) {
        try {
          await recordAccessAttempt(
            signer,
            parseInt(digitalTokenId) || 0,
            userDID,
            false,
            'Unauthorized Mint Attempt (Missing MANAGER_ROLE)'
          );
        } catch (logErr) {
          console.warn('Failed to record on-chain access attempt:', logErr);
        }
        throw new Error('Access Denied: Your account does not possess the MANAGER_ROLE on the smart contract registry. An unauthorized attempt has been logged to the audit ledger.');
      }

      // Ensure token ID and serial are unique and don't conflict with existing on-chain tokens
      // On-chain tokens already include: 101 (LEX-DRONE-ALPHA-01), 102 (LEX-SECURE-SERVER-99), 201 (LEX-CONFIDENTIAL-AI-SPECS.pdf), 202 (LEX-QUANTUM-ALGO-V2.pdf), 501, 601
      const tokenIdNum = parseInt(digitalTokenId) || 0;
      const serialUsed = digitalSerial ? ['LEX-DRONE-ALPHA-01', 'LEX-SECURE-SERVER-99', 'LEX-CONFIDENTIAL-AI-SPECS.pdf', 'LEX-QUANTUM-ALGO-V2.pdf', 'LEX-E2E-PHYSICAL-001', 'LEX-E2E-DIGITAL-DOC-001'].includes(digitalSerial) : false;
      const tokenUsed = [101, 102, 201, 202, 501, 601].includes(tokenIdNum);

      if (!tokenIdNum || tokenIdNum <= 0) {
        throw new Error('Token ID must be a positive integer (e.g., 301, 401, 701 — avoid 101, 102, 201, 202, 501, 601 which already exist on-chain).');
      }
      if (tokenUsed) {
        throw new Error(`Token ID #${tokenIdNum} already exists on-chain. Please use a unique token ID (e.g., 301, 401, 701, 801, 901, etc.).`);
      }
      if (serialUsed) {
        throw new Error(`Serial number "${digitalSerial}" already exists on-chain. Please use a unique serial number.`);
      }
      if (!digitalSerial || digitalSerial.trim().length === 0) {
        throw new Error('Serial number is required. The smart contract requires EmptySerialNumber to be non-empty.');
      }
      if (!fileHash || fileHash.trim().length === 0) {
        throw new Error('File hash is required (SHA-256). Upload a document first.');
      }
      if (!offchainURI || offchainURI.trim().length === 0) {
        throw new Error('Off-chain URI is required. Upload a document first.');
      }

      const did = `did:ethr:13371:${digitalRecipient.toLowerCase()}`;
      const result = await mintDigitalAsset(
        signer,
        digitalRecipient,
        parseInt(digitalTokenId),
        digitalSerial,
        did,
        fileHash,
        offchainURI
      );

      setDigitalMintResult({
        tokenId: digitalTokenId,
        serialNumber: digitalSerial,
        fileHash,
        offchainURI,
        ownerDID: did,
        txHash: result.txHash,
      });

      await addTokenToMetaMask(deployment.address, digitalTokenId);
    } catch (err) {
      console.error('Digital Minting error:', err);
      setError(err.message || 'Digital Minting failed');
    } finally {
      setDigitalMinting(false);
    }
  };

  const handlePhysicalMint = async (e) => {
    e.preventDefault();
    setError('');
    setMinting(true);
    setMintedAsset(null);

    try {
      const callerAddress = await signer.getAddress();
      const isMgr = await checkManagerRole(signer, callerAddress);
      const userDID = `did:ethr:13371:${callerAddress.toLowerCase()}`;

      if (!isMgr) {
        try {
          await recordAccessAttempt(
            signer,
            parseInt(mintTokenId) || 0,
            userDID,
            false,
            'Unauthorized Physical Mint Attempt (Missing MANAGER_ROLE)'
          );
        } catch (logErr) {
          console.warn('Failed to record on-chain access attempt:', logErr);
        }
        throw new Error('Access Denied: Your account does not possess the MANAGER_ROLE on the smart contract registry. An unauthorized attempt has been logged to the audit ledger.');
      }

      // Validate unique token/serial for physical mint (avoid existing: 101, 102, 501)
      const pTokenNum = parseInt(mintTokenId) || 0;
      const pSerialUsed = mintSerial ? ['LEX-DRONE-ALPHA-01', 'LEX-SECURE-SERVER-99', 'LEX-CONFIDENTIAL-AI-SPECS.pdf', 'LEX-QUANTUM-ALGO-V2.pdf', 'LEX-E2E-PHYSICAL-001', 'LEX-E2E-DIGITAL-DOC-001'].includes(mintSerial) : false;
      const pTokenUsed = [101, 102, 201, 202, 501, 601].includes(pTokenNum);
      if (!pTokenNum || pTokenNum <= 0) {
        throw new Error('Physical Token ID must be a positive integer (e.g., 301, 401 — avoid 101, 102, 501, 601 which exist on-chain).');
      }
      if (pTokenUsed) {
        throw new Error(`Physical Token ID #${pTokenNum} already exists on-chain. Use a unique ID.`);
      }
      if (pSerialUsed) {
        throw new Error(`Physical Serial "${mintSerial}" already exists on-chain. Use a unique serial.`);
      }
      if (!mintSerial || mintSerial.trim().length === 0) {
        throw new Error('Physical Serial number is required (smart contract requires non-empty serial number).');
      }

      const did = `did:ethr:13371:${mintRecipient.toLowerCase()}`;
      const result = await mintAsset(
        signer,
        mintRecipient,
        parseInt(mintTokenId),
        mintSerial,
        did
      );

      const asset = await getAsset(mintTokenId);
      setMintedAsset({
        ...(asset || {}),
        tokenId: mintTokenId,
        serialNumber: mintSerial,
        txHash: result.txHash,
      });

      await addTokenToMetaMask(deployment.address, mintTokenId);
    } catch (err) {
      console.error('Minting error:', err);
      setError(err.message || 'Minting failed');
    } finally {
      setMinting(false);
    }
  };

  const handleGrantAccess = async (e) => {
    e.preventDefault();
    setError('');
    setGranting(true);
    setAccessResult(null);

    try {
      // Normalize target DID to ensure chain ID 13371 and lowercase address format
      let formattedDID = accessTargetDID.trim();
      if (formattedDID.startsWith('0x')) {
        formattedDID = `did:ethr:13371:${formattedDID.toLowerCase()}`;
      } else if (formattedDID.startsWith('did:ethr:')) {
        const parts = formattedDID.split(':');
        const addr = parts[parts.length - 1].toLowerCase();
        formattedDID = `did:ethr:13371:${addr}`;
      }

      const result = await grantAssetAccess(
        signer,
        parseInt(accessDocTokenId),
        formattedDID,
        parseInt(accessLevel)
      );

      setAccessResult({
        tokenId: accessDocTokenId,
        targetDID: formattedDID,
        level: accessLevel === 1 ? 'READ' : 'READ_WRITE',
        txHash: result.txHash,
      });
    } catch (err) {
      console.error('Access grant error:', err);
      setError(err.message || 'Granting access failed');
    } finally {
      setGranting(false);
    }
  };

  const handleTransfer = async (e) => {
    e.preventDefault();
    setError('');
    setTransferring(true);
    setTransferResult(null);

    try {
      const callerAddress = await signer.getAddress();
      const isMgr = await checkManagerRole(signer, callerAddress);
      const userDID = `did:ethr:13371:${callerAddress.toLowerCase()}`;

      if (!isMgr) {
        try {
          await recordAccessAttempt(
            signer,
            parseInt(transferTokenId) || 0,
            userDID,
            false,
            'Unauthorized Asset Transfer Attempt (Missing MANAGER_ROLE)'
          );
        } catch (logErr) {
          console.warn('Failed to record on-chain access attempt:', logErr);
        }
        throw new Error('Access Denied: Your account does not possess the MANAGER_ROLE on the smart contract registry. An unauthorized attempt has been logged to the audit ledger.');
      }

      // Role check: Managers can only transfer PHYSICAL assets
      const assetData = await getAsset(transferTokenId);
      if (assetData?.isDigital && user?.role === 'MANAGER') {
        throw new Error('Policy Violation: Managers are only permitted to transfer PHYSICAL defense hardware. Custody transfer of digital documents is restricted to Administrators.');
      }

      const result = await transferAsset(
        signer,
        transferRecipient,
        parseInt(transferTokenId),
        `did:ethr:13371:${transferRecipient.toLowerCase()}`
      );

      setTransferResult({
        tokenId: transferTokenId,
        to: transferRecipient,
        txHash: result.txHash
      });
    } catch (err) {
      console.error('Transfer error:', err);
      setError(err.message || 'Transfer failed');
    } finally {
      setTransferring(false);
    }
  };

  const handleRevoke = async (e) => {
    e.preventDefault();
    if (!window.confirm(`Permanently burn Token ID #${revokeTokenId} on-chain?`)) return;

    setError('');
    setRevoking(true);
    setRevokeResult(null);

    try {
      const callerAddress = await signer.getAddress();
      const isMgr = await checkManagerRole(signer, callerAddress);
      const userDID = `did:ethr:13371:${callerAddress.toLowerCase()}`;

      if (!isMgr) {
        try {
          await recordAccessAttempt(
            signer,
            parseInt(revokeTokenId) || 0,
            userDID,
            false,
            'Unauthorized Asset Revoke Attempt (Missing MANAGER_ROLE)'
          );
        } catch (logErr) {
          console.warn('Failed to record on-chain access attempt:', logErr);
        }
        throw new Error('Access Denied: Your account does not possess the MANAGER_ROLE on the smart contract registry. An unauthorized attempt has been logged to the audit ledger.');
      }

      // Role check: Managers can only revoke PHYSICAL assets
      const assetData = await getAsset(revokeTokenId);
      if (assetData?.isDigital && user?.role === 'MANAGER') {
        throw new Error('Policy Violation: Managers are only permitted to revoke PHYSICAL defense hardware. Revocation of digital documents is restricted to the asset owner or Administrator.');
      }

      const result = await revokeAsset(signer, parseInt(revokeTokenId));
      setRevokeResult({
        tokenId: revokeTokenId,
        txHash: result.txHash
      });
      setRevokeTokenId('');
    } catch (err) {
      console.error('Revocation error:', err);
      setError(err.message || 'Revocation failed');
    } finally {
      setRevoking(false);
    }
  };

  const panelStyle = { border: '1px solid #e5e7eb', padding: '1.5rem', borderRadius: '12px', background: '#fff' };
  const inputStyle = { width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #d1d5db', boxSizing: 'border-box', marginBottom: '1rem', fontFamily: 'monospace' };
  const labelStyle = { display: 'block', marginBottom: '6px', fontWeight: 'bold', fontSize: '12px', color: '#374151', textTransform: 'uppercase' };

  return (
    <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: '10px', marginBottom: '2rem', borderBottom: '2px solid #e5e7eb', paddingBottom: '10px' }}>
        {[
          { id: 'digital', label: 'Mint Digital Asset (PDF / Cert)' },
          { id: 'physical', label: 'Mint Physical Asset (QR / Serial)' },
          { id: 'access', label: 'Asset Access Permissions' },
          { id: 'lifecycle', label: 'Physical Custody & Revocation' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => { setActiveTab(tab.id); setError(''); }}
            style={{
              padding: '10px 16px',
              border: 'none',
              borderRadius: '8px',
              background: activeTab === tab.id ? '#4f46e5' : '#f3f4f6',
              color: activeTab === tab.id ? '#fff' : '#4b5563',
              fontWeight: 'bold',
              cursor: 'pointer',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {error && (
        <div style={{ marginBottom: '1.5rem', padding: '1rem', background: '#fee2e2', color: '#991b1b', borderRadius: '8px', fontWeight: 'bold', fontSize: '14px' }}>
          Error: {error}
        </div>
      )}

      {/* 1. DIGITAL ASSET MINTING */}
      {activeTab === 'digital' && (
        <div style={panelStyle}>
          <h2 style={{ margin: '0 0 8px', fontSize: '20px', color: '#111827' }}>Digital Asset NFT Creation</h2>
          <p style={{ margin: '0 0 1.5rem', fontSize: '14px', color: '#6b7280' }}>
            Upload off-chain document (PDF, certificate, software license) to anchor its cryptographic SHA-256 hash on-chain.
          </p>

          <form onSubmit={handleDigitalMint}>
            <label style={labelStyle}>1. Select Document to Hash & Store Off-Chain</label>
            <input type="file" onChange={handleFileUpload} style={inputStyle} required />
            {uploading && <p style={{ fontSize: '12px', color: '#4f46e5' }}>Calculating SHA-256 and storing off-chain...</p>}
            {fileHash && (
              <div style={{ padding: '8px 12px', background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: '6px', marginBottom: '1rem', fontSize: '12px', fontFamily: 'monospace' }}>
                <strong>SHA-256 Hash:</strong> {fileHash}<br />
                <strong>Off-Chain URI:</strong> {offchainURI}
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <label style={labelStyle}>Token ID</label>
                <input type="number" value={digitalTokenId} onChange={(e) => setDigitalTokenId(e.target.value)} required style={inputStyle} placeholder="e.g. 301 (avoid 101, 102, 201, 202, 501, 601 — already on-chain)" />
              </div>
              <div>
                <label style={labelStyle}>Document Identifier / Name</label>
                <input type="text" value={digitalSerial} onChange={(e) => setDigitalSerial(e.target.value)} required style={inputStyle} placeholder="e.g. LEX-DOC-301 (must be unique — not LEX-CONFIDENTIAL-AI-SPECS.pdf etc.)" />
              </div>
            </div>

            <label style={labelStyle}>Initial Owner Wallet Address</label>
            <input type="text" value={digitalRecipient} onChange={(e) => setDigitalRecipient(e.target.value)} required style={inputStyle} placeholder="0x..." />

            <button type="submit" disabled={digitalMinting || uploading || !fileHash} style={{ width: '100%', padding: '12px', background: digitalMinting ? '#9ca3af' : '#4f46e5', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}>
              {digitalMinting ? 'Minting Digital NFT on Besu...' : 'Mint Digital Asset NFT'}
            </button>
          </form>

          {digitalMintResult && (
            <div style={{ marginTop: '1.5rem', padding: '1rem', background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '8px' }}>
              <h4 style={{ margin: '0 0 10px 0', color: '#166534' }}>Digital Asset Minted Successfully on-chain!</h4>
              <div style={{ fontSize: '12px', color: '#15803d', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                <strong>Token ID:</strong> #{digitalMintResult.tokenId}<br />
                <strong>Identifier:</strong> {digitalMintResult.serialNumber}<br />
                <strong>Owner DID:</strong> {digitalMintResult.ownerDID}<br />
                <strong>Anchored File Hash:</strong> {digitalMintResult.fileHash}<br />
                <strong>Tx Hash:</strong> {digitalMintResult.txHash}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 2. PHYSICAL ASSET MINTING */}
      {activeTab === 'physical' && (
        <div style={panelStyle}>
          <h2 style={{ margin: '0 0 8px', fontSize: '20px', color: '#111827' }}>Physical Asset NFT Creation</h2>
          <p style={{ margin: '0 0 1.5rem', fontSize: '14px', color: '#6b7280' }}>
            Mint physical asset token bound to hardware serial number and cryptographic verification QR.
          </p>

          <form onSubmit={handlePhysicalMint}>
            <label style={labelStyle}>Token ID</label>
            <input type="number" value={mintTokenId} onChange={(e) => setMintTokenId(e.target.value)} required style={inputStyle} placeholder="e.g. 101" />

            <label style={labelStyle}>Physical Serial / Hardware Tag</label>
            <input type="text" value={mintSerial} onChange={(e) => setMintSerial(e.target.value)} required style={inputStyle} placeholder="e.g. LEX-SERVER-99" />

            <label style={labelStyle}>Owner Wallet Address</label>
            <input type="text" value={mintRecipient} onChange={(e) => setMintRecipient(e.target.value)} required style={inputStyle} placeholder="0x..." />

            <button type="submit" disabled={minting} style={{ width: '100%', padding: '12px', background: minting ? '#9ca3af' : '#4f46e5', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}>
              {minting ? 'Minting Physical NFT...' : 'Mint Physical Asset'}
            </button>
          </form>

          {mintedAsset && (
            <div style={{ marginTop: '1.5rem', padding: '1rem', background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '8px' }}>
              <h4 style={{ margin: '0 0 10px 0', color: '#166534' }}>Physical Asset Minted!</h4>
              <div style={{ fontSize: '12px', color: '#15803d', fontFamily: 'monospace' }}>
                <strong>Serial:</strong> {mintedAsset.serialNumber}<br />
                <strong>Tx:</strong> {mintedAsset.txHash}
              </div>
              <div style={{ marginTop: '1rem', textAlign: 'center' }}>
                <img src={`/api/assets/serial/${mintedAsset.serialNumber}/qr?host=${window.location.host}`} alt="Asset QR" style={{ width: '120px', height: '120px', borderRadius: '8px' }} />
              </div>
            </div>
          )}
        </div>
      )}

      {/* 3. ASSET-LEVEL ACCESS PERMISSIONS */}
      {activeTab === 'access' && (
        <div style={panelStyle}>
          <h2 style={{ margin: '0 0 8px', fontSize: '20px', color: '#111827' }}>Asset-Level Access Control (Granular ACL)</h2>
          <p style={{ margin: '0 0 1.5rem', fontSize: '14px', color: '#6b7280' }}>
            Grant or revoke access permissions on specific digital documents for specific user DIDs on-chain.
          </p>

          <form onSubmit={handleGrantAccess}>
            <label style={labelStyle}>Digital Asset Token ID</label>
            <input type="number" value={accessDocTokenId} onChange={(e) => setAccessDocTokenId(e.target.value)} required style={inputStyle} placeholder="e.g. 201" />

            <label style={labelStyle}>Target User DID</label>
            <input type="text" value={accessTargetDID} onChange={(e) => setAccessTargetDID(e.target.value)} required style={inputStyle} placeholder="did:ethr:13371:0x..." />

            <label style={labelStyle}>Permission Level</label>
            <select value={accessLevel} onChange={(e) => setAccessLevel(Number(e.target.value))} style={inputStyle}>
              <option value={1}>READ (View & Verify Off-chain Document)</option>
              <option value={2}>READ_WRITE (Modify / Update Metadata)</option>
            </select>

            <button type="submit" disabled={granting} style={{ width: '100%', padding: '12px', background: granting ? '#9ca3af' : '#059669', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}>
              {granting ? 'Updating On-Chain Access List...' : 'Grant Access Permission on Chain'}
            </button>
          </form>

          {accessResult && (
            <div style={{ marginTop: '1.5rem', padding: '1rem', background: '#ecfdf5', border: '1px solid #a7f3d0', borderRadius: '8px' }}>
              <h4 style={{ margin: '0 0 10px 0', color: '#047857' }}>Access Permission Granted On-Chain!</h4>
              <div style={{ fontSize: '12px', color: '#047857', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                <strong>Token ID:</strong> #{accessResult.tokenId}<br />
                <strong>Granted To:</strong> {accessResult.targetDID}<br />
                <strong>Level:</strong> {accessResult.level}<br />
                <strong>Tx Hash:</strong> {accessResult.txHash}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 4. LIFECYCLE (TRANSFER & REVOKE) */}
      {activeTab === 'lifecycle' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
          {/* Transfer */}
          <div style={panelStyle}>
            <h3 style={{ margin: '0 0 8px', color: '#111827' }}>Transfer Physical Asset Custody</h3>
            <p style={{ fontSize: '12px', color: '#6b7280', marginBottom: '1rem' }}>
              Transfer custody of physical defense hardware. Digital document ownership transfer is restricted to Administrators.
            </p>
            <form onSubmit={handleTransfer}>
              <label style={labelStyle}>Token ID</label>
              <input type="number" value={transferTokenId} onChange={(e) => setTransferTokenId(e.target.value)} required style={inputStyle} placeholder="e.g. 101" />

              <label style={labelStyle}>New Custodian Wallet Address</label>
              <input type="text" value={transferRecipient} onChange={(e) => setTransferRecipient(e.target.value)} required style={inputStyle} placeholder="0x..." />

              <button type="submit" disabled={transferring} style={{ width: '100%', padding: '10px', background: transferring ? '#9ca3af' : '#ea580c', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}>
                {transferring ? 'Transferring Custody...' : 'Transfer Physical Asset Custody'}
              </button>
            </form>
            {transferResult && (
              <div style={{ marginTop: '1rem', padding: '10px', background: '#fff7ed', borderRadius: '6px', fontSize: '12px', color: '#c2410c' }}>
                Transferred custody of #{transferResult.tokenId} to {transferResult.to}
              </div>
            )}
          </div>

          {/* Revoke */}
          <div style={panelStyle}>
            <h3 style={{ margin: '0 0 8px', color: '#111827' }}>Revoke Physical Asset Assignment</h3>
            <p style={{ fontSize: '12px', color: '#6b7280', marginBottom: '1rem' }}>
              Permanently revoke physical asset assignment. Digital document revocation is restricted to document owners and Administrators.
            </p>
            <form onSubmit={handleRevoke}>
              <label style={labelStyle}>Token ID to Revoke</label>
              <input type="number" value={revokeTokenId} onChange={(e) => setRevokeTokenId(e.target.value)} required style={inputStyle} placeholder="e.g. 101" />

              <button type="submit" disabled={revoking} style={{ width: '100%', padding: '10px', background: revoking ? '#9ca3af' : '#dc2626', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}>
                {revoking ? 'Revoking Assignment...' : 'Revoke Physical Asset'}
              </button>
            </form>
            {revokeResult && (
              <div style={{ marginTop: '1rem', padding: '10px', background: '#fef2f2', borderRadius: '6px', fontSize: '12px', color: '#991b1b' }}>
                Revoked assignment of Token #{revokeResult.tokenId} on-chain.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
