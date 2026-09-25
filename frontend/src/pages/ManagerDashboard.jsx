import { useState, useEffect } from 'react';
import axios from 'axios';
import { ethers } from 'ethers';
import { useAuth } from '../context/AuthContext';
import {
  uploadDocument,
  proposeDocument,
  proposePhysicalAsset,
  getPendingDocuments,
  getPendingPhysicalAssets,
  getPendingDownloadRequests,
  approveDocument,
  approvePhysicalAsset,
  approveDownloadRequest,
  getDownloadDocumentUrl,
  getAuditEvents,
  updateAlertStatus,
  authenticateWithPasskey
} from '../services/api';
import {
  grantAssetAccess,
  revokeAssetAccess,
  transferAsset,
  revokeAsset,
  getAsset,
  checkManagerRole,
  recordAccessAttempt
} from '../services/web3';

export default function ManagerDashboard() {
  const { signer, user } = useAuth();
  const [activeTab, setActiveTab] = useState('pending'); // 'pending' | 'propose_doc' | 'propose_phys' | 'access' | 'transfer'
  const [pendingSubTab, setPendingSubTab] = useState('docs'); // 'docs' | 'physical' | 'downloads'

  // Queue Data
  const [pendingDocs, setPendingDocs] = useState([]);
  const [pendingPhysical, setPendingPhysical] = useState([]);
  const [pendingDownloads, setPendingDownloads] = useState([]);
  const [forwardedIncidents, setForwardedIncidents] = useState([]);
  const [loadingQueue, setLoadingQueue] = useState(false);

  // Factor 3 Approval Modal State
  const [selectedAction, setSelectedAction] = useState(null); // { type: 'doc' | 'physical' | 'download', item: ... }
  const [factor3Code, setFactor3Code] = useState('');
  const [maxViewsLimit, setMaxViewsLimit] = useState('');
  const [rejectionReason, setRejectionReason] = useState('');
  const [isProcessingApproval, setIsProcessingApproval] = useState(false);
  const [approvalResult, setApprovalResult] = useState(null);
  const [passkeyFactor3Verified, setPasskeyFactor3Verified] = useState(false);

  // Digital Propose State
  const [docName, setDocName] = useState('');
  const [digitalSerial, setDigitalSerial] = useState('');
  const [docPurpose, setDocPurpose] = useState('');
  const [docTotpCode, setDocTotpCode] = useState('');
  const [docRecipientAddress, setDocRecipientAddress] = useState('');
  const [docPasskeyVerified, setDocPasskeyVerified] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileHash, setFileHash] = useState('');
  const [offchainURI, setOffchainURI] = useState('');
  const [uploading, setUploading] = useState(false);
  const [proposingDoc, setProposingDoc] = useState(false);
  const [docProposalResult, setDocProposalResult] = useState(null);

  // Physical Propose State
  const [physName, setPhysName] = useState('');
  const [physSerial, setPhysSerial] = useState('');
  const [physType, setPhysType] = useState('EQUIPMENT');
  const [physMac, setPhysMac] = useState('');
  const [physDevAddr, setPhysDevAddr] = useState('');
  const [physLocation, setPhysLocation] = useState('');
  const [physPurpose, setPhysPurpose] = useState('');
  const [physTotpCode, setPhysTotpCode] = useState('');
  const [physRecipientAddress, setPhysRecipientAddress] = useState('');
  const [physPasskeyVerified, setPhysPasskeyVerified] = useState(false);
  const [hasMac, setHasMac] = useState(false);
  const [proposingPhys, setProposingPhys] = useState(false);
  const [physProposalResult, setPhysProposalResult] = useState(null);

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
  const [successMsg, setSuccessMsg] = useState('');

  // Fetch Pending Items & Escalated Incidents
  const fetchPendingQueues = async () => {
    setLoadingQueue(true);
    setError('');
    try {
      const [docs, phys, dls, incidents] = await Promise.all([
        getPendingDocuments().catch(() => []),
        getPendingPhysicalAssets().catch(() => []),
        getPendingDownloadRequests().catch(() => []),
        getAuditEvents({ alert_status: 'FORWARDED_TO_MANAGER', limit: 50 }).catch(() => [])
      ]);
      setPendingDocs(Array.isArray(docs) ? docs : []);
      setPendingPhysical(Array.isArray(phys) ? phys : []);
      setPendingDownloads(Array.isArray(dls) ? dls : []);
      setForwardedIncidents(Array.isArray(incidents) ? incidents : []);
    } catch (err) {
      console.error('Failed to load pending queues:', err);
    } finally {
      setLoadingQueue(false);
    }
  };

  const handleAlertAction = async (eventId, newStatus) => {
    try {
      await updateAlertStatus(eventId, newStatus);
      setSuccessMsg(`Incident updated to ${newStatus}`);
      fetchPendingQueues();
    } catch (err) {
      console.error('Failed to update incident:', err);
      setError(err.response?.data?.detail || 'Failed to update alert');
    }
  };

  const handlePasskeyF2Doc = async () => {
    try {
      setError('');
      await authenticateWithPasskey('factor2', 'document.submit');
      setDocPasskeyVerified(true);
      setSuccessMsg('Passkey Factor 2 verified successfully!');
    } catch (err) {
      console.error('Passkey verification failed:', err);
      setError('Passkey authentication failed or not registered. Use 6-digit TOTP code.');
    }
  };

  const handlePasskeyF2Phys = async () => {
    try {
      setError('');
      await authenticateWithPasskey('factor2', 'document.submit');
      setPhysPasskeyVerified(true);
      setSuccessMsg('Passkey Factor 2 verified successfully!');
    } catch (err) {
      console.error('Passkey verification failed:', err);
      setError('Passkey authentication failed or not registered. Use 6-digit TOTP code.');
    }
  };

  const handlePasskeyF3 = async () => {
    try {
      setError('');
      await authenticateWithPasskey('factor3', 'asset.approve');
      setPasskeyFactor3Verified(true);
      setSuccessMsg('Passkey Factor 3 verified successfully!');
    } catch (err) {
      console.error('Passkey verification failed:', err);
      setError('Passkey authentication failed or not registered. Use 6-digit Factor 3 TOTP code.');
    }
  };

  useEffect(() => {
    if (activeTab === 'pending') {
      fetchPendingQueues();
    }
  }, [activeTab]);

  // Handle Approvals / Rejections (Factor 3 Enforced)
  const handleDecision = async (decision) => {
    if (!selectedAction) return;
    setIsProcessingApproval(true);
    setError('');
    setSuccessMsg('');
    setApprovalResult(null);

    const { type, item } = selectedAction;
    const actionId = item.action_id;

    try {
      const payload = {
        decision,
        totp_code: factor3Code || null,
        rejection_reason: decision === 'REJECT' ? (rejectionReason || 'Rejected by Department Manager') : null,
        ...(maxViewsLimit && { max_views: parseInt(maxViewsLimit) })
      };

      let res;
      if (type === 'doc') {
        res = await approveDocument(actionId, payload);
      } else if (type === 'physical') {
        res = await approvePhysicalAsset(actionId, payload);
      } else if (type === 'download') {
        res = await approveDownloadRequest(actionId, payload);
      }

      setSuccessMsg(`Action ${actionId} successfully marked as ${decision}!`);
      setApprovalResult(res);
      setSelectedAction(null);
      setFactor3Code('');
      setRejectionReason('');
      await fetchPendingQueues();
    } catch (err) {
      console.error('Approval execution error:', err);
      setError(err.response?.data?.detail || err.message || 'Operation failed');
    } finally {
      setIsProcessingApproval(false);
    }
  };

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
      if (!docName) setDocName(file.name.replace(/\.[^/.]+$/, ''));
    } catch (err) {
      console.error('File upload error:', err);
      setError(err.response?.data?.detail || 'File processing failed');
    } finally {
      setUploading(false);
    }
  };

  // Propose Digital Document (Factor 2 Protected)
  const handleProposeDocument = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');
    setProposingDoc(true);
    setDocProposalResult(null);

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

      const payload = {
        name: docName,
        serial_number: digitalSerial,
        file_hash: fileHash,
        offchain_uri: offchainURI,
        purpose: docPurpose || 'Defense Technical Documentation',
        recipient_address: docRecipientAddress.trim() || null,
        totp_code: docTotpCode || null,
      };

      const result = await proposeDocument(payload);
      setSuccessMsg(`Document proposal ${result.action_id} submitted! Pending Factor 3 approval.`);
      setDocProposalResult(result);
      setDocName('');
      setDigitalSerial('');
      setDocPurpose('');
      setDocRecipientAddress('');
      setDocTotpCode('');
      setFileHash('');
      setOffchainURI('');
      setSelectedFile(null);
    } catch (err) {
      console.error('Document proposal error:', err);
      setError(err.response?.data?.detail || err.message || 'Proposal failed');
    } finally {
      setProposingDoc(false);
    }
  };

  // Propose Physical Hardware (Factor 2 Protected)
  const handleProposePhysical = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');
    setProposingPhys(true);
    setPhysProposalResult(null);

    try {
      if (!physName.trim()) throw new Error('Hardware unit name is required.');
      if (!physSerial.trim()) throw new Error('Serial number is required.');

      const payload = {
        name: physName,
        serial_number: physSerial,
        asset_type: physType,
        mac_address: hasMac ? (physMac.trim() || null) : null,
        device_unique_address: !hasMac ? (physDevAddr.trim() || null) : null,
        location: physLocation.trim() || null,
        purpose: physPurpose.trim() || 'Tactical Defense Deployment',
        recipient_address: physRecipientAddress.trim() || null,
        totp_code: physTotpCode || null
      };

      const result = await proposePhysicalAsset(payload);
      setSuccessMsg(`Physical asset proposal ${result.action_id} submitted! Pending Factor 3 approval.`);
      setPhysProposalResult(result);
      setPhysName('');
      setPhysSerial('');
      setPhysMac('');
      setPhysDevAddr('');
      setPhysLocation('');
      setPhysPurpose('');
      setPhysRecipientAddress('');
      setHasMac(false);
      setPhysTotpCode('');
    } catch (err) {
      console.error('Physical asset proposal error:', err);
      setError(err.response?.data?.detail || err.message || 'Proposal failed');
    } finally {
      setProposingPhys(false);
    }
  };

  // Grant Access Control
  const handleGrantAccess = async (e) => {
    e.preventDefault();
    setError('');
    setGranting(true);
    setAccessResult(null);

    try {
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

  // Transfer Asset
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
        throw new Error('Access Denied: Your account does not possess the MANAGER_ROLE on the smart contract registry.');
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

  // Revoke Physical Asset
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
        throw new Error('Access Denied: Your account does not possess the MANAGER_ROLE on the smart contract registry.');
      }

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

  const panelStyle = { border: '1px solid #e5e7eb', padding: '1.5rem', borderRadius: '12px', background: '#fff', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' };
  const inputStyle = { width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #d1d5db', boxSizing: 'border-box', marginBottom: '1rem', fontFamily: 'monospace' };
  const labelStyle = { display: 'block', marginBottom: '6px', fontWeight: 'bold', fontSize: '12px', color: '#374151', textTransform: 'uppercase' };
  const tableHeaderStyle = { padding: '12px 14px', background: '#f8fafc', color: '#475569', fontWeight: 'bold', fontSize: '12px', textAlign: 'left', borderBottom: '1px solid #e2e8f0' };
  const tableCellStyle = { padding: '12px 14px', borderBottom: '1px solid #e2e8f0', fontSize: '13px', color: '#1e293b' };

  return (
    <div style={{ maxWidth: '1150px', margin: '0 auto', width: '100%' }}>
      {/* Top Header */}
      <div style={{ marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 'bold', color: '#0f172a' }}>
            Manager Command & Approval Portal
          </h1>
          <p style={{ margin: '4px 0 0', color: '#64748b', fontSize: '14px' }}>
            Departmental Asset Approval, Defense Hardware Registration & Smart Contract Custody Control
          </p>
        </div>
        <div style={{ background: '#e0e7ff', color: '#3730a3', padding: '6px 14px', borderRadius: '20px', fontWeight: 'bold', fontSize: '12px' }}>
          Department: {user?.department || 'Operations'}
        </div>
      </div>

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '1.5rem', borderBottom: '2px solid #e5e7eb', paddingBottom: '10px' }}>
        {[
          { id: 'pending', label: `Pending Approvals (${pendingDocs.length + pendingPhysical.length + pendingDownloads.length})` },
          ...(user?.role !== 'ADMIN' ? [{ id: 'propose_doc', label: 'Propose Digital Document' }] : []),
          ...(user?.role !== 'ADMIN' ? [{ id: 'propose_phys', label: 'Propose Physical Hardware' }] : []),
          { id: 'access', label: 'Granular ACL Permissions' },
          { id: 'transfer', label: 'Transfer & Revoke' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => { setActiveTab(tab.id); setError(''); setSuccessMsg(''); }}
            style={{
              padding: '10px 18px',
              border: 'none',
              borderRadius: '8px',
              background: activeTab === tab.id ? '#1e293b' : '#f1f5f9',
              color: activeTab === tab.id ? '#ffffff' : '#475569',
              fontWeight: '600',
              fontSize: '13px',
              cursor: 'pointer',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Messages */}
      {successMsg && (
        <div style={{ marginBottom: '1.5rem', padding: '1rem', background: '#ecfdf5', color: '#065f46', border: '1px solid #10b981', borderRadius: '8px', fontWeight: 'bold', fontSize: '14px' }}>
          ✓ {successMsg}
        </div>
      )}

      {error && (
        <div style={{ marginBottom: '1.5rem', padding: '1rem', background: '#fef2f2', color: '#991b1b', border: '1px solid #ef4444', borderRadius: '8px', fontWeight: 'bold', fontSize: '14px' }}>
          ⚠ {error}
        </div>
      )}

      {/* TAB 1: PENDING APPROVAL QUEUE */}
      {activeTab === 'pending' && (
        <div style={panelStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div>
              <h2 style={{ margin: 0, fontSize: '18px', color: '#0f172a' }}>Departmental Review Queue</h2>
              <p style={{ margin: '4px 0 0', fontSize: '13px', color: '#64748b' }}>
                Review and approve document creation proposals, physical defense hardware proposals, and secure download requests. Approvals require Factor 3 MFA.
              </p>
            </div>
            <button
              onClick={fetchPendingQueues}
              disabled={loadingQueue}
              style={{ padding: '8px 14px', background: '#f1f5f9', border: '1px solid #cbd5e1', borderRadius: '6px', cursor: 'pointer', fontSize: '12px', fontWeight: 'bold' }}
            >
              {loadingQueue ? 'Refreshing...' : '↻ Refresh Queue'}
            </button>
          </div>

          {/* Sub-Queue Tabs */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '1.5rem', background: '#f8fafc', padding: '4px', borderRadius: '8px', width: 'fit-content' }}>
            <button
              onClick={() => setPendingSubTab('docs')}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                border: 'none',
                background: pendingSubTab === 'docs' ? '#ffffff' : 'transparent',
                color: pendingSubTab === 'docs' ? '#0f172a' : '#64748b',
                fontWeight: '600',
                fontSize: '12px',
                cursor: 'pointer',
                boxShadow: pendingSubTab === 'docs' ? '0 1px 2px rgba(0,0,0,0.05)' : 'none'
              }}
            >
              Digital Documents ({pendingDocs.length})
            </button>
            <button
              onClick={() => setPendingSubTab('physical')}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                border: 'none',
                background: pendingSubTab === 'physical' ? '#ffffff' : 'transparent',
                color: pendingSubTab === 'physical' ? '#0f172a' : '#64748b',
                fontWeight: '600',
                fontSize: '12px',
                cursor: 'pointer',
                boxShadow: pendingSubTab === 'physical' ? '0 1px 2px rgba(0,0,0,0.05)' : 'none'
              }}
            >
              Physical Hardware ({pendingPhysical.length})
            </button>
            <button
              onClick={() => setPendingSubTab('downloads')}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                border: 'none',
                background: pendingSubTab === 'downloads' ? '#ffffff' : 'transparent',
                color: pendingSubTab === 'downloads' ? '#0f172a' : '#64748b',
                fontWeight: '600',
                fontSize: '12px',
                cursor: 'pointer',
                boxShadow: pendingSubTab === 'downloads' ? '0 1px 2px rgba(0,0,0,0.05)' : 'none'
              }}
            >
              Download Requests ({pendingDownloads.length})
            </button>
            <button
              onClick={() => setPendingSubTab('incidents')}
              style={{
                padding: '6px 14px',
                borderRadius: '6px',
                border: 'none',
                background: pendingSubTab === 'incidents' ? '#ffffff' : 'transparent',
                color: pendingSubTab === 'incidents' ? '#0f172a' : '#64748b',
                fontWeight: '600',
                fontSize: '12px',
                cursor: 'pointer',
                boxShadow: pendingSubTab === 'incidents' ? '0 1px 2px rgba(0,0,0,0.05)' : 'none'
              }}
            >
              Escalated Incidents ({forwardedIncidents.length})
            </button>
          </div>

          {/* Sub-tab 1: Pending Documents */}
          {pendingSubTab === 'docs' && (
            <div>
              {pendingDocs.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '3rem 1rem', color: '#94a3b8' }}>
                  No pending digital document proposals awaiting approval in your department.
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr>
                        <th style={tableHeaderStyle}>Action ID</th>
                        <th style={tableHeaderStyle}>Document Serial</th>
                        <th style={tableHeaderStyle}>Proposed By</th>
                        <th style={tableHeaderStyle}>Purpose</th>
                        <th style={tableHeaderStyle}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pendingDocs.map((item) => (
                        <tr key={item.action_id}>
                          <td style={{ ...tableCellStyle, fontFamily: 'monospace', fontWeight: 'bold' }}>{item.action_id}</td>
                          <td style={tableCellStyle}>{item.asset_serial || '—'}</td>
                          <td style={{ ...tableCellStyle, fontFamily: 'monospace', fontSize: '11px' }}>{item.actor_did ? `${item.actor_did.slice(0, 16)}...` : '—'}</td>
                          <td style={tableCellStyle}>{item.purpose || 'Document Registration'}</td>
                          <td style={tableCellStyle}>
                            <button
                              onClick={() => { setSelectedAction({ type: 'doc', item }); setFactor3Code(''); }}
                              style={{ padding: '6px 12px', background: '#059669', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
                            >
                              Review & Approve →
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Sub-tab 2: Pending Physical Assets */}
          {pendingSubTab === 'physical' && (
            <div>
              {pendingPhysical.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '3rem 1rem', color: '#94a3b8' }}>
                  No pending physical hardware proposals awaiting approval.
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr>
                        <th style={tableHeaderStyle}>Action ID</th>
                        <th style={tableHeaderStyle}>Hardware Serial</th>
                        <th style={tableHeaderStyle}>Proposer DID</th>
                        <th style={tableHeaderStyle}>Department</th>
                        <th style={tableHeaderStyle}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pendingPhysical.map((item) => (
                        <tr key={item.action_id}>
                          <td style={{ ...tableCellStyle, fontFamily: 'monospace', fontWeight: 'bold' }}>{item.action_id}</td>
                          <td style={tableCellStyle}>{item.asset_serial || '—'}</td>
                          <td style={{ ...tableCellStyle, fontFamily: 'monospace', fontSize: '11px' }}>{item.actor_did ? `${item.actor_did.slice(0, 16)}...` : '—'}</td>
                          <td style={tableCellStyle}>{item.department || 'Avionics'}</td>
                          <td style={tableCellStyle}>
                            <button
                              onClick={() => { setSelectedAction({ type: 'physical', item }); setFactor3Code(''); }}
                              style={{ padding: '6px 12px', background: '#059669', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
                            >
                              Review & Approve →
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Sub-tab 3: Pending Download Requests */}
          {pendingSubTab === 'downloads' && (
            <div>
              {pendingDownloads.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '3rem 1rem', color: '#94a3b8' }}>
                  No pending document download requests.
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr>
                        <th style={tableHeaderStyle}>Action ID</th>
                        <th style={tableHeaderStyle}>Asset Serial</th>
                        <th style={tableHeaderStyle}>Requested By</th>
                        <th style={tableHeaderStyle}>Purpose / Justification</th>
                        <th style={tableHeaderStyle}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pendingDownloads.map((item) => (
                        <tr key={item.action_id}>
                          <td style={{ ...tableCellStyle, fontFamily: 'monospace', fontWeight: 'bold' }}>{item.action_id}</td>
                          <td style={tableCellStyle}>{item.asset_serial || '—'}</td>
                          <td style={{ ...tableCellStyle, fontFamily: 'monospace', fontSize: '11px' }}>{item.actor_did ? `${item.actor_did.slice(0, 16)}...` : '—'}</td>
                          <td style={tableCellStyle}>{item.purpose || 'Operational Assessment'}</td>
                          <td style={tableCellStyle}>
                            <button
                              onClick={() => { setSelectedAction({ type: 'download', item }); setFactor3Code(''); }}
                              style={{ padding: '6px 12px', background: '#2563eb', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold', cursor: 'pointer' }}
                            >
                              Approve Download →
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Sub-tab 4: Escalated Incidents */}
          {pendingSubTab === 'incidents' && (
            <div>
              {forwardedIncidents.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '3rem 1rem', color: '#94a3b8' }}>
                  No escalated security incidents awaiting management review.
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr>
                        <th style={tableHeaderStyle}>Event ID</th>
                        <th style={tableHeaderStyle}>Event</th>
                        <th style={tableHeaderStyle}>Actor</th>
                        <th style={tableHeaderStyle}>Risk</th>
                        <th style={tableHeaderStyle}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {forwardedIncidents.map((e) => (
                        <tr key={e.id}>
                          <td style={{ ...tableCellStyle, fontFamily: 'monospace', fontSize: '11px' }}>{e.id.slice(0, 8)}...</td>
                          <td style={tableCellStyle}>{e.event_type}</td>
                          <td style={{ ...tableCellStyle, fontFamily: 'monospace', fontSize: '11px' }}>{e.actor_did ? `${e.actor_did.slice(0, 16)}...` : '—'}</td>
                          <td style={{...tableCellStyle, fontWeight: 'bold', color: '#dc2626'}}>{e.risk_label}</td>
                          <td style={tableCellStyle}>
                            <button onClick={() => handleAlertAction(e.id, 'ESCALATED_TO_ADMIN')} style={{ padding: '4px 8px', marginRight: '4px', background: '#dc2626', color: 'white', borderRadius: '4px', border: 'none', cursor: 'pointer', fontSize: '11px' }}>Escalate to Admin</button>
                            <button onClick={() => handleAlertAction(e.id, 'DISMISSED')} style={{ padding: '4px 8px', background: '#e2e8f0', color: 'black', borderRadius: '4px', border: 'none', cursor: 'pointer', fontSize: '11px' }}>Dismiss</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* FACTOR 3 APPROVAL MODAL */}
      {selectedAction && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(15, 23, 42, 0.65)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ background: '#ffffff', borderRadius: '12px', width: '100%', maxWidth: '520px', padding: '2rem', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.2rem', borderBottom: '1px solid #e2e8f0', paddingBottom: '12px' }}>
              <h3 style={{ margin: 0, fontSize: '18px', color: '#0f172a' }}>
                Review Action: {selectedAction.item.action_id}
              </h3>
              <button
                onClick={() => setSelectedAction(null)}
                style={{ background: 'transparent', border: 'none', fontSize: '18px', cursor: 'pointer', color: '#64748b' }}
              >
                ✕
              </button>
            </div>

            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '12px', marginBottom: '1.5rem', fontSize: '13px' }}>
              <div style={{ marginBottom: '6px' }}><strong>Asset Serial:</strong> {selectedAction.item.asset_serial || '—'}</div>
              <div style={{ marginBottom: '6px' }}><strong>Proposed By:</strong> <span style={{ fontFamily: 'monospace', fontSize: '11px' }}>{selectedAction.item.actor_did}</span></div>
              <div style={{ marginBottom: '6px' }}><strong>Purpose:</strong> {selectedAction.item.purpose || '—'}</div>
              {selectedAction.item.file_hash && (
                <div style={{ wordBreak: 'break-all', fontSize: '11px', fontFamily: 'monospace' }}>
                  <strong>SHA-256:</strong> {selectedAction.item.file_hash}
                </div>
              )}
            </div>

            <div style={{ marginBottom: '1.2rem' }}>
              <label style={labelStyle}>
                Factor 3 Multi-Factor Authentication Code (TOTP 3 / Passkey 3) *
              </label>
              <div style={{ display: 'flex', gap: '8px' }}>
                <input
                  type="text"
                  value={factor3Code}
                  onChange={(e) => setFactor3Code(e.target.value)}
                  placeholder="6-digit Factor 3 code"
                  style={{ ...inputStyle, marginBottom: 0, fontSize: '16px', letterSpacing: '2px', textAlign: 'center', flex: 1 }}
                  maxLength={6}
                />
                <button
                  type="button"
                  onClick={handlePasskeyF3}
                  style={{ padding: '0 16px', background: passkeyFactor3Verified ? '#10b981' : '#f1f5f9', color: passkeyFactor3Verified ? '#fff' : '#1e293b', border: '1px solid #cbd5e1', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}
                >
                  {passkeyFactor3Verified ? '✓ Passkey Verified' : '🔑 Use Passkey'}
                </button>
              </div>
              <p style={{ margin: '4px 0 0', fontSize: '11px', color: '#64748b' }}>
                Manager / Admin Factor 3 authentication is cryptographically enforced for all on-chain mints and download approvals.
              </p>
            </div>

            {selectedAction.item.action_type === 'SHARE' && (
              <div style={{ marginBottom: '1.2rem' }}>
                <label style={labelStyle}>Max Allowed Views (Optional Quota)</label>
                <input
                  type="number"
                  value={maxViewsLimit}
                  onChange={(e) => setMaxViewsLimit(e.target.value)}
                  placeholder="e.g. 5 (leave blank for unlimited)"
                  style={inputStyle}
                  min={1}
                />
              </div>
            )}

            {selectedAction.item.action_type === 'MODIFICATION' && (
              <div style={{ padding: '8px', background: '#fffbeb', border: '1px solid #fde68a', borderRadius: '6px', marginBottom: '1.2rem', fontSize: '12px', color: '#92400e' }}>
                <strong>Note:</strong> This is a MODIFICATION proposal. Approving this will generate the on-chain calldata to overwrite the asset's URI and SHA-256 hash.
              </div>
            )}

            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                onClick={() => handleDecision('APPROVE')}
                disabled={isProcessingApproval || (!factor3Code && !passkeyFactor3Verified)}
                style={{ flex: 1, padding: '12px', background: isProcessingApproval || (!factor3Code && !passkeyFactor3Verified) ? '#94a3b8' : '#059669', color: '#ffffff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}
              >
                {isProcessingApproval ? 'Verifying MFA...' : '✓ Approve Action'}
              </button>
              <button
                onClick={() => handleDecision('REJECT')}
                disabled={isProcessingApproval}
                style={{ padding: '12px 18px', background: '#fee2e2', color: '#991b1b', border: '1px solid #f87171', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}
              >
                Reject
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: PROPOSE DIGITAL DOCUMENT */}
      {activeTab === 'propose_doc' && (
        <div style={panelStyle}>
          <h2 style={{ margin: '0 0 8px', fontSize: '20px', color: '#111827' }}>Propose Classified Digital Document</h2>
          <p style={{ margin: '0 0 1.5rem', fontSize: '14px', color: '#6b7280' }}>
            Upload off-chain document (PDF, specifications, security protocol) to anchor its cryptographic SHA-256 hash on-chain.
          </p>

          <form onSubmit={handleProposeDocument}>
            <label style={labelStyle}>1. Select Document to Hash & Store Off-Chain *</label>
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
                <label style={labelStyle}>Document Name / Title *</label>
                <input
                  type="text"
                  value={docName}
                  onChange={(e) => setDocName(e.target.value)}
                  required
                  style={inputStyle}
                  placeholder="e.g. Avionics Guidance Firmware Specs"
                />
              </div>
              <div>
                <label style={labelStyle}>Document Serial Identifier *</label>
                <input
                  type="text"
                  value={digitalSerial}
                  onChange={(e) => setDigitalSerial(e.target.value)}
                  required
                  style={inputStyle}
                  placeholder="e.g. BEL-DOC-AVIONICS-2026-001"
                />
              </div>
            </div>

            <label style={labelStyle}>Forward to Recipient Address *</label>
            <input
              type="text"
              value={docRecipientAddress}
              onChange={(e) => setDocRecipientAddress(e.target.value)}
              required
              style={inputStyle}
              placeholder="e.g. 0x123... or DID"
            />

            <label style={labelStyle}>Purpose & Department Classification</label>
            <input
              type="text"
              value={docPurpose}
              onChange={(e) => setDocPurpose(e.target.value)}
              style={inputStyle}
              placeholder="e.g. Strategic Radar Upgrade Documentation"
            />

            <label style={labelStyle}>Factor 2 Submission MFA (TOTP / Passkey) *</label>
            <div style={{ display: 'flex', gap: '8px', marginBottom: '1rem' }}>
              <input
                type="text"
                value={docTotpCode}
                onChange={(e) => setDocTotpCode(e.target.value)}
                style={{ ...inputStyle, marginBottom: 0, flex: 1 }}
                placeholder="Enter 6-digit Factor 2 code"
                maxLength={6}
              />
              <button
                type="button"
                onClick={handlePasskeyF2Doc}
                style={{ padding: '0 16px', background: docPasskeyVerified ? '#10b981' : '#f1f5f9', color: docPasskeyVerified ? '#fff' : '#1e293b', border: '1px solid #cbd5e1', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}
              >
                {docPasskeyVerified ? '✓ Passkey Verified' : '🔑 Use Passkey'}
              </button>
            </div>

            <button
              type="submit"
              disabled={proposingDoc || uploading || !fileHash}
              style={{ width: '100%', padding: '12px', background: proposingDoc ? '#9ca3af' : '#1e293b', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}
            >
              {proposingDoc ? 'Submitting Document Proposal...' : 'Submit Document Proposal'}
            </button>
          </form>

          {docProposalResult && (
            <div style={{ marginTop: '1.5rem', padding: '1rem', background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '8px' }}>
              <h4 style={{ margin: '0 0 10px 0', color: '#166534' }}>Document Proposal Created Successfully!</h4>
              <div style={{ fontSize: '12px', color: '#15803d', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                <strong>Action ID:</strong> {docProposalResult.action_id}<br />
                <strong>Serial:</strong> {docProposalResult.asset_serial}<br />
                <strong>Status:</strong> {docProposalResult.status} (Pending Factor 3 Manager Approval)
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: PROPOSE PHYSICAL HARDWARE */}
      {activeTab === 'propose_phys' && (
        <div style={panelStyle}>
          <h2 style={{ margin: '0 0 8px', fontSize: '20px', color: '#111827' }}>Propose Defense Physical Hardware Asset</h2>
          <p style={{ margin: '0 0 1.5rem', fontSize: '14px', color: '#6b7280' }}>
            Register tactical defense equipment with globally unique serial, MAC address, and device hardware identifiers.
          </p>

          <form onSubmit={handleProposePhysical}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <label style={labelStyle}>Hardware Name / Unit Title *</label>
                <input
                  type="text"
                  value={physName}
                  onChange={(e) => setPhysName(e.target.value)}
                  required
                  style={inputStyle}
                  placeholder="e.g. Radar Signal Processor Mark-IV"
                />
              </div>
              <div>
                <label style={labelStyle}>Physical Serial Number *</label>
                <input
                  type="text"
                  value={physSerial}
                  onChange={(e) => setPhysSerial(e.target.value)}
                  required
                  style={inputStyle}
                  placeholder="e.g. BEL-HW-RADAR-901"
                />
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <label style={labelStyle}>Does this device have a MAC Address? *</label>
                <select
                  value={hasMac}
                  onChange={(e) => setHasMac(e.target.value === 'true')}
                  style={inputStyle}
                >
                  <option value={false}>No</option>
                  <option value={true}>Yes</option>
                </select>
              </div>
              {hasMac ? (
                <div>
                  <label style={labelStyle}>MAC Address (Hardware Tag) *</label>
                  <input
                    type="text"
                    value={physMac}
                    onChange={(e) => setPhysMac(e.target.value)}
                    required
                    style={inputStyle}
                    placeholder="e.g. 00:1A:2B:3C:4D:5E"
                  />
                </div>
              ) : (
                <div>
                  <label style={labelStyle}>Device Unique Hardware Address *</label>
                  <input
                    type="text"
                    value={physDevAddr}
                    onChange={(e) => setPhysDevAddr(e.target.value)}
                    required
                    style={inputStyle}
                    placeholder="e.g. DEV-SECURE-CHIP-778"
                  />
                </div>
              )}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <label style={labelStyle}>Forward to Recipient Address *</label>
                <input
                  type="text"
                  value={physRecipientAddress}
                  onChange={(e) => setPhysRecipientAddress(e.target.value)}
                  required
                  style={inputStyle}
                  placeholder="e.g. 0x123... or DID"
                />
              </div>
              <div>
                <label style={labelStyle}>Deployment Location / Bay</label>
                <input
                  type="text"
                  value={physLocation}
                  onChange={(e) => setPhysLocation(e.target.value)}
                  style={inputStyle}
                  placeholder="e.g. Bay-4 Avionics Testing Hangar"
                />
              </div>
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <label style={labelStyle}>Asset Classification Type</label>
              <select
                value={physType}
                onChange={(e) => setPhysType(e.target.value)}
                style={inputStyle}
              >
                <option value="EQUIPMENT">EQUIPMENT</option>
                <option value="WEAPON_SYSTEM">WEAPON SYSTEM</option>
                <option value="COMMUNICATION">COMMUNICATION</option>
                <option value="VEHICLE">TACTICAL VEHICLE</option>
              </select>
            </div>

            <label style={labelStyle}>Factor 2 Submission MFA (TOTP / Passkey) *</label>
            <div style={{ display: 'flex', gap: '8px', marginBottom: '1rem' }}>
              <input
                type="text"
                value={physTotpCode}
                onChange={(e) => setPhysTotpCode(e.target.value)}
                style={{ ...inputStyle, marginBottom: 0, flex: 1 }}
                placeholder="Enter 6-digit Factor 2 code"
                maxLength={6}
              />
              <button
                type="button"
                onClick={handlePasskeyF2Phys}
                style={{ padding: '0 16px', background: physPasskeyVerified ? '#10b981' : '#f1f5f9', color: physPasskeyVerified ? '#fff' : '#1e293b', border: '1px solid #cbd5e1', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}
              >
                {physPasskeyVerified ? '✓ Passkey Verified' : '🔑 Use Passkey'}
              </button>
            </div>

            <button
              type="submit"
              disabled={proposingPhys}
              style={{ width: '100%', padding: '12px', background: proposingPhys ? '#9ca3af' : '#1e293b', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}
            >
              {proposingPhys ? 'Submitting Hardware Proposal...' : 'Submit Physical Asset Proposal'}
            </button>
          </form>

          {physProposalResult && (
            <div style={{ marginTop: '1.5rem', padding: '1rem', background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '8px' }}>
              <h4 style={{ margin: '0 0 10px 0', color: '#166534' }}>Physical Hardware Proposal Created!</h4>
              <div style={{ fontSize: '12px', color: '#15803d', fontFamily: 'monospace' }}>
                <strong>Action ID:</strong> {physProposalResult.action_id}<br />
                <strong>Serial:</strong> {physProposalResult.asset_serial}<br />
                <strong>Status:</strong> {physProposalResult.status} (Pending Factor 3 Manager Approval)
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: ASSET-LEVEL ACCESS PERMISSIONS */}
      {activeTab === 'access' && (
        <div style={panelStyle}>
          <h2 style={{ margin: '0 0 8px', fontSize: '20px', color: '#111827' }}>Asset-Level Access Control (Granular ACL)</h2>
          <p style={{ margin: '0 0 1.5rem', fontSize: '14px', color: '#6b7280' }}>
            Grant or revoke access permissions on specific digital documents for specific user DIDs on-chain.
          </p>

          <form onSubmit={handleGrantAccess}>
            <label style={labelStyle}>Digital Asset Token ID *</label>
            <input type="number" value={accessDocTokenId} onChange={(e) => setAccessDocTokenId(e.target.value)} required style={inputStyle} placeholder="e.g. 201" />

            <label style={labelStyle}>Target User DID / Wallet Address *</label>
            <input type="text" value={accessTargetDID} onChange={(e) => setAccessTargetDID(e.target.value)} required style={inputStyle} placeholder="did:ethr:13371:0x... or 0x..." />

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

      {/* TAB 5: ASSET TRANSFER & REVOKE */}
      {activeTab === 'transfer' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
          {/* Transfer */}
          <div style={panelStyle}>
            <h3 style={{ margin: '0 0 8px', color: '#111827' }}>Transfer Asset</h3>
            <p style={{ fontSize: '12px', color: '#6b7280', marginBottom: '1rem' }}>
              Transfer custody of any active physical defense hardware to another authorized operator within your department.
            </p>
            <form onSubmit={handleTransfer}>
              <label style={labelStyle}>Token ID</label>
              <input type="number" value={transferTokenId} onChange={(e) => setTransferTokenId(e.target.value)} required style={inputStyle} placeholder="e.g. 101" />

              <label style={labelStyle}>New Owner Wallet Address</label>
              <input type="text" value={transferRecipient} onChange={(e) => setTransferRecipient(e.target.value)} required style={inputStyle} placeholder="0x..." />

              <button type="submit" disabled={transferring} style={{ width: '100%', padding: '10px', background: transferring ? '#9ca3af' : '#ea580c', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer' }}>
                {transferring ? 'Transferring Asset...' : 'Transfer Physical Asset'}
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
            <h3 style={{ margin: '0 0 8px', color: '#111827' }}>Revoke Physical Asset</h3>
            <p style={{ fontSize: '12px', color: '#6b7280', marginBottom: '1rem' }}>
              Permanently decommission/burn a physical asset token from the active registry.
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
