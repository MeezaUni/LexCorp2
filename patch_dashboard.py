import re

with open("frontend/src/pages/UserDashboard.jsx", "r", encoding="utf-8") as f:
    code = f.read()

# Add proposeDocumentShare import
if "proposeDocumentShare" not in code:
    code = code.replace("proposePhysicalAsset,", "proposePhysicalAsset,\n  proposeDocumentShare,\n  prepareMintDigital,\n  prepareMintPhysical,")

# 1. Update the document proposal method
doc_propose_regex = r"const handleDocumentPropose = async \(e\) => \{.*?\}(?=\n\n  // Handle Proposing)"
doc_propose_new = """const handleDocumentPropose = async (e, usePasskey = false) => {
    if (e) e.preventDefault();
    setError(null);
    setProposing(true);
    setProposalResult(null);

    try {
      if (!fileHash || !offchainURI) throw new Error('Please select and upload a document first.');
      if (!docName.trim()) throw new Error('Please enter a document title.');
      if (!digitalSerial.trim()) throw new Error('Please enter a document serial number.');
      if (!docRecipientAddress.trim()) throw new Error('Recipient Address is mandatory.');

      let currentTotp = docTotpCode;

      // Attempt Passkey if requested
      if (usePasskey) {
        try {
          const factor = (user?.role === 'ADMIN' || user?.role === 'MANAGER') ? 'factor3' : 'factor2';
          await authenticateWithPasskey(factor);
          currentTotp = ''; // Clear TOTP requirement if passkey succeeds
        } catch (pkErr) {
          throw new Error('Passkey verification failed. Please use TOTP fallback. ' + pkErr.message);
        }
      } else {
        if ((!currentTotp || currentTotp.trim() === '') && (user?.role === 'USER' || user?.role === 'AUDITOR')) {
            throw new Error('TOTP code is required if passkey is not used.');
        }
      }

      if (user?.role === 'ADMIN' || user?.role === 'MANAGER') {
         // Direct Minting (Factor 3)
         if (!usePasskey && (!currentTotp || currentTotp.trim() === '')) {
             throw new Error('Factor 3 TOTP code is required for direct minting if passkey is not used.');
         }

         const tokenId = Math.floor(Math.random() * 1000000) + 1000;

         const preparePayload = {
            to_address: docRecipientAddress,
            token_id: tokenId,
            serial_number: digitalSerial,
            owner_did: `did:ethr:13371:${docRecipientAddress.toLowerCase()}`,
            file_hash: fileHash,
            offchain_uri: offchainURI
         };

         const pre = await prepareMintDigital(preparePayload);

         // Send Tx
         const tx = await signer.sendTransaction({
             to: pre.calldata.to,
             data: pre.calldata.data,
             gasLimit: pre.calldata.gas,
         });
         await tx.wait();

         setActionSuccessMsg(`Document mint transaction ${tx.hash.slice(0,10)}... executed on-chain successfully!`);
      } else {
         // Proposal Creation (Factor 2)
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

      // Refresh immediately
      setTimeout(() => fetchDashboardData(), 1500);
    } catch (err) {
      console.error('Document action error:', err);
      setError(err.response?.data?.detail || err.message || 'Document operation failed');
    } finally {
      setProposing(false);
    }
  };"""
code = re.sub(doc_propose_regex, doc_propose_new, code, flags=re.DOTALL)


# 2. Update the physical proposal method
phys_propose_regex = r"const handlePhysicalPropose = async \(e\) => \{.*?\}(?=\n\n  // Handle Granting)"
phys_propose_new = """const handlePhysicalPropose = async (e, usePasskey = false) => {
    if (e) e.preventDefault();
    setError(null);
    setProposingPhys(true);
    setPhysProposalResult(null);

    try {
      if (!physName.trim()) throw new Error('Please enter a hardware name.');
      if (!physSerial.trim()) throw new Error('Please enter a hardware serial number.');
      if (hasMac && !physMac.trim()) throw new Error('Please enter the MAC Address.');
      if (!hasMac && !physDevAddr.trim()) throw new Error('Please enter the Unique Hardware Address.');
      if (!physRecipientAddress.trim()) throw new Error('Recipient Address is mandatory.');

      let currentTotp = physTotpCode;

      // Attempt Passkey
      if (usePasskey) {
        try {
          const factor = (user?.role === 'ADMIN' || user?.role === 'MANAGER') ? 'factor3' : 'factor2';
          await authenticateWithPasskey(factor);
          currentTotp = '';
        } catch (pkErr) {
          throw new Error('Passkey verification failed. Please use TOTP fallback. ' + pkErr.message);
        }
      } else {
        if (!currentTotp || currentTotp.trim() === '') {
            throw new Error('TOTP code is required if passkey is not used.');
        }
      }

      if (user?.role === 'ADMIN' || user?.role === 'MANAGER') {
         // Direct Minting (Factor 3)
         const tokenId = Math.floor(Math.random() * 1000000) + 1000;

         const preparePayload = {
            to_address: physRecipientAddress,
            token_id: tokenId,
            serial_number: physSerial,
            owner_did: `did:ethr:13371:${physRecipientAddress.toLowerCase()}`
         };

         const pre = await prepareMintPhysical(preparePayload);

         const tx = await signer.sendTransaction({
             to: pre.calldata.to,
             data: pre.calldata.data,
             gasLimit: pre.calldata.gas,
         });
         await tx.wait();
         setActionSuccessMsg(`Physical Hardware mint transaction ${tx.hash.slice(0,10)}... executed on-chain successfully!`);
      } else {
         const payload = {
           name: physName,
           serial_number: physSerial,
           asset_type: physType,
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

      setTimeout(() => fetchDashboardData(), 1500);
    } catch (err) {
      console.error('Physical proposal error:', err);
      setError(err.response?.data?.detail || err.message || 'Physical hardware operation failed');
    } finally {
      setProposingPhys(false);
    }
  };"""
code = re.sub(phys_propose_regex, phys_propose_new, code, flags=re.DOTALL)


# 3. Update the share access method
grant_access_regex = r"const handleGrantAccess = async \(e\) => \{.*?\}(?=\n\n  // Handle Revoking)"
grant_access_new = """const [shareTotpCode, setShareTotpCode] = useState('');
  const [sharePurpose, setSharePurpose] = useState('');

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
          await authenticateWithPasskey('factor2');
          currentTotp = '';
        } catch (pkErr) {
          throw new Error('Passkey verification failed. Please use TOTP fallback. ' + pkErr.message);
        }
      } else if (!currentTotp || currentTotp.trim() === '') {
        throw new Error('TOTP code is required if passkey is not used.');
      }

      const payload = {
        asset_serial: assetObj.serial_number,
        target_did: targetDID,
        access_level: parseInt(shareLevel),
        purpose: sharePurpose || 'Share access permission',
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
  };"""
code = re.sub(grant_access_regex, grant_access_new, code, flags=re.DOTALL)

with open("frontend/src/pages/UserDashboard.jsx", "w", encoding="utf-8") as f:
    f.write(code)

print("Patch applied.")
