import { useState, useEffect } from 'react';
import { getAllAssets, deleteAsset, getAssetCertificateUrl } from '../services/api';
import deployment from '../../../contracts/deployments/localhost.json';
import { useAuth } from '../context/AuthContext';
import { revokeAsset } from '../services/web3';

export default function AssetRegistry() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedDID, setSelectedDID] = useState(null);

  const { user, signer } = useAuth();
  const isAdmin = user && user.role === 'ADMIN';

  const CONTRACT_ADDRESS = deployment.address;

  const fetchAssets = async () => {
    try {
      setLoading(true);
      const data = await getAllAssets();
      setAssets(data);
    } catch (err) {
      console.error('Failed to load asset registry:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const handleDeleteAsset = async (tokenId, serialNumber) => {
    if (!window.confirm(`Are you sure you want to permanently delete/revoke Token ID #${tokenId} (Serial: ${serialNumber}) from the blockchain? This action is irreversible.`)) {
      return;
    }
    try {
      if (signer) {
        await revokeAsset(signer, tokenId);
      } else {
        await deleteAsset(tokenId);
      }
      alert(`Asset #${tokenId} (${serialNumber}) revoked successfully!`);
      fetchAssets();
    } catch (err) {
      console.error('Failed to revoke asset:', err);
      alert(err.message || 'Failed to revoke asset.');
    }
  };

  return (
    <div style={{ padding: '1.75rem', background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '12px', width: '100%', boxSizing: 'border-box' }}>
      <div style={{ marginBottom: '1.5rem', borderBottom: '1px solid #e2e8f0', paddingBottom: '1rem' }}>
        <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#0f172a', margin: '0 0 4px 0' }}>
          Global Asset Registry
        </h2>
        <p style={{ fontSize: '13px', color: '#64748b', margin: 0 }}>
          Centralized inventory of all tokenized physical assets, decentralized owner DIDs, and on-chain verification links.
        </p>
        <div style={{ marginTop: '8px', fontSize: '12px', color: '#475569', background: '#f8fafc', padding: '6px 10px', borderRadius: '4px', border: '1px solid #e2e8f0', display: 'inline-block' }}>
          <strong>Contract Address:</strong> <code style={{ userSelect: 'all' }}>{CONTRACT_ADDRESS}</code>
          <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
            To view an NFT in MetaMask (Localhost), switch to the NFTs tab, click "Import NFT", and use this address with the Token ID.
          </div>
        </div>
      </div>

      {/* DID VERIFICATION MODAL */}
      {selectedDID && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(15, 23, 42, 0.6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
        }}>
          <div style={{
            background: '#ffffff',
            borderRadius: '12px',
            padding: '2rem',
            maxWidth: '520px',
            width: '90%',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)',
            border: '1px solid #e2e8f0',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '700', color: '#0f172a' }}>
                W3C DID Cryptographic Proof
              </h3>
              <button
                onClick={() => setSelectedDID(null)}
                style={{ background: 'none', border: 'none', fontSize: '18px', cursor: 'pointer', color: '#64748b' }}
              >
                ✕
              </button>
            </div>

            <div style={{ background: '#f8fafc', padding: '1rem', borderRadius: '8px', border: '1px solid #e2e8f0', marginBottom: '1rem' }}>
              <div style={{ fontSize: '11px', fontWeight: '700', color: '#64748b', textTransform: 'uppercase', marginBottom: '4px' }}>
                Subject DID
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#2563eb', wordBreak: 'break-all', fontWeight: '600' }}>
                {selectedDID.owner_did}
              </div>
            </div>

            <div style={{ background: '#f0fdf4', padding: '1rem', borderRadius: '8px', border: '1px solid #bbf7d0', marginBottom: '1.5rem', fontSize: '12px', color: '#166534' }}>
              <div style={{ fontWeight: '700', marginBottom: '4px' }}>Verified Authentic Identity</div>
              <div>This Decentralized Identifier (DID) conforms to the W3C DID-v2 specification, anchored to Ethereum Chain ID 31337.</div>
            </div>

            <button
              onClick={() => setSelectedDID(null)}
              style={{
                width: '100%',
                background: '#0f172a',
                color: '#fff',
                border: 'none',
                padding: '10px',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Done
            </button>
          </div>
        </div>
      )}

      {loading ? (
        <p style={{ color: '#64748b', fontSize: '13px' }}>Loading registry...</p>
      ) : assets.length === 0 ? (
        <p style={{ color: '#64748b', fontSize: '13px', textAlign: 'center', padding: '2rem' }}>No assets found in global registry.</p>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ background: '#f8fafc', borderBottom: '2px solid #e2e8f0', textAlign: 'left' }}>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Type</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Identifier / Serial</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Token ID</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Cryptographic Fingerprint</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Owner Address</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Owner DID</th>
                <th style={{ padding: '10px 12px', color: '#475569', fontWeight: '600' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {assets.map(asset => (
                <tr key={asset.token_id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <td style={{ padding: '10px 12px' }}>
                    <span style={{
                      fontSize: '11px',
                      fontWeight: '700',
                      padding: '3px 8px',
                      borderRadius: '4px',
                      background: asset.is_digital ? '#f3e8ff' : '#eff6ff',
                      color: asset.is_digital ? '#7c3aed' : '#2563eb',
                      display: 'inline-block'
                    }}>
                      {asset.is_digital ? '📄 Digital' : '📦 Physical'}
                    </span>
                  </td>
                  <td style={{ padding: '10px 12px', fontFamily: 'monospace', fontWeight: '700', color: '#0f172a' }}>
                    {asset.serial_number}
                  </td>
                  <td style={{ padding: '10px 12px', color: '#334155', fontWeight: '600' }}>
                    #{asset.token_id}
                  </td>
                  <td style={{ padding: '10px 12px', fontFamily: 'monospace', fontSize: '11px', color: '#64748b' }}>
                    {asset.file_hash ? (
                      <span title={asset.file_hash} style={{ background: '#f8fafc', padding: '2px 6px', borderRadius: '4px', border: '1px solid #e2e8f0', color: '#0f172a' }}>
                        SHA-256: {asset.file_hash.slice(0, 10)}...
                      </span>
                    ) : (
                      <span style={{ color: '#94a3b8' }}>Hardware QR</span>
                    )}
                  </td>
                  <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: '#475569' }}>
                    {asset.owner_address ? `${asset.owner_address.slice(0, 8)}...${asset.owner_address.slice(-6)}` : '—'}
                  </td>
                  <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: '#2563eb' }}>
                    <button
                      onClick={() => setSelectedDID(asset)}
                      style={{
                        background: '#eff6ff',
                        color: '#1d4ed8',
                        border: '1px solid #bfdbfe',
                        padding: '3px 8px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                      title="Verify W3C DID Credentials"
                    >
                      Verify DID
                    </button>
                  </td>
                  <td style={{ padding: '10px 12px', display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                    <button
                      onClick={() => window.open(`/verify/${asset.serial_number}`, '_blank')}
                      style={{
                        background: '#0f172a',
                        color: '#fff',
                        border: 'none',
                        padding: '5px 10px',
                        borderRadius: '6px',
                        fontSize: '12px',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                    >
                      Verify
                    </button>
                    <a
                      href={getAssetCertificateUrl(asset.serial_number)}
                      target="_blank"
                      rel="noreferrer"
                      style={{
                        background: '#0284c7',
                        color: '#fff',
                        border: 'none',
                        padding: '5px 10px',
                        borderRadius: '6px',
                        fontSize: '12px',
                        fontWeight: '600',
                        textDecoration: 'none',
                        display: 'inline-block'
                      }}
                      title="Download Official Defense Asset Certificate (SVG)"
                    >
                      Certificate
                    </a>
                    {isAdmin && (
                      <button
                        onClick={() => handleDeleteAsset(asset.token_id, asset.serial_number)}
                        style={{
                          background: '#fee2e2',
                          color: '#991b1b',
                          border: '1px solid #fecaca',
                          padding: '5px 10px',
                          borderRadius: '6px',
                          fontSize: '12px',
                          fontWeight: '600',
                          cursor: 'pointer'
                        }}
                        title="Revoke / Burn this Asset (Admin only)"
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
