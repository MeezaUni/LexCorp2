import { useState, useEffect } from 'react';
import axios from 'axios';
import { ethers } from 'ethers';
import { useAuth } from '../context/AuthContext';
import { revokeAsset } from '../services/web3';
import { getAssetsByOwner } from '../services/api';

const API_BASE = '/api';

export default function AdminDashboard() {
  const { signer, user } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const [formData, setFormData] = useState({
    wallet_address: '',
    name: '',
    contact_number: '',
    role: 'USER',
  });

  const [generatedWallet, setGeneratedWallet] = useState(null);

  // Deletion Modal state
  const [deleteModalUser, setDeleteModalUser] = useState(null);
  const [userAssets, setUserAssets] = useState([]);
  const [isCheckingAssets, setIsCheckingAssets] = useState(false);
  const [revokingTokenId, setRevokingTokenId] = useState(null);
  const [modalError, setModalError] = useState('');

  // Role hierarchy: determine which roles the current user can create
  const getAvailableRoles = () => {
    const currentRole = user?.role || 'USER';

    // ADMIN can create MANAGER, AUDITOR, and USER (not another ADMIN)
    if (currentRole === 'ADMIN') {
      return [
        { value: 'USER', label: 'USER (Standard Personnel)' },
        { value: 'AUDITOR', label: 'AUDITOR (Read-only Compliance)' },
        { value: 'MANAGER', label: 'MANAGER (Operations & Minting)' },
      ];
    }

    // MANAGER can only create USER
    if (currentRole === 'MANAGER') {
      return [
        { value: 'USER', label: 'USER (Standard Personnel)' },
      ];
    }

    // USER and AUDITOR cannot create users (shouldn't reach this in normal flow)
    return [];
  };

  const availableRoles = getAvailableRoles();

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const res = await axios.get(`${API_BASE}/users`);
      setUsers(res.data);
    } catch (err) {
      console.error('Failed to load users:', err);
      setError('Failed to load user list.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleGenerateWallet = () => {
    const randomWallet = ethers.Wallet.createRandom();
    setGeneratedWallet({
      address: randomWallet.address,
      privateKey: randomWallet.privateKey,
      mnemonic: randomWallet.mnemonic?.phrase || '',
    });
    setFormData(prev => ({
      ...prev,
      wallet_address: randomWallet.address,
    }));
    setSuccess('New cryptographic wallet generated! Private key is shown below.');
  };

  const handleCreateOrUpdate = async (e) => {
    e.preventDefault();
    if (!formData.wallet_address.trim()) {
      setError('Please provide or generate a wallet address.');
      return;
    }

    try {
      setError('');
      setSuccess('');
      await axios.post(`${API_BASE}/users`, formData);
      setSuccess(`User successfully registered / updated as ${formData.role}.`);
      setFormData({ wallet_address: '', name: '', contact_number: '', role: 'USER' });
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to register/update user.');
    }
  };

  const updateRole = async (userId, newRole) => {
    try {
      setError('');
      await axios.patch(`${API_BASE}/users/${userId}/role`, { role: newRole });
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update role.');
    }
  };

  const fundWallet = async (userId) => {
    try {
      setError('');
      setSuccess('Funding wallet with 1000 LEX...');
      const res = await axios.post(`${API_BASE}/users/${userId}/fund`);
      setSuccess(res.data?.message || 'Successfully funded wallet with 1000 LEX.');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to fund wallet.');
    }
  };

  const initiateDelete = async (user) => {
    setDeleteModalUser(user);
    setUserAssets([]);
    setModalError('');
    setIsCheckingAssets(true);

    try {
      const assets = await getAssetsByOwner(user.wallet_address);
      setUserAssets(Array.isArray(assets) ? assets : []);
    } catch (err) {
      console.error('Failed to query user assets:', err);
      setModalError('Failed to inspect on-chain asset ownership.');
    } finally {
      setIsCheckingAssets(false);
    }
  };

  const handleRevokeInModal = async (tokenId) => {
    if (!signer) {
      setModalError('MetaMask signer is not connected.');
      return;
    }
    try {
      setModalError('');
      setRevokingTokenId(tokenId);
      await revokeAsset(signer, parseInt(tokenId));
      // Remove the revoked asset from local modal list
      setUserAssets(prev => prev.filter(a => a.token_id !== tokenId));
    } catch (err) {
      console.error('Revocation failed:', err);
      setModalError(err.message || 'Revocation transaction failed.');
    } finally {
      setRevokingTokenId(null);
    }
  };

  const confirmDelete = async () => {
    if (!deleteModalUser) return;
    try {
      setError('');
      setSuccess('');
      await axios.delete(`${API_BASE}/users/${deleteModalUser.id}`);
      setSuccess(`User "${deleteModalUser.name || deleteModalUser.wallet_address}" has been deactivated and blocked.`);
      setDeleteModalUser(null);
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to delete user.');
      setDeleteModalUser(null);
    }
  };

  const inputStyle = {
    padding: '10px 12px',
    border: '1px solid #cbd5e1',
    borderRadius: '6px',
    fontSize: '13px',
    width: '100%',
    boxSizing: 'border-box',
    marginBottom: '10px',
  };

  const labelStyle = {
    fontSize: '11px',
    fontWeight: '600',
    color: '#475569',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    marginBottom: '4px',
    display: 'block',
  };

  return (
    <div style={{ background: '#fff', padding: '1.5rem', borderRadius: '12px', border: '1px solid #e2e8f0' }}>
      <div style={{ marginBottom: '1.5rem', borderBottom: '1px solid #e2e8f0', paddingBottom: '1rem' }}>
        <h2 style={{ fontSize: '20px', fontWeight: '700', color: '#0f172a', margin: '0 0 4px 0' }}>
          User & Identity Management
        </h2>
        <p style={{ fontSize: '13px', color: '#64748b', margin: 0 }}>
          Provision cryptographic identities, generate user wallets, and manage role-based authorization.
        </p>
      </div>

      {error && (
        <div style={{ color: '#991b1b', background: '#fef2f2', border: '1px solid #fecaca', padding: '12px', borderRadius: '8px', marginBottom: '1.5rem', fontSize: '13px' }}>
          {error}
        </div>
      )}

      {success && (
        <div style={{ color: '#166534', background: '#f0fdf4', border: '1px solid #bbf7d0', padding: '12px', borderRadius: '8px', marginBottom: '1.5rem', fontSize: '13px' }}>
          {success}
        </div>
      )}

      {/* REGISTRATION FORM */}
      <div style={{ background: '#f8fafc', padding: '1.5rem', border: '1px solid #e2e8f0', borderRadius: '10px', marginBottom: '2rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3 style={{ fontSize: '15px', fontWeight: '600', color: '#0f172a', margin: 0 }}>
            Provision New User / Generate Wallet
          </h3>
          <button
            type="button"
            onClick={handleGenerateWallet}
            style={{
              background: '#0f172a',
              color: '#fff',
              border: 'none',
              padding: '8px 14px',
              borderRadius: '6px',
              fontSize: '12px',
              fontWeight: '600',
              cursor: 'pointer',
            }}
          >
            + Generate Keypair
          </button>
        </div>

        {/* GENERATED KEYPAIR WARNING BOX */}
        {generatedWallet && (
          <div style={{ background: '#fffbeb', border: '1px solid #fde68a', borderRadius: '8px', padding: '1rem', marginBottom: '1.5rem' }}>
            <div style={{ fontSize: '12px', fontWeight: '700', color: '#92400e', marginBottom: '8px' }}>
              Generated Wallet Credentials (Save Immediately - Hand over to User)
            </div>
            <div style={{ fontSize: '12px', marginBottom: '6px' }}>
              <strong style={{ color: '#78350f' }}>Public Address:</strong>{' '}
              <code style={{ fontFamily: 'monospace', background: '#fff', padding: '2px 6px', borderRadius: '4px', border: '1px solid #fed7aa' }}>
                {generatedWallet.address}
              </code>
            </div>
            <div style={{ fontSize: '12px', marginBottom: '6px' }}>
              <strong style={{ color: '#991b1b' }}>Private Key:</strong>{' '}
              <code style={{ fontFamily: 'monospace', background: '#fff', padding: '2px 6px', borderRadius: '4px', border: '1px solid #fecaca', color: '#dc2626', wordBreak: 'break-all' }}>
                {generatedWallet.privateKey}
              </code>
            </div>
            <p style={{ fontSize: '11px', color: '#b45309', margin: '6px 0 0 0' }}>
              Import this private key into MetaMask or hardware signer to authenticate as this user.
            </p>
          </div>
        )}

        <form onSubmit={handleCreateOrUpdate}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div>
              <label style={labelStyle}>Full Name</label>
              <input
                type="text"
                placeholder="Full name"
                value={formData.name}
                onChange={e => setFormData({ ...formData, name: e.target.value })}
                style={inputStyle}
              />
            </div>
            <div>
              <label style={labelStyle}>Contact Number / Service ID</label>
              <input
                type="text"
                placeholder="Contact number or ID"
                value={formData.contact_number}
                onChange={e => setFormData({ ...formData, contact_number: e.target.value })}
                style={inputStyle}
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem' }}>
            <div>
              <label style={labelStyle}>Ethereum Wallet Address</label>
              <input
                type="text"
                placeholder="0x..."
                value={formData.wallet_address}
                onChange={e => setFormData({ ...formData, wallet_address: e.target.value })}
                style={{ ...inputStyle, fontFamily: 'monospace' }}
                required
              />
            </div>
            <div>
              <label style={labelStyle}>Assign Role</label>
              <select
                value={formData.role}
                onChange={e => setFormData({ ...formData, role: e.target.value })}
                style={{ ...inputStyle, background: '#fff', color: '#0f172a' }}
              >
                {availableRoles.length === 0 ? (
                  <option value="" disabled>No roles available for your permission level</option>
                ) : (
                  availableRoles.map(role => (
                    <option key={role.value} value={role.value} style={{ color: '#0f172a' }}>
                      {role.label}
                    </option>
                  ))
                )}
              </select>
            </div>
          </div>

          <button
            type="submit"
            style={{
              background: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
              color: 'white',
              padding: '10px 20px',
              border: 'none',
              borderRadius: '6px',
              fontWeight: '600',
              fontSize: '13px',
              cursor: 'pointer',
              marginTop: '4px',
            }}
          >
            Save & Provision User
          </button>
        </form>
      </div>

      {/* USER LIST TABLE */}
      <h3 style={{ fontSize: '15px', fontWeight: '600', color: '#0f172a', marginBottom: '1rem' }}>
        Registered System Users ({users.length})
      </h3>

      {loading ? (
        <p style={{ color: '#64748b', fontSize: '13px' }}>Loading users...</p>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead style={{ background: '#f8fafc', borderBottom: '2px solid #e2e8f0', textAlign: 'left' }}>
              <tr>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#475569' }}>Name & Contact</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#475569' }}>Wallet Address</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#475569' }}>W3C DID</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#475569' }}>Role</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#475569' }}>Change Role</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#475569' }}>Dev Faucet</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#475569' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id} style={{ borderBottom: '1px solid #f1f5f9' }}>
                  <td style={{ padding: '10px 12px' }}>
                    <div style={{ fontWeight: '600', color: '#0f172a' }}>{u.name || 'Unnamed'}</div>
                    <div style={{ fontSize: '11px', color: '#64748b' }}>{u.contact_number || 'No contact'}</div>
                  </td>
                  <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: '#334155' }}>
                    {u.wallet_address}
                  </td>
                  <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: '#64748b', fontSize: '11px' }}>
                    {u.did ? `${u.did.slice(0, 22)}...` : 'N/A'}
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <span style={{
                      padding: '3px 8px',
                      borderRadius: '4px',
                      background: u.role === 'ADMIN' ? '#fee2e2' : u.role === 'MANAGER' ? '#dbeafe' : u.role === 'AUDITOR' ? '#fef3c7' : '#f1f5f9',
                      color: u.role === 'ADMIN' ? '#991b1b' : u.role === 'MANAGER' ? '#1e40af' : u.role === 'AUDITOR' ? '#92400e' : '#475569',
                      fontWeight: '700',
                      fontSize: '11px'
                    }}>
                      {u.role}
                    </span>
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <select
                      value={u.role}
                      onChange={(e) => updateRole(u.id, e.target.value)}
                      style={{ padding: '4px 8px', fontSize: '12px', borderRadius: '4px', border: '1px solid #cbd5e1', color: '#0f172a', background: '#fff' }}
                    >
                      {availableRoles.map(role => (
                        <option key={role.value} value={role.value} style={{ color: '#0f172a' }}>
                          {role.value}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <button
                      onClick={() => fundWallet(u.id)}
                      style={{
                        background: '#f0fdf4',
                        color: '#166534',
                        border: '1px solid #bbf7d0',
                        padding: '4px 10px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                      title="Send 1000 LEX for transaction gas on local network"
                    >
                      + 1000 LEX
                    </button>
                  </td>
                  <td style={{ padding: '10px 12px' }}>
                    <button
                      onClick={() => initiateDelete(u)}
                      style={{
                        background: '#fee2e2',
                        color: '#991b1b',
                        border: '1px solid #fecaca',
                        padding: '4px 10px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: '600',
                        cursor: 'pointer'
                      }}
                      title="Permanently remove and block this user"
                    >
                      Revoke Identity
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* VERIFY & REVOKE ASSETS BEFORE USER DELETION MODAL */}
      {deleteModalUser && (
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
            maxWidth: '560px',
            width: '90%',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)',
            border: '1px solid #e2e8f0',
            maxHeight: '90vh',
            overflowY: 'auto',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '700', color: '#991b1b' }}>
                Revoke User Access & Identity
              </h3>
              <button
                onClick={() => setDeleteModalUser(null)}
                style={{ background: 'none', border: 'none', fontSize: '18px', cursor: 'pointer', color: '#64748b' }}
              >
                ✕
              </button>
            </div>

            <p style={{ fontSize: '13px', color: '#475569', marginTop: 0 }}>
              You are about to deactivate user <strong>{deleteModalUser.name || 'Unnamed'}</strong> (<code>{deleteModalUser.wallet_address.slice(0, 10)}...</code>). Their identity will be soft-deleted, blocking authentication while preserving audit trail integrity.
            </p>

            {modalError && (
              <div style={{ color: '#991b1b', background: '#fef2f2', border: '1px solid #fecaca', padding: '10px', borderRadius: '6px', marginBottom: '1rem', fontSize: '12px' }}>
                {modalError}
              </div>
            )}

            {isCheckingAssets ? (
              <div style={{ textAlign: 'center', padding: '1.5rem', color: '#64748b', fontSize: '13px' }}>
                🔍 Inspecting on-chain asset ownership...
              </div>
            ) : userAssets.length > 0 ? (
              <div style={{ background: '#fffbeb', border: '1px solid #fde68a', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem' }}>
                <div style={{ fontSize: '13px', fontWeight: '700', color: '#92400e', marginBottom: '8px' }}>
                  ⚠️ Active On-Chain Assets Detected ({userAssets.length})
                </div>
                <p style={{ fontSize: '12px', color: '#78350f', margin: '0 0 10px 0' }}>
                  This user currently owns digital assets on the blockchain. You should revoke these tokens before deleting the user.
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {userAssets.map(asset => (
                    <div key={asset.token_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#fff', padding: '8px 12px', borderRadius: '6px', border: '1px solid #fed7aa' }}>
                      <div>
                        <div style={{ fontWeight: '700', fontSize: '12px', color: '#0f172a' }}>
                          Serial: {asset.serial_number}
                        </div>
                        <div style={{ fontSize: '11px', color: '#64748b', fontFamily: 'monospace' }}>
                          Token ID #{asset.token_id}
                        </div>
                      </div>
                      <button
                        onClick={() => handleRevokeInModal(asset.token_id)}
                        disabled={revokingTokenId === asset.token_id}
                        style={{
                          background: '#dc2626',
                          color: '#fff',
                          border: 'none',
                          padding: '6px 12px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontWeight: '600',
                          cursor: revokingTokenId === asset.token_id ? 'not-allowed' : 'pointer'
                        }}
                      >
                        {revokingTokenId === asset.token_id ? 'Burning...' : 'Revoke Token'}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem', fontSize: '12px', color: '#166534' }}>
                ✓ No active on-chain assets assigned to this wallet. Safe to proceed with deletion.
              </div>
            )}

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setDeleteModalUser(null)}
                style={{
                  background: '#f1f5f9',
                  color: '#475569',
                  border: '1px solid #cbd5e1',
                  padding: '10px 16px',
                  borderRadius: '6px',
                  fontSize: '13px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                style={{
                  background: '#dc2626',
                  color: '#fff',
                  border: 'none',
                  padding: '10px 16px',
                  borderRadius: '6px',
                  fontSize: '13px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                Confirm Delete & Block User
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
