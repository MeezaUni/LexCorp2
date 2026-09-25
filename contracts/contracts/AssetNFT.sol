// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title AssetNFT (v3)
 * @notice LexCorp2 registry for digital and physical assets.
 *
 * Every state change is role-restricted ON-CHAIN; backend RBAC is an additional layer,
 * not the only one:
 *
 *   DEFAULT_ADMIN_ROLE  governance key (deployment/operations only). Can pause, can
 *                       manage REGISTRAR_ROLE.
 *   REGISTRAR_ROLE      role administrator for the operational roles below. Held by the
 *                       LexCorp2 backend "chain operator" so that on-chain roles follow
 *                       the identity lifecycle (provision / role change / revocation).
 *                       A registrar can NEVER hold an operational role itself.
 *   MINTER_ROLE         register (mint) physical and digital assets.
 *   ANCHOR_ROLE         anchor an approved revision (new file hash) of a digital asset.
 *   MANAGER_ROLE        transfer custody, revoke (burn), mirror access grants, record
 *                       access attempts.
 *   AUDITOR_ROLE        read-only compliance role; may record access attempts.
 *
 * Tokens are custody records, not tradeable NFTs: plain ERC-721 transfers and
 * approvals are disabled; custody moves only through transferAsset (MANAGER_ROLE).
 */
contract AssetNFT is ERC721, AccessControl, ReentrancyGuard, Pausable {
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant ANCHOR_ROLE = keccak256("ANCHOR_ROLE");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    error TokenAlreadyExists(uint256 tokenId);
    error InvalidTokenId();
    error EmptySerialNumber();
    error EmptyOwnerDID();
    error EmptyFileHash();
    error ZeroAddress();
    error InvalidPermission();
    error NotDigitalAsset(uint256 tokenId);
    error TransfersRestricted();
    error SeparationOfDuties(bytes32 role, address account);

    enum PermissionLevel {
        NONE,
        READ,
        READ_WRITE
    }

    struct Asset {
        string serialNumber;
        string ownerDID;
        string fileHash;
        string offchainURI;
        bool isDigital;
    }

    mapping(uint256 => Asset) private _assets;
    mapping(string => uint256) private _serialToToken;
    mapping(uint256 => mapping(string => PermissionLevel)) private _assetPermissions;
    bool private _managedTransfer;

    event AssetMinted(uint256 indexed tokenId, string serialNumber, string ownerDID, address indexed owner);
    event DigitalAssetMinted(
        uint256 indexed tokenId,
        string serialNumber,
        string ownerDID,
        string fileHash,
        string offchainURI,
        address indexed owner
    );
    event DigitalAssetUpdated(
        uint256 indexed tokenId,
        string oldFileHash,
        string newFileHash,
        string newOffchainURI,
        address indexed updater
    );
    event AssetTransferred(uint256 indexed tokenId, string fromDID, string toDID, address indexed newOwner);
    event AssetRevoked(uint256 indexed tokenId, string serialNumber);
    event AccessPermissionGranted(uint256 indexed tokenId, string targetDID, PermissionLevel level, address indexed grantedBy);
    event AccessPermissionRevoked(uint256 indexed tokenId, string targetDID, address indexed revokedBy);
    event AccessAttempted(uint256 indexed tokenId, string actorDID, bool granted, string reason, uint256 timestamp);

    /// @param admin governance account (DEFAULT_ADMIN_ROLE)
    /// @param registrar backend chain-operator account (REGISTRAR_ROLE); may be address(0)
    constructor(address admin, address registrar) ERC721("LexCorp2 Asset Record", "LEX2") {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _setRoleAdmin(MINTER_ROLE, REGISTRAR_ROLE);
        _setRoleAdmin(ANCHOR_ROLE, REGISTRAR_ROLE);
        _setRoleAdmin(MANAGER_ROLE, REGISTRAR_ROLE);
        _setRoleAdmin(AUDITOR_ROLE, REGISTRAR_ROLE);
        if (registrar != address(0)) _grantRole(REGISTRAR_ROLE, registrar);
    }

    // ---------------------------------------------------------------- roles

    function _isOperational(bytes32 role) private pure returns (bool) {
        return role == MINTER_ROLE || role == ANCHOR_ROLE || role == MANAGER_ROLE || role == AUDITOR_ROLE;
    }

    /// Separation of duties: the registrar (which hands out roles) and the governance
    /// admin can never also act as minter/anchor/manager/auditor, and vice versa.
    function _grantRole(bytes32 role, address account) internal override {
        if (_isOperational(role)) {
            if (hasRole(REGISTRAR_ROLE, account) || hasRole(DEFAULT_ADMIN_ROLE, account)) {
                revert SeparationOfDuties(role, account);
            }
        } else if (role == REGISTRAR_ROLE || role == DEFAULT_ADMIN_ROLE) {
            if (
                hasRole(MINTER_ROLE, account) || hasRole(ANCHOR_ROLE, account) ||
                hasRole(MANAGER_ROLE, account) || hasRole(AUDITOR_ROLE, account)
            ) {
                revert SeparationOfDuties(role, account);
            }
        }
        super._grantRole(role, account);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ---------------------------------------------------------------- minting

    function mint(address to, uint256 tokenId, string calldata serialNumber, string calldata ownerDID)
        external
        onlyRole(MINTER_ROLE)
        whenNotPaused
        nonReentrant
    {
        _mintAsset(to, tokenId, serialNumber, ownerDID, "", "", false);
        emit AssetMinted(tokenId, serialNumber, ownerDID, to);
    }

    function mintDigitalAsset(
        address to,
        uint256 tokenId,
        string calldata serialNumber,
        string calldata ownerDID,
        string calldata fileHash,
        string calldata offchainURI
    ) external onlyRole(MINTER_ROLE) whenNotPaused nonReentrant {
        if (bytes(fileHash).length == 0) revert EmptyFileHash();
        _mintAsset(to, tokenId, serialNumber, ownerDID, fileHash, offchainURI, true);
        emit DigitalAssetMinted(tokenId, serialNumber, ownerDID, fileHash, offchainURI, to);
    }

    function _mintAsset(
        address to,
        uint256 tokenId,
        string calldata serialNumber,
        string calldata ownerDID,
        string memory fileHash,
        string memory offchainURI,
        bool isDigital
    ) internal {
        if (to == address(0)) revert ZeroAddress();
        if (tokenId == 0) revert InvalidTokenId();
        if (bytes(serialNumber).length == 0) revert EmptySerialNumber();
        if (bytes(ownerDID).length == 0) revert EmptyOwnerDID();
        if (_serialToToken[serialNumber] != 0) revert TokenAlreadyExists(_serialToToken[serialNumber]);
        if (_exists(tokenId)) revert TokenAlreadyExists(tokenId);

        _assets[tokenId] = Asset(serialNumber, ownerDID, fileHash, offchainURI, isDigital);
        _serialToToken[serialNumber] = tokenId;
        _assetPermissions[tokenId][ownerDID] = PermissionLevel.READ_WRITE;
        _mint(to, tokenId);
    }

    // ---------------------------------------------------------------- lifecycle

    /// Anchor an approved revision. Only ANCHOR_ROLE; no caller-supplied identity is trusted.
    function updateDigitalAsset(uint256 tokenId, string calldata newFileHash, string calldata newOffchainURI)
        external
        onlyRole(ANCHOR_ROLE)
        whenNotPaused
        nonReentrant
    {
        _requireMinted(tokenId);
        if (!_assets[tokenId].isDigital) revert NotDigitalAsset(tokenId);
        if (bytes(newFileHash).length == 0) revert EmptyFileHash();
        string memory oldFileHash = _assets[tokenId].fileHash;
        _assets[tokenId].fileHash = newFileHash;
        _assets[tokenId].offchainURI = newOffchainURI;
        emit DigitalAssetUpdated(tokenId, oldFileHash, newFileHash, newOffchainURI, msg.sender);
    }

    function transferAsset(address to, uint256 tokenId, string calldata newOwnerDID)
        external
        onlyRole(MANAGER_ROLE)
        whenNotPaused
        nonReentrant
    {
        if (to == address(0)) revert ZeroAddress();
        if (bytes(newOwnerDID).length == 0) revert EmptyOwnerDID();
        address currentOwner = ownerOf(tokenId);
        string memory oldDID = _assets[tokenId].ownerDID;

        delete _assetPermissions[tokenId][oldDID];
        _assets[tokenId].ownerDID = newOwnerDID;
        _assetPermissions[tokenId][newOwnerDID] = PermissionLevel.READ_WRITE;

        _managedTransfer = true;
        _transfer(currentOwner, to, tokenId);
        _managedTransfer = false;

        emit AssetTransferred(tokenId, oldDID, newOwnerDID, to);
    }

    function revoke(uint256 tokenId) external onlyRole(MANAGER_ROLE) nonReentrant {
        ownerOf(tokenId);
        string memory serial = _assets[tokenId].serialNumber;
        delete _serialToToken[serial];
        delete _assets[tokenId];
        _burn(tokenId);
        emit AssetRevoked(tokenId, serial);
    }

    // ---------------------------------------------------------------- access mirror

    /// On-chain mirror of an access grant that was approved in LexCorp2 (MANAGER_ROLE only;
    /// a token holder cannot grant access to itself or others without approval).
    function grantAssetAccess(uint256 tokenId, string calldata targetDID, PermissionLevel level)
        external
        onlyRole(MANAGER_ROLE)
        nonReentrant
    {
        ownerOf(tokenId);
        if (bytes(targetDID).length == 0) revert EmptyOwnerDID();
        if (level == PermissionLevel.NONE) revert InvalidPermission();
        _assetPermissions[tokenId][targetDID] = level;
        emit AccessPermissionGranted(tokenId, targetDID, level, msg.sender);
    }

    function revokeAssetAccess(uint256 tokenId, string calldata targetDID) external onlyRole(MANAGER_ROLE) nonReentrant {
        ownerOf(tokenId);
        delete _assetPermissions[tokenId][targetDID];
        emit AccessPermissionRevoked(tokenId, targetDID, msg.sender);
    }

    function checkAssetAccess(uint256 tokenId, string calldata requesterDID, address callerAddress)
        external
        view
        returns (bool authorized, PermissionLevel level)
    {
        address holder = ownerOf(tokenId);
        if (hasRole(AUDITOR_ROLE, callerAddress) || hasRole(MANAGER_ROLE, callerAddress)) {
            return (true, PermissionLevel.READ);
        }
        if (callerAddress == holder) return (true, PermissionLevel.READ_WRITE);
        PermissionLevel perm = _assetPermissions[tokenId][requesterDID];
        if (perm != PermissionLevel.NONE) return (true, perm);
        return (false, PermissionLevel.NONE);
    }

    function recordAccessAttempt(uint256 tokenId, string calldata actorDID, bool granted, string calldata reason) external {
        if (!hasRole(MANAGER_ROLE, msg.sender) && !hasRole(AUDITOR_ROLE, msg.sender)) {
            revert AccessControlUnauthorized(msg.sender);
        }
        emit AccessAttempted(tokenId, actorDID, granted, reason, block.timestamp);
    }

    error AccessControlUnauthorized(address account);

    // ---------------------------------------------------------------- views

    function getAsset(uint256 tokenId) external view returns (string memory serialNumber, string memory ownerDID) {
        ownerOf(tokenId);
        Asset storage a = _assets[tokenId];
        return (a.serialNumber, a.ownerDID);
    }

    function getDigitalAsset(uint256 tokenId)
        external
        view
        returns (
            string memory serialNumber,
            string memory ownerDID,
            string memory fileHash,
            string memory offchainURI,
            bool isDigital
        )
    {
        ownerOf(tokenId);
        Asset storage a = _assets[tokenId];
        return (a.serialNumber, a.ownerDID, a.fileHash, a.offchainURI, a.isDigital);
    }

    function getTokenBySerial(string calldata serialNumber) external view returns (uint256 tokenId) {
        return _serialToToken[serialNumber];
    }

    function getAssetPermission(uint256 tokenId, string calldata did) external view returns (PermissionLevel) {
        ownerOf(tokenId);
        return _assetPermissions[tokenId][did];
    }

    // ---------------------------------------------------------------- custody restrictions

    function approve(address, uint256) public pure override {
        revert TransfersRestricted();
    }

    function setApprovalForAll(address, bool) public pure override {
        revert TransfersRestricted();
    }

    function _beforeTokenTransfer(address from, address to, uint256 firstTokenId, uint256 batchSize)
        internal
        override
    {
        if (from != address(0) && to != address(0) && !_managedTransfer) revert TransfersRestricted();
        super._beforeTokenTransfer(from, to, firstTokenId, batchSize);
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC721, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
