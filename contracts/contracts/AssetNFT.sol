// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title AssetNFT
 * @author LexCorp / SIH 2026
 * @notice Enterprise ERC-721 Digital & Physical Asset Tokens with:
 *         - Dual-layer Access Control: System RBAC (Admin/Manager/Auditor) & Asset-Specific Access Lists
 *         - Off-chain Document Hash Anchoring (SHA-256 integrity verification)
 *         - Immutable On-chain Audit Event Logging for all operations and access attempts.
 */
contract AssetNFT is ERC721, AccessControl, ReentrancyGuard {
    // -------------------------------------------------------------------------
    // Roles
    // -------------------------------------------------------------------------

    /// @notice System Role that can mint, transfer, and revoke assets.
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    /// @notice System Role with read-only compliance and audit access to all assets.
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    // -------------------------------------------------------------------------
    // Custom Errors (OWASP SCSVS SC3)
    // -------------------------------------------------------------------------
    error NotManager();
    error NotAuthorized();
    error TokenAlreadyExists(uint256 tokenId);
    error EmptySerialNumber();
    error EmptyOwnerDID();
    error EmptyFileHash();
    error ZeroAddress();
    error InvalidPermission();

    // -------------------------------------------------------------------------
    // State Structures
    // -------------------------------------------------------------------------

    enum PermissionLevel {
        NONE,       // 0: No access
        READ,       // 1: Read/Verify access to off-chain file
        READ_WRITE  // 2: Modify/Update off-chain metadata
    }

    struct Asset {
        string serialNumber; // Human-readable identifier or digital asset code
        string ownerDID;     // W3C DID of current owner (e.g., "did:ethr:13371:0x...")
        string fileHash;     // Cryptographic SHA-256 hash of the off-chain file
        string offchainURI;  // IPFS CID or secure off-chain storage pointer
        bool isDigital;      // Flag: true for digital documents, false for physical assets
    }

    /// @dev tokenId => Asset details
    mapping(uint256 => Asset) private _assets;

    /// @dev serialNumber => tokenId reverse lookup
    mapping(string => uint256) private _serialToToken;

    /// @dev tokenId => (DID => PermissionLevel)
    mapping(uint256 => mapping(string => PermissionLevel)) private _assetPermissions;

    // -------------------------------------------------------------------------
    // Audit Events
    // -------------------------------------------------------------------------
    event AssetMinted(
        uint256 indexed tokenId,
        string serialNumber,
        string ownerDID,
        address indexed owner
    );

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

    event AssetTransferred(
        uint256 indexed tokenId,
        string fromDID,
        string toDID,
        address indexed newOwner
    );

    event AssetRevoked(uint256 indexed tokenId, string serialNumber);

    event AccessPermissionGranted(
        uint256 indexed tokenId,
        string targetDID,
        PermissionLevel level,
        address indexed grantedBy
    );

    event AccessPermissionRevoked(
        uint256 indexed tokenId,
        string targetDID,
        address indexed revokedBy
    );

    event AccessAttempted(
        uint256 indexed tokenId,
        string actorDID,
        bool granted,
        string reason,
        uint256 timestamp
    );

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    constructor() ERC721("LexCorpEnterpriseAsset", "LEXASSET") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------
    modifier onlyManager() {
        if (!hasRole(MANAGER_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotManager();
        }
        _;
    }

    // -------------------------------------------------------------------------
    // Minting Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Mint a standard physical asset NFT bound to a DID (V1 compatibility).
     */
    function mint(
        address to,
        uint256 tokenId,
        string calldata serialNumber,
        string calldata ownerDID
    ) external onlyManager nonReentrant {
        _mintAsset(to, tokenId, serialNumber, ownerDID, "", "", false);
        emit AssetMinted(tokenId, serialNumber, ownerDID, to);
    }

    /**
     * @notice Mint a secure Digital Asset NFT with cryptographic SHA-256 hash & off-chain URI.
     */
    function mintDigitalAsset(
        address to,
        uint256 tokenId,
        string calldata serialNumber,
        string calldata ownerDID,
        string calldata fileHash,
        string calldata offchainURI
    ) external nonReentrant {
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
        if (bytes(serialNumber).length == 0) revert EmptySerialNumber();
        if (bytes(ownerDID).length == 0) revert EmptyOwnerDID();
        if (_serialToToken[serialNumber] != 0) revert TokenAlreadyExists(_serialToToken[serialNumber]);

        _assets[tokenId] = Asset(serialNumber, ownerDID, fileHash, offchainURI, isDigital);
        _serialToToken[serialNumber] = tokenId;

        // Auto-grant READ_WRITE access to the owner's DID
        _assetPermissions[tokenId][ownerDID] = PermissionLevel.READ_WRITE;

        _mint(to, tokenId);
    }

    // -------------------------------------------------------------------------
    // Asset Management (Transfer / Revocation / Update)
    // -------------------------------------------------------------------------

    /**
     * @notice Update a Digital Asset's file hash and offchain URI.
     * @dev Caller must have READ_WRITE permission for the targeted DID.
     */
    function updateDigitalAsset(
        uint256 tokenId,
        string calldata requesterDID,
        string calldata newFileHash,
        string calldata newOffchainURI
    ) external nonReentrant {
        // Must be a digital asset
        require(_assets[tokenId].isDigital, "Not a digital asset");

        bool authorized = false;
        PermissionLevel level = PermissionLevel.NONE;

        if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) || hasRole(MANAGER_ROLE, msg.sender)) {
            authorized = true;
            level = PermissionLevel.READ_WRITE; // Admins/managers have override to write
        } else if (msg.sender == ownerOf(tokenId)) {
            authorized = true;
            level = PermissionLevel.READ_WRITE; // Owner can write
        } else {
            level = _assetPermissions[tokenId][requesterDID];
            if (level != PermissionLevel.NONE) {
                authorized = true;
            }
        }

        require(authorized && level == PermissionLevel.READ_WRITE, "Not authorized to write");
        require(bytes(newFileHash).length > 0, "Empty file hash");

        string memory oldFileHash = _assets[tokenId].fileHash;

        _assets[tokenId].fileHash = newFileHash;
        _assets[tokenId].offchainURI = newOffchainURI;

        emit DigitalAssetUpdated(tokenId, oldFileHash, newFileHash, newOffchainURI, msg.sender);
    }

    /**
     * @notice Transfer asset and bind new owner DID.
     */
    function transferAsset(
        address to,
        uint256 tokenId,
        string calldata newOwnerDID
    ) external onlyManager nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        if (bytes(newOwnerDID).length == 0) revert EmptyOwnerDID();

        address currentOwner = ownerOf(tokenId);
        string memory oldDID = _assets[tokenId].ownerDID;

        _assets[tokenId].ownerDID = newOwnerDID;
        _assetPermissions[tokenId][newOwnerDID] = PermissionLevel.READ_WRITE;

        _transfer(currentOwner, to, tokenId);

        emit AssetTransferred(tokenId, oldDID, newOwnerDID, to);
    }

    /**
     * @notice Permanently revoke an asset NFT (burn).
     */
    function revoke(uint256 tokenId) external onlyManager nonReentrant {
        ownerOf(tokenId);

        string memory serial = _assets[tokenId].serialNumber;

        delete _serialToToken[serial];
        delete _assets[tokenId];

        _burn(tokenId);

        emit AssetRevoked(tokenId, serial);
    }

    // -------------------------------------------------------------------------
    // Asset-Level Access Control (Permission Management)
    // -------------------------------------------------------------------------

    /**
     * @notice Grant access permission for a specific asset to a DID.
     */
    function grantAssetAccess(
        uint256 tokenId,
        string calldata targetDID,
        PermissionLevel level
    ) external nonReentrant {
        address currentOwner = ownerOf(tokenId);
        if (msg.sender != currentOwner && !hasRole(MANAGER_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotAuthorized();
        }
        if (bytes(targetDID).length == 0) revert EmptyOwnerDID();
        if (level == PermissionLevel.NONE) revert InvalidPermission();

        _assetPermissions[tokenId][targetDID] = level;

        emit AccessPermissionGranted(tokenId, targetDID, level, msg.sender);
    }

    /**
     * @notice Revoke access permission for a specific asset from a DID.
     */
    function revokeAssetAccess(
        uint256 tokenId,
        string calldata targetDID
    ) external nonReentrant {
        address currentOwner = ownerOf(tokenId);
        if (msg.sender != currentOwner && !hasRole(MANAGER_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert NotAuthorized();
        }

        delete _assetPermissions[tokenId][targetDID];

        emit AccessPermissionRevoked(tokenId, targetDID, msg.sender);
    }

    /**
     * @notice Check whether a given DID / caller address is authorized to access an asset.
     */
    function checkAssetAccess(
        uint256 tokenId,
        string calldata requesterDID,
        address callerAddress
    ) external view returns (bool authorized, PermissionLevel level) {
        ownerOf(tokenId); // Reverts if token doesn't exist

        // 1. System Admins and Auditors have global compliance access
        if (hasRole(DEFAULT_ADMIN_ROLE, callerAddress) || hasRole(AUDITOR_ROLE, callerAddress)) {
            return (true, PermissionLevel.READ);
        }

        // 2. Token Owner has full access
        if (callerAddress == ownerOf(tokenId)) {
            return (true, PermissionLevel.READ_WRITE);
        }

        // 3. Check explicit DID permission
        PermissionLevel perm = _assetPermissions[tokenId][requesterDID];
        if (perm != PermissionLevel.NONE) {
            return (true, perm);
        }

        return (false, PermissionLevel.NONE);
    }

    /**
     * @notice Record an access attempt on-chain for tamper-proof audit trail.
     */
    function recordAccessAttempt(
        uint256 tokenId,
        string calldata actorDID,
        bool granted,
        string calldata reason
    ) external {
        emit AccessAttempted(tokenId, actorDID, granted, reason, block.timestamp);
    }

    // -------------------------------------------------------------------------
    // View Functions
    // -------------------------------------------------------------------------

    function getAsset(uint256 tokenId)
        external
        view
        returns (string memory serialNumber, string memory ownerDID)
    {
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

    function getTokenBySerial(string calldata serialNumber)
        external
        view
        returns (uint256 tokenId)
    {
        return _serialToToken[serialNumber];
    }

    function getAssetPermission(uint256 tokenId, string calldata did)
        external
        view
        returns (PermissionLevel)
    {
        ownerOf(tokenId);
        return _assetPermissions[tokenId][did];
    }

    // -------------------------------------------------------------------------
    // Overrides
    // -------------------------------------------------------------------------
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
