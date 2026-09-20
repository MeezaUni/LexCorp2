import { expect } from "chai";
import hre from "hardhat";

describe("AssetNFT (V2 Enhanced)", function () {
  let AssetNFT, assetNFT, admin, manager, auditor, user1, user2;

  beforeEach(async function () {
    [admin, manager, auditor, user1, user2] = await hre.ethers.getSigners();
    AssetNFT = await hre.ethers.getContractFactory("AssetNFT");
    assetNFT = await AssetNFT.deploy();

    // Grant roles
    await assetNFT.grantRole(await assetNFT.MANAGER_ROLE(), manager.address);
    await assetNFT.grantRole(await assetNFT.AUDITOR_ROLE(), auditor.address);
  });

  describe("Physical Assets (V1 Compatibility)", function () {
    it("should mint a physical asset", async function () {
      await expect(assetNFT.connect(manager).mint(user1.address, 1, "PHYS-001", "did:ethr:13371:0xuser1"))
        .to.emit(assetNFT, "AssetMinted")
        .withArgs(1, "PHYS-001", "did:ethr:13371:0xuser1", user1.address);

      const asset = await assetNFT.getAsset(1);
      expect(asset.serialNumber).to.equal("PHYS-001");
      expect(asset.ownerDID).to.equal("did:ethr:13371:0xuser1");
    });
  });

  describe("Digital Assets with Cryptographic Hashes", function () {
    const fileHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // SHA-256
    const offchainURI = "ipfs://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";

    it("should mint a digital asset with hash and URI", async function () {
      await expect(
        assetNFT.connect(manager).mintDigitalAsset(
          user1.address,
          101,
          "DIGI-DOC-001",
          "did:ethr:13371:0xuser1",
          fileHash,
          offchainURI
        )
      )
        .to.emit(assetNFT, "DigitalAssetMinted")
        .withArgs(101, "DIGI-DOC-001", "did:ethr:13371:0xuser1", fileHash, offchainURI, user1.address);

      const digitalAsset = await assetNFT.getDigitalAsset(101);
      expect(digitalAsset.serialNumber).to.equal("DIGI-DOC-001");
      expect(digitalAsset.fileHash).to.equal(fileHash);
      expect(digitalAsset.offchainURI).to.equal(offchainURI);
      expect(digitalAsset.isDigital).to.be.true;
    });
  });

  describe("Asset-Level Access Control", function () {
    beforeEach(async function () {
      await assetNFT.connect(manager).mintDigitalAsset(
        user1.address,
        201,
        "CONFIDENTIAL-PDF-01",
        "did:ethr:13371:0xuser1",
        "hash123",
        "ipfs://doc123"
      );
    });

    it("should allow owner to grant and revoke access to another DID", async function () {
      // User 2 initially has no access
      let access = await assetNFT.checkAssetAccess(201, "did:ethr:13371:0xuser2", user2.address);
      expect(access.authorized).to.be.false;

      // User 1 grants READ (1) access to User 2
      await expect(
        assetNFT.connect(user1).grantAssetAccess(201, "did:ethr:13371:0xuser2", 1)
      )
        .to.emit(assetNFT, "AccessPermissionGranted")
        .withArgs(201, "did:ethr:13371:0xuser2", 1, user1.address);

      // Now User 2 is authorized
      access = await assetNFT.checkAssetAccess(201, "did:ethr:13371:0xuser2", user2.address);
      expect(access.authorized).to.be.true;
      expect(access.level).to.equal(1);

      // Revoke access
      await expect(
        assetNFT.connect(user1).revokeAssetAccess(201, "did:ethr:13371:0xuser2")
      )
        .to.emit(assetNFT, "AccessPermissionRevoked")
        .withArgs(201, "did:ethr:13371:0xuser2", user1.address);

      access = await assetNFT.checkAssetAccess(201, "did:ethr:13371:0xuser2", user2.address);
      expect(access.authorized).to.be.false;
    });

    it("should allow Auditor and Admin global read access", async function () {
      const auditorAccess = await assetNFT.checkAssetAccess(201, "did:ethr:13371:0xauditor", auditor.address);
      expect(auditorAccess.authorized).to.be.true;

      const adminAccess = await assetNFT.checkAssetAccess(201, "did:ethr:13371:0xadmin", admin.address);
      expect(adminAccess.authorized).to.be.true;
    });

    it("should record access attempts with on-chain event", async function () {
      await expect(
        assetNFT.recordAccessAttempt(201, "did:ethr:13371:0xuser2", false, "Permission Denied")
      ).to.emit(assetNFT, "AccessAttempted");
    });
  });
});
