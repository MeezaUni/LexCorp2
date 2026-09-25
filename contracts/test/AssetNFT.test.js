import { expect } from "chai";
import hre from "hardhat";

const HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const HASH2 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const DID = (a) => `did:ethr:13371:${a.toLowerCase()}`;

describe("AssetNFT v3 - on-chain authorization", function () {
  let c, admin, registrar, manager, auditor, user, outsider;
  let MINTER, ANCHOR, MANAGER, AUDITOR, REGISTRAR, ADMIN;

  beforeEach(async function () {
    [admin, registrar, manager, auditor, user, outsider] = await hre.ethers.getSigners();
    const F = await hre.ethers.getContractFactory("AssetNFT");
    c = await F.deploy(admin.address, registrar.address);
    [MINTER, ANCHOR, MANAGER, AUDITOR, REGISTRAR, ADMIN] = await Promise.all([
      c.MINTER_ROLE(), c.ANCHOR_ROLE(), c.MANAGER_ROLE(), c.AUDITOR_ROLE(), c.REGISTRAR_ROLE(), c.DEFAULT_ADMIN_ROLE(),
    ]);
    for (const r of [MINTER, ANCHOR, MANAGER]) await c.connect(registrar).grantRole(r, manager.address);
    await c.connect(registrar).grantRole(AUDITOR, auditor.address);
  });

  describe("deployment", function () {
    it("assigns admin and registrar from constructor arguments, not the deployer", async function () {
      expect(await c.hasRole(ADMIN, admin.address)).to.equal(true);
      expect(await c.hasRole(REGISTRAR, registrar.address)).to.equal(true);
      expect(await c.hasRole(MINTER, admin.address)).to.equal(false);
      expect(await c.getRoleAdmin(MINTER)).to.equal(REGISTRAR);
      expect(await c.getRoleAdmin(ANCHOR)).to.equal(REGISTRAR);
      expect(await c.getRoleAdmin(MANAGER)).to.equal(REGISTRAR);
      expect(await c.getRoleAdmin(AUDITOR)).to.equal(REGISTRAR);
    });

    it("rejects a zero admin", async function () {
      const F = await hre.ethers.getContractFactory("AssetNFT");
      await expect(F.deploy(hre.ethers.ZeroAddress, registrar.address)).to.be.revertedWithCustomError(c, "ZeroAddress");
    });
  });

  describe("minting", function () {
    it("authorized minter mints a physical asset", async function () {
      await expect(c.connect(manager).mint(user.address, 1, "PHY-001", DID(user.address)))
        .to.emit(c, "AssetMinted").withArgs(1, "PHY-001", DID(user.address), user.address);
      expect(await c.ownerOf(1)).to.equal(user.address);
      expect(await c.getTokenBySerial("PHY-001")).to.equal(1n);
    });

    it("authorized minter mints a digital asset", async function () {
      await expect(c.connect(manager).mintDigitalAsset(user.address, 7, "DOC-7", DID(user.address), HASH, "vault://7"))
        .to.emit(c, "DigitalAssetMinted");
      const d = await c.getDigitalAsset(7);
      expect(d.fileHash).to.equal(HASH);
      expect(d.isDigital).to.equal(true);
    });

    for (const who of ["user", "outsider", "auditor", "admin", "registrar"]) {
      it(`${who} (no MINTER_ROLE) cannot mint physical or digital assets`, async function () {
        const s = { user, outsider, auditor, admin, registrar }[who];
        await expect(c.connect(s).mint(s.address, 2, "PHY-X", DID(s.address))).to.be.revertedWith(/AccessControl/);
        await expect(c.connect(s).mintDigitalAsset(s.address, 3, "DOC-X", DID(s.address), HASH, "u"))
          .to.be.revertedWith(/AccessControl/);
      });
    }

    it("rejects token id 0, duplicate token ids and duplicate serials", async function () {
      await expect(c.connect(manager).mint(user.address, 0, "S0", "d")).to.be.revertedWithCustomError(c, "InvalidTokenId");
      await c.connect(manager).mint(user.address, 5, "S5", "d");
      await expect(c.connect(manager).mint(user.address, 6, "S5", "d")).to.be.revertedWithCustomError(c, "TokenAlreadyExists");
      await expect(c.connect(manager).mint(user.address, 5, "S6", "d")).to.be.revertedWithCustomError(c, "TokenAlreadyExists");
    });

    it("a revoked minter can no longer mint", async function () {
      await c.connect(registrar).revokeRole(MINTER, manager.address);
      await expect(c.connect(manager).mint(user.address, 9, "S9", "d")).to.be.revertedWith(/AccessControl/);
    });
  });

  describe("revision anchoring", function () {
    beforeEach(async function () {
      await c.connect(manager).mintDigitalAsset(user.address, 10, "DOC-10", DID(user.address), HASH, "vault://a");
    });

    it("ANCHOR_ROLE anchors a new hash", async function () {
      await expect(c.connect(manager).updateDigitalAsset(10, HASH2, "vault://b"))
        .to.emit(c, "DigitalAssetUpdated").withArgs(10, HASH, HASH2, "vault://b", manager.address);
      expect((await c.getDigitalAsset(10)).fileHash).to.equal(HASH2);
    });

    it("the token holder cannot anchor a revision (no caller-supplied DID path)", async function () {
      await expect(c.connect(user).updateDigitalAsset(10, HASH2, "x")).to.be.revertedWith(/AccessControl/);
      await expect(c.connect(outsider).updateDigitalAsset(10, HASH2, "x")).to.be.revertedWith(/AccessControl/);
    });

    it("cannot anchor a physical asset or an empty hash", async function () {
      await c.connect(manager).mint(user.address, 11, "PHY-11", "d");
      await expect(c.connect(manager).updateDigitalAsset(11, HASH2, "x")).to.be.revertedWithCustomError(c, "NotDigitalAsset");
      await expect(c.connect(manager).updateDigitalAsset(10, "", "x")).to.be.revertedWithCustomError(c, "EmptyFileHash");
    });
  });

  describe("custody", function () {
    beforeEach(async function () {
      await c.connect(manager).mint(user.address, 20, "PHY-20", DID(user.address));
    });

    it("holders cannot transfer, approve or setApprovalForAll", async function () {
      await expect(c.connect(user).transferFrom(user.address, outsider.address, 20)).to.be.reverted;
      await expect(c.connect(user)["safeTransferFrom(address,address,uint256)"](user.address, outsider.address, 20)).to.be.reverted;
      await expect(c.connect(user).approve(outsider.address, 20)).to.be.revertedWithCustomError(c, "TransfersRestricted");
      await expect(c.connect(user).setApprovalForAll(outsider.address, true)).to.be.revertedWithCustomError(c, "TransfersRestricted");
    });

    it("MANAGER_ROLE transfers custody and rebinds the DID", async function () {
      await expect(c.connect(manager).transferAsset(outsider.address, 20, DID(outsider.address))).to.emit(c, "AssetTransferred");
      expect(await c.ownerOf(20)).to.equal(outsider.address);
      await expect(c.connect(user).transferAsset(user.address, 20, "d")).to.be.revertedWith(/AccessControl/);
    });

    it("only MANAGER_ROLE revokes (burns)", async function () {
      await expect(c.connect(user).revoke(20)).to.be.revertedWith(/AccessControl/);
      await expect(c.connect(manager).revoke(20)).to.emit(c, "AssetRevoked").withArgs(20, "PHY-20");
      expect(await c.getTokenBySerial("PHY-20")).to.equal(0n);
    });
  });

  describe("access mirror and audit records", function () {
    beforeEach(async function () {
      await c.connect(manager).mintDigitalAsset(user.address, 30, "DOC-30", DID(user.address), HASH, "u");
    });

    it("the holder cannot grant itself or others access; MANAGER_ROLE can", async function () {
      await expect(c.connect(user).grantAssetAccess(30, DID(outsider.address), 1)).to.be.revertedWith(/AccessControl/);
      await c.connect(manager).grantAssetAccess(30, DID(outsider.address), 1);
      expect(await c.getAssetPermission(30, DID(outsider.address))).to.equal(1n);
      await expect(c.connect(user).revokeAssetAccess(30, DID(outsider.address))).to.be.revertedWith(/AccessControl/);
    });

    it("arbitrary accounts cannot forge AccessAttempted audit events", async function () {
      await expect(c.connect(outsider).recordAccessAttempt(30, "did:x", true, "fake"))
        .to.be.revertedWithCustomError(c, "AccessControlUnauthorized");
      await expect(c.connect(auditor).recordAccessAttempt(30, "did:x", false, "denied")).to.emit(c, "AccessAttempted");
    });
  });

  describe("role administration and separation of duties", function () {
    it("only the registrar grants operational roles (not the admin, not a manager)", async function () {
      await expect(c.connect(admin).grantRole(MINTER, outsider.address)).to.be.revertedWith(/AccessControl/);
      await expect(c.connect(manager).grantRole(MINTER, outsider.address)).to.be.revertedWith(/AccessControl/);
      await c.connect(registrar).grantRole(MINTER, outsider.address);
      expect(await c.hasRole(MINTER, outsider.address)).to.equal(true);
    });

    it("the registrar and the admin can never hold an operational role", async function () {
      await expect(c.connect(registrar).grantRole(MINTER, registrar.address)).to.be.revertedWithCustomError(c, "SeparationOfDuties");
      await expect(c.connect(registrar).grantRole(MINTER, admin.address)).to.be.revertedWithCustomError(c, "SeparationOfDuties");
      await expect(c.connect(admin).grantRole(REGISTRAR, manager.address)).to.be.revertedWithCustomError(c, "SeparationOfDuties");
    });

    it("only the admin manages the registrar", async function () {
      await expect(c.connect(registrar).grantRole(REGISTRAR, outsider.address)).to.be.revertedWith(/AccessControl/);
      await c.connect(admin).revokeRole(REGISTRAR, registrar.address);
      await expect(c.connect(registrar).grantRole(MINTER, outsider.address)).to.be.revertedWith(/AccessControl/);
    });

    it("the admin can pause minting and anchoring; others cannot", async function () {
      await expect(c.connect(manager).pause()).to.be.revertedWith(/AccessControl/);
      await c.connect(admin).pause();
      await expect(c.connect(manager).mint(user.address, 40, "P40", "d")).to.be.revertedWith("Pausable: paused");
      await c.connect(admin).unpause();
      await c.connect(manager).mint(user.address, 40, "P40", "d");
    });
  });
});
