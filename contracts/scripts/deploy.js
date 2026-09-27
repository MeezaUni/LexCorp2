// Deploy AssetNFT v3 to the LexCorp Besu network.
//
//   npx hardhat run scripts/deploy.js --network besu
//
// Requires (from ../secrets/chain.env or the environment; never hardcoded):
//   DEPLOYER_PRIVATE_KEY   governance/admin key (becomes DEFAULT_ADMIN_ROLE)
//   REGISTRAR_ADDRESS      backend chain-operator address (becomes REGISTRAR_ROLE)
//
// Refuses to run against any chain other than 13371, and refuses publicly known
// Hardhat/Anvil development accounts as admin or registrar.
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

// Addresses of the well-known Hardhat/Anvil mnemonic ("test test ... junk"), accounts #0-#9.
const PUBLIC_DEV_ADDRESSES = new Set([
  "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
  "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65", "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc",
  "0x976ea74026e726554db657fa54763abd0c3a0aa9", "0x14dc79964da2c08b23698b3d3cc7ca32193d9955",
  "0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f", "0xa0ee7a142d267c1f36714e4a8f75612f20a79720",
]);

async function main() {
  if (hre.network.name !== "besu") throw new Error("Deploy only with --network besu");
  const { chainId } = await hre.ethers.provider.getNetwork();
  if (chainId !== 13371n) throw new Error(`Unexpected chain id ${chainId}; expected 13371`);

  const signers = await hre.ethers.getSigners();
  if (signers.length === 0) throw new Error("DEPLOYER_PRIVATE_KEY is not configured (secrets/chain.env)");
  const deployer = signers[0];
  const registrar = process.env.REGISTRAR_ADDRESS;
  if (!registrar || !hre.ethers.isAddress(registrar)) throw new Error("REGISTRAR_ADDRESS is not configured");
  for (const [label, a] of [["admin", deployer.address], ["registrar", registrar]]) {
    if (PUBLIC_DEV_ADDRESSES.has(a.toLowerCase())) throw new Error(`Refusing publicly known dev account as ${label}`);
  }
  if (deployer.address.toLowerCase() === registrar.toLowerCase()) throw new Error("Admin and registrar must be different keys");

  console.log("Deploying AssetNFT v3; admin:", deployer.address, "registrar:", registrar);
  const F = await hre.ethers.getContractFactory("AssetNFT");
  const c = await F.deploy(deployer.address, registrar, { gasPrice: 0 });
  const tx = c.deploymentTransaction();
  await c.waitForDeployment();
  const receipt = await hre.ethers.provider.getTransactionReceipt(tx.hash);
  if (!receipt || receipt.status !== 1) throw new Error("Deployment transaction failed");
  const address = await c.getAddress();

  const code = await hre.ethers.provider.getCode(address);
  const ADMIN = await c.DEFAULT_ADMIN_ROLE();
  const REGISTRAR = await c.REGISTRAR_ROLE();
  if (!(await c.hasRole(ADMIN, deployer.address)) || !(await c.hasRole(REGISTRAR, registrar))) {
    throw new Error("Role verification failed after deployment");
  }

  const out = {
    address,
    chainId: 13371,
    contractVersion: 3,
    admin: deployer.address,
    registrar,
    deployTxHash: tx.hash,
    deployBlock: receipt.blockNumber,
    runtimeBytecodeKeccak: hre.ethers.keccak256(code),
    deployedAt: new Date().toISOString(),
    abi: JSON.parse(c.interface.formatJson()),
  };
  const dir = path.join(__dirname, "../deployments");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "besu.json"), JSON.stringify(out, null, 2));
  console.log("AssetNFT v3 deployed:", address, "block", receipt.blockNumber, "codehash", out.runtimeBytecodeKeccak);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e.message || e); process.exit(1); });
