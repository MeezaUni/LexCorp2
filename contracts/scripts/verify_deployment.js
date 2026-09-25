// Read-only verification of the deployed AssetNFT v3 on Besu. Prints no secrets.
//   npx hardhat run scripts/verify_deployment.js --network besu
const hre = require("hardhat");
const d = require("../deployments/besu.json");

const PUBLIC_DEV_ADDRESSES = [
  "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
  "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65", "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc",
  "0x976ea74026e726554db657fa54763abd0c3a0aa9", "0x14dc79964da2c08b23698b3d3cc7ca32193d9955",
  "0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f", "0xa0ee7a142d267c1f36714e4a8f75612f20a79720",
];

async function main() {
  const p = hre.ethers.provider;
  const checks = [];
  const ok = (name, pass, info = "") => checks.push({ name, pass, info });
  const { chainId } = await p.getNetwork();
  ok("chain id is 13371", chainId === 13371n, String(chainId));
  const code = await p.getCode(d.address);
  ok("contract has code", code !== "0x", `${(code.length - 2) / 2} bytes`);
  ok("runtime bytecode matches deployment record", hre.ethers.keccak256(code) === d.runtimeBytecodeKeccak, d.runtimeBytecodeKeccak);
  const artifact = await hre.artifacts.readArtifact("AssetNFT");
  ok("runtime bytecode matches compiled source", code === artifact.deployedBytecode);
  const c = await hre.ethers.getContractAt("AssetNFT", d.address);
  const roles = {};
  for (const r of ["DEFAULT_ADMIN_ROLE", "REGISTRAR_ROLE", "MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE", "AUDITOR_ROLE"]) roles[r] = await c[r]();
  ok("admin holds DEFAULT_ADMIN_ROLE", await c.hasRole(roles.DEFAULT_ADMIN_ROLE, d.admin), d.admin);
  ok("registrar holds REGISTRAR_ROLE", await c.hasRole(roles.REGISTRAR_ROLE, d.registrar), d.registrar);
  for (const r of ["MINTER_ROLE", "ANCHOR_ROLE", "MANAGER_ROLE"]) {
    ok(`registrar does not hold ${r}`, !(await c.hasRole(roles[r], d.registrar)));
    ok(`admin does not hold ${r}`, !(await c.hasRole(roles[r], d.admin)));
  }
  let devHasRole = false;
  for (const a of PUBLIC_DEV_ADDRESSES) for (const r of Object.values(roles)) if (await c.hasRole(r, a)) devHasRole = true;
  ok("no publicly known dev account holds any role", !devHasRole);
  const rcpt = await p.getTransactionReceipt(d.deployTxHash);
  ok("deployment receipt succeeded", !!rcpt && rcpt.status === 1 && rcpt.contractAddress === d.address, d.deployTxHash);
  for (const x of checks) console.log(`${x.pass ? "PASS" : "FAIL"}  ${x.name}${x.info ? "  (" + x.info + ")" : ""}`);
  if (checks.some((x) => !x.pass)) process.exit(1);
}

main().catch((e) => { console.error(e.message || e); process.exit(1); });
