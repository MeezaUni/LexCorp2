// Hand REGISTRAR_ROLE from the recorded registrar to a new chain-operator address.
// Signed by the governance key (DEFAULT_ADMIN_ROLE). Prints only public addresses.
//   REGISTRAR_ADDRESS=<new> npx hardhat run scripts/rotate_registrar.js --network besu
// (REGISTRAR_ADDRESS is read from ../secrets/chain.env after `init_secrets.py --rotate CHAIN_OPERATOR_PRIVATE_KEY`.)
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const file = path.join(__dirname, "../deployments/besu.json");
  const d = JSON.parse(fs.readFileSync(file, "utf8"));
  const next = process.env.REGISTRAR_ADDRESS;
  if (!next || !hre.ethers.isAddress(next)) throw new Error("REGISTRAR_ADDRESS is not configured");
  const [admin] = await hre.ethers.getSigners();
  const c = await hre.ethers.getContractAt("AssetNFT", d.address, admin);
  const ROLE = await c.REGISTRAR_ROLE();
  if (!(await c.hasRole(await c.DEFAULT_ADMIN_ROLE(), admin.address))) throw new Error("Signer is not the governance admin");
  const prev = d.registrar;
  if (prev.toLowerCase() === next.toLowerCase()) { console.log("Registrar unchanged"); return; }

  if (!(await c.hasRole(ROLE, next))) await (await c.grantRole(ROLE, next, { gasPrice: 0 })).wait();
  if (await c.hasRole(ROLE, prev)) await (await c.revokeRole(ROLE, prev, { gasPrice: 0 })).wait();
  if (!(await c.hasRole(ROLE, next)) || (await c.hasRole(ROLE, prev))) throw new Error("Registrar rotation did not converge");

  d.registrar = next;
  d.registrarRotatedAt = new Date().toISOString();
  fs.writeFileSync(file, JSON.stringify(d, null, 2));
  console.log(`REGISTRAR_ROLE moved from ${prev} to ${next}`);
}

main().then(() => process.exit(0)).catch((e) => { console.error(e.message || e); process.exit(1); });
