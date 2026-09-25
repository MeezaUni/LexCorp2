require("@nomicfoundation/hardhat-toolbox");
const fs = require("fs");
const path = require("path");

// Deployment credentials come ONLY from the environment or from the git-ignored
// ../secrets/chain.env (created by `python scripts/init_secrets.py`). No private key
// is ever written in this file. The in-process `hardhat` network used by unit tests
// runs on Hardhat's throw-away accounts and never touches Besu.
function loadSecretsFile() {
  const file = path.join(__dirname, "..", "secrets", "chain.env");
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
}
loadSecretsFile();

const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "london",
    },
  },
  networks: {
    hardhat: { chainId: 13371 },
    besu: {
      url: process.env.BESU_RPC_URL || "http://127.0.0.1:8545",
      chainId: 13371,
      accounts: deployerKey ? [deployerKey] : [],
      gasPrice: 0,
    },
  },
};
