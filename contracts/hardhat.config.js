require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      evmVersion: "london",
    },
  },
  networks: {
    hardhat: {
      chainId: 13371,
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 13371,
      accounts: [
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // Admin (f39Fd6e51aad88F6F4ce6aB8827279cffFb92266)
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", // User1
        "0x5de4111afa1a4b94908f83103eb2f9580842109d94c804602564c00f8b45479a", // User2
      ],
      gasPrice: "auto",
    },
    besu_consortium: {
      url: "http://127.0.0.1:8545",
      chainId: 13371,
      accounts: [
        // Standard pre-funded development validator/admin keys
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // Admin
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", // User1
        "0x5de4111afa1a4b94908f83103eb2f9580842109d94c804602564c00f8b45479a", // User2
      ],
      gasPrice: "auto",
    },
  },
};
