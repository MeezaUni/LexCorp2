const hre = require("hardhat");

async function main() {
  const [funder] = await hre.ethers.getSigners();
  const targets = [
    "0x31aac4e1a4dbd3b9792007519c3e8ba6fa6978f0", // Admin
  ];

  for (const target of targets) {
    console.log(`Funding ${target} with 1,000 ETH...`);
    const tx = await funder.sendTransaction({
      to: target,
      value: hre.ethers.parseEther("1000.0"),
    });
    await tx.wait();
    console.log(`Funded! Tx: ${tx.hash}`);
  }
}

main().catch(console.error);
