const hre = require("hardhat");

async function main() {
  const [funder] = await hre.ethers.getSigners();
  const recipient = process.env.FUND_RECIPIENT;

  if (!recipient) {
    console.error("No FUND_RECIPIENT provided");
    process.exit(1);
  }

  console.log(`Funding ${recipient} with 10 LEX from ${funder.address}...`);
  const tx = await funder.sendTransaction({
    to: recipient,
    value: hre.ethers.parseEther("10.0"),
  });
  await tx.wait();
  console.log(`Funded! Tx: ${tx.hash}`);
}

main().catch(console.error);
