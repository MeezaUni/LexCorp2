async function main() {
  const signers = await ethers.getSigners();
  signers.forEach((s, i) => console.log(i, s.address));
}
main();
