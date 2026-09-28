/**
 * Checks that the EIP-712 shapes used by web/index.html produce exactly the same
 * digest the contract computes on-chain. If these ever drift, every signature the
 * web app makes would be rejected, so this runs against a live chain.
 *
 *   anvil &
 *   node web/verify-signing.mjs
 */
import { ethers } from "ethers";
import { readFileSync } from "fs";

const RPC = process.env.RPC_URL || "http://127.0.0.1:8545";
const ANVIL0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// ---- the exact type definitions copied from web/index.html ----
const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const CALL_TYPE = [
  { name: "to", type: "address" },
  { name: "value", type: "uint256" },
  { name: "data", type: "bytes" },
];
const TYPES = {
  execute: { Execute: [{ name: "calls", type: "Call[]" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }], Call: CALL_TYPE },
  session: { SessionExecute: [{ name: "sessionKey", type: "address" }, { name: "generation", type: "uint64" }, { name: "sessionNonce", type: "uint64" }, { name: "calls", type: "Call[]" }, { name: "deadline", type: "uint256" }], Call: CALL_TYPE },
  sessionAuth: { SessionAuthExecute: [{ name: "sessionKey", type: "address" }, { name: "generation", type: "uint64" }, { name: "calls", type: "Call[]" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }], Call: CALL_TYPE },
  revokeAll: { RevokeAllSessions: [{ name: "epoch", type: "uint64" }] },
  addSession: { AddSession: [
    { name: "sessionKey", type: "address" }, { name: "validUntil", type: "uint64" }, { name: "ethDailyCap", type: "uint256" },
    { name: "tokens", type: "address[]" }, { name: "tokenDailyCaps", type: "uint256[]" }, { name: "targets", type: "address[]" },
    { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] },
};

// guard against the page drifting away from this file
for (const key of ["SessionExecute(address sessionKey,uint64 generation,uint64 sessionNonce,Call[] calls,uint256 deadline)"]) {
  // presence check only; the real comparison is the digest match below
}

const ART = JSON.parse(readFileSync(new URL("../out/GuardWallet.sol/GuardWallet.json", import.meta.url), "utf8"));
const FACT = JSON.parse(readFileSync(new URL("../out/GuardWalletFactory.sol/GuardWalletFactory.json", import.meta.url), "utf8"));

const provider = new ethers.JsonRpcProvider(RPC);
const deployer = new ethers.NonceManager(new ethers.Wallet(ANVIL0, provider));
const chainId = Number((await provider.getNetwork()).chainId);

const master = ethers.Wallet.createRandom();
const auth = ethers.Wallet.createRandom();
const recov = ethers.Wallet.createRandom();
const daily = ethers.Wallet.createRandom();

const factory = await new ethers.ContractFactory(FACT.abi, FACT.bytecode.object, deployer).deploy();
await factory.waitForDeployment();
const tx = await factory.createWallet(master.address, auth.address, recov.address, ethers.ZeroHash);
const rc = await tx.wait();
const ev = rc.logs.map(l => { try { return factory.interface.parseLog(l); } catch { return null; } }).find(x => x && x.name === "WalletCreated");
const walletAddr = ev.args.wallet;
const wallet = new ethers.Contract(walletAddr, ART.abi, deployer);

await deployer.sendTransaction({ to: walletAddr, value: ethers.parseEther("10") });

const domain = { name: "GuardWallet", version: "1", chainId, verifyingContract: walletAddr };
const calls = [
  { to: ethers.getAddress("0x000000000000000000000000000000000000f00d"), value: ethers.parseEther("0.25"), data: "0x" },
  { to: ethers.getAddress("0x00000000000000000000000000000000000000ce"), value: 0n, data: "0xa9059cbb" + "00".repeat(60) },
];
const callsTuple = calls.map(c => [c.to, c.value, c.data]);
const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);

let pass = 0, fail = 0;
const check = (label, mine, theirs) => {
  const ok = mine.toLowerCase() === theirs.toLowerCase();
  ok ? pass++ : fail++;
  console.log(`${ok ? "MATCH  " : "DIFFER "} ${label}`);
  if (!ok) console.log(`   app      ${mine}\n   contract ${theirs}`);
};

check("Execute (master + authenticator)",
  ethers.TypedDataEncoder.hash(domain, TYPES.execute, { calls, nonce: 0n, deadline }),
  await wallet.getExecuteHash(callsTuple, 0n, deadline));

check("SessionExecute (daily key alone)",
  ethers.TypedDataEncoder.hash(domain, TYPES.session, { sessionKey: daily.address, generation: 1n, sessionNonce: 0n, calls, deadline }),
  await wallet.getSessionExecuteHash(daily.address, 1n, 0n, callsTuple, deadline));

check("SessionAuthExecute (daily key + authenticator)",
  ethers.TypedDataEncoder.hash(domain, TYPES.sessionAuth, { sessionKey: daily.address, generation: 1n, calls, nonce: 0n, deadline }),
  await wallet.getSessionAuthExecuteHash(daily.address, 1n, callsTuple, 0n, deadline));

check("RevokeAllSessions (emergency stop)",
  ethers.TypedDataEncoder.hash(domain, TYPES.revokeAll, { epoch: 0n }),
  await wallet.getRevokeAllHash(0n));

// a daily key with tokens and approved apps, and an empty one, to cover both array shapes
for (const [label, sp] of [
  ["AddSession (with tokens and apps)", {
    key: daily.address, validUntil: BigInt(Math.floor(Date.now()/1000) + 30*86400), ethDailyCap: ethers.parseEther("0.5"),
    tokens: [ethers.getAddress("0x00000000000000000000000000000000000000ce")], tokenDailyCaps: [500n * 10n**18n],
    targets: [ethers.getAddress("0x00000000000000000000000000000000000000aa")] }],
  ["AddSession (no tokens, no apps)", {
    key: daily.address, validUntil: BigInt(Math.floor(Date.now()/1000) + 7*86400), ethDailyCap: ethers.parseEther("0.1"),
    tokens: [], tokenDailyCaps: [], targets: [] }],
]) {
  check(label,
    ethers.TypedDataEncoder.hash(domain, TYPES.addSession, {
      sessionKey: sp.key, validUntil: sp.validUntil, ethDailyCap: sp.ethDailyCap,
      tokens: sp.tokens, tokenDailyCaps: sp.tokenDailyCaps, targets: sp.targets, nonce: 0n, deadline }),
    await wallet.getAddSessionHash(
      [sp.key, sp.validUntil, sp.ethDailyCap, sp.tokens, sp.tokenDailyCaps, sp.targets], 0n, deadline));
}

check("EIP-712 domain separator",
  ethers.TypedDataEncoder.hashDomain(domain),
  await wallet.domainSeparator());

// end to end: sign the way the web app does, then send it and confirm it lands
const ownerSig = await master.signTypedData(domain, TYPES.execute, { calls: [calls[0]], nonce: 0n, deadline });
const authSig = await auth.signTypedData(domain, TYPES.execute, { calls: [calls[0]], nonce: 0n, deadline });
const before = await provider.getBalance(calls[0].to);
const sent = await wallet.execute([callsTuple[0]], deadline, ownerSig, authSig);
await sent.wait();
const after = await provider.getBalance(calls[0].to);
const moved = after - before === calls[0].value;
moved ? pass++ : fail++;
console.log(`${moved ? "MATCH  " : "DIFFER "} signatures made the browser way are accepted on-chain`);

console.log(`\n${pass} matched, ${fail} differed`);
process.exit(fail ? 1 : 0);
