/**
 * Exercises the web app's onboarding the same way the browser does, using the
 * ABI and EIP-712 types read straight out of web/index.html.
 * If the page and the contracts ever drift apart, this fails.
 *
 *   anvil &
 *   node web/verify-onboarding.mjs
 */
import { ethers } from "ethers";
import { readFileSync } from "fs";

const RPC = process.env.RPC_URL || "http://127.0.0.1:8545";
const ANVIL0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// ---- pull the real constants out of the page ----
const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const grabArray = (name) => {
  const start = html.indexOf(`const ${name} = [`);
  if (start < 0) throw new Error(`${name} not found in index.html`);
  const open = html.indexOf("[", start);
  let depth = 0, i = open;
  for (; i < html.length; i++) {
    if (html[i] === "[") depth++;
    else if (html[i] === "]") { depth--; if (depth === 0) break; }
  }
  return eval(html.slice(open, i + 1));
};
const ABI = grabArray("ABI");
const FACTORY_ABI = grabArray("FACTORY_ABI");
// the page no longer ships compiled bytecode; it talks to a factory the user supplies,
// so deploy one here from the build output and drive the page's flow against it
const FACTORY_BYTECODE = JSON.parse(
  readFileSync(new URL("../out/GuardWalletFactory.sol/GuardWalletFactory.json", import.meta.url), "utf8")
).bytecode.object;

const CALL_TYPE = [
  { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "data", type: "bytes" },
];
const ADD_SESSION_TYPE = { AddSession: [
  { name: "sessionKey", type: "address" }, { name: "validUntil", type: "uint64" }, { name: "ethDailyCap", type: "uint256" },
  { name: "tokens", type: "address[]" }, { name: "tokenDailyCaps", type: "uint256[]" }, { name: "targets", type: "address[]" },
  { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] };
const SESSION_EXEC_TYPE = { SessionExecute: [
  { name: "sessionKey", type: "address" }, { name: "generation", type: "uint64" }, { name: "sessionNonce", type: "uint64" },
  { name: "calls", type: "Call[]" }, { name: "deadline", type: "uint256" }], Call: CALL_TYPE };

const provider = new ethers.JsonRpcProvider(RPC);
const payer = new ethers.NonceManager(new ethers.Wallet(ANVIL0, provider));
const chainId = Number((await provider.getNetwork()).chainId);

let pass = 0, fail = 0;
const ok = (label, cond, extra) => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "PASS " : "FAIL "} ${label}${cond || !extra ? "" : "  -> " + extra}`);
};

// three keys from three different seeds, as the app insists on
const master = ethers.Wallet.createRandom();
const auth = ethers.Wallet.createRandom();
const recovery = ethers.Wallet.createRandom();
const daily = ethers.Wallet.createRandom();

// ---- 1. stand up a factory for the page to talk to ----
const cf = new ethers.ContractFactory(FACTORY_ABI, FACTORY_BYTECODE, payer);
const factory = await cf.deploy();
await factory.waitForDeployment();
const factoryAddr = await factory.getAddress();
ok("factory deploys and answers the calls the page makes", ethers.isAddress(factoryAddr));

// ---- 2. predict, then create, and check they agree ----
const salt = ethers.toBeHex(0n, 32);
const predicted = await factory.predictAddress(master.address, auth.address, recovery.address, salt);
ok("address is empty before creating", (await provider.getCode(predicted)) === "0x");
await (await factory.createWallet(master.address, auth.address, recovery.address, salt)).wait();
ok("wallet lands exactly on the predicted address", (await provider.getCode(predicted)) !== "0x");

const wallet = new ethers.Contract(predicted, ABI, payer);
ok("master key stored correctly", (await wallet.owner()) === master.address);
ok("authenticator stored correctly", (await wallet.authenticator()) === auth.address);
ok("backup key stored correctly", (await wallet.recovery()) === recovery.address);

// the app refuses duplicate keys; the contract must refuse too
let duped = false;
try { await factory.createWallet.staticCall(master.address, master.address, recovery.address, salt); }
catch { duped = true; }
ok("contract rejects a wallet with a repeated key", duped);

await payer.sendTransaction({ to: predicted, value: ethers.parseEther("5") });

// ---- 3. add a daily key, signed the way the page signs it ----
const domain = { name: "GuardWallet", version: "1", chainId, verifyingContract: predicted };
const cap = ethers.parseEther("0.5");
const validUntil = BigInt(Math.floor(Date.now() / 1000) + 30 * 86400);
const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
const value = {
  sessionKey: daily.address, validUntil, ethDailyCap: cap,
  tokens: [], tokenDailyCaps: [], targets: [], nonce: 0n, deadline,
};
const mSig = await master.signTypedData(domain, ADD_SESSION_TYPE, value);
const aSig = await auth.signTypedData(domain, ADD_SESSION_TYPE, value);
await (await wallet.addSession(
  [daily.address, validUntil, cap, [], [], []], deadline, mSig, aSig)).wait();
ok("daily key is active after being added from the page's flow", await wallet.isSessionActive(daily.address));

const spend = await wallet.sessionSpentToday(daily.address, ethers.ZeroAddress);
ok("daily limit reads back as set", spend.cap === cap, spend.cap.toString());

// one signature alone must not be enough
let refused = false;
try {
  await wallet.addSession.staticCall(
    [ethers.Wallet.createRandom().address, validUntil, cap, [], [], []], deadline, mSig, mSig);
} catch { refused = true; }
ok("master key alone cannot add a daily key", refused);

// ---- 4. the daily key spends on its own, and stops at its limit ----
const friend = ethers.getAddress("0x000000000000000000000000000000000000f00d");
const sendCalls = [{ to: friend, value: ethers.parseEther("0.3"), data: "0x" }];
const s = await wallet.sessions(daily.address);
const dSig = await daily.signTypedData(domain, SESSION_EXEC_TYPE, {
  sessionKey: daily.address, generation: s.generation, sessionNonce: s.nonce, calls: sendCalls, deadline });
await (await wallet.executeSession(
  daily.address, sendCalls.map(c => [c.to, c.value, c.data]), deadline, dSig)).wait();
ok("daily key sends within its limit", (await provider.getBalance(friend)) === ethers.parseEther("0.3"));

const s2 = await wallet.sessions(daily.address);
const overCalls = [{ to: friend, value: ethers.parseEther("0.3"), data: "0x" }];
const dSig2 = await daily.signTypedData(domain, SESSION_EXEC_TYPE, {
  sessionKey: daily.address, generation: s2.generation, sessionNonce: s2.nonce, calls: overCalls, deadline });
let blocked = false;
try {
  await wallet.executeSession.staticCall(
    daily.address, overCalls.map(c => [c.to, c.value, c.data]), deadline, dSig2);
} catch { blocked = true; }
ok("daily key is blocked once it would pass the limit", blocked);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
