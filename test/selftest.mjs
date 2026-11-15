// SPDX-License-Identifier: MIT
// Self-test: starts the server on a test port with a test HMAC secret and
// strategy salt, then exercises preflight, HMAC rejection, every Gatekeeper
// trap + boundaries, idempotency, and Steal turns (EXTRACT/FORTIFY/HOLD,
// wrong commitment, replay). Every proof is verified locally with snarkjs.
// Exits 0 only if ALL checks pass. (snarkjs worker threads keep the Node
// event loop alive, so the process exits explicitly at the end.)
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as snarkjs from "snarkjs";
import { signBody, verifyBody } from "../src/hmac.mjs";
import { computeCommitment, DEFAULT_STRATEGY_PARAMS } from "../src/strategy.mjs";
import { publicInputsHash } from "../src/steal.mjs";
import { circuitPaths, exportVk } from "../src/circuits.mjs";

const PORT = 3456;
const BASE = `http://127.0.0.1:${PORT}`;
const TEST_SECRET = "test-secret-" + randomBytes(8).toString("hex");
const TEST_SALT = randomBytes(16).toString("hex");

let passed = 0;
let failed = 0;
const proofTimes = [];
function check(name, ok, detail = "") {
  if (ok) { passed++; console.log(`  PASS ${name}${detail ? " — " + detail : ""}`); }
  else { failed++; console.log(`  FAIL ${name}${detail ? " — " + detail : ""}`); }
}

async function post(path, obj, { sign = true, badSig = false } = {}) {
  const body = JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (sign) {
    headers["x-agent-games-signature"] = badSig ? "deadbeef" : signBody(TEST_SECRET, body);
  }
  const res = await fetch(BASE + path, { method: "POST", headers, body });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep null */ }
  return { status: res.status, json, text, sig: res.headers.get("x-agent-games-signature") };
}

async function waitHealth() {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(BASE + "/health");
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

async function main() {
  const serverLog = [];
  const child = spawn("node", ["src/server.mjs"], {
    cwd: new URL("..", import.meta.url).pathname,
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      STRATEGY_SALT: TEST_SALT,
      CIRCUITS_DIR: new URL("../circuits", import.meta.url).pathname,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (d) => serverLog.push(d.toString()));
  child.stderr.on("data", (d) => serverLog.push("[stderr] " + d.toString()));

  const up = await waitHealth();
  check("server starts + /health ok", up);
  if (!up) {
    console.log(serverLog.join("").slice(-3000));
    process.exit(1);
  }

  const gkVk = await exportVk("gatekeeper");
  const vfyVk = await exportVk("vfyPolicy");
  const commitment = await computeCommitment(DEFAULT_STRATEGY_PARAMS, TEST_SALT);

  // ---- 1. preflight ----
  console.log("\n[preflight]");
  const pre = await post("/", { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  check("signed preflight → 200 {ok:true, protocolVersion:v1}", pre.status === 200 && pre.json?.ok === true && pre.json?.protocolVersion === "v1");
  check("preflight response is HMAC-signed", typeof pre.sig === "string" && verifyBody(TEST_SECRET, pre.text, pre.sig));

  // ---- 2. HMAC rejection ----
  console.log("\n[hmac]");
  const unsigned = await post("/", { type: "agent-games.preflight.v1" }, { sign: false });
  check("unsigned request → 401", unsigned.status === 401);
  const bad = await post("/", { type: "agent-games.preflight.v1" }, { badSig: true });
  check("bad signature → 401", bad.status === 401);

  // ---- 3. Gatekeeper ----
  console.log("\n[gatekeeper]");
  const baseInput = {
    registered_vk: "0x7d00000000000000000000000000000000000000000000000000000000000091",
    proof_vk: "0x7d00000000000000000000000000000000000000000000000000000000000091",
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: "0xDe4200000000000000000000000000000000009f01",
    condition_recipient: "0xDe4200000000000000000000000000000000009f01",
    amount: "500",
    max_transfer: "1000",
    proof_tx: "0xa80000000000000000000000000000000000000000000000000000000000002c",
  };
  const gkEnv = (taskId, input) => ({
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input,
  });

  async function gkCase(name, taskId, input, wantDecision, wantReason, wantProof) {
    const t0 = Date.now();
    const r = await post("/", gkEnv(taskId, input));
    const ms = Date.now() - t0;
    const okShape = r.status === 200 && r.json?.decision === wantDecision && r.json?.reason_code === wantReason;
    check(`${name} → ${wantDecision}/${wantReason}`, okShape, `HTTP ${r.status}, got ${r.json?.decision}/${r.json?.reason_code}`);
    if (wantProof) {
      const hasProof = Boolean(r.json?.proof && Array.isArray(r.json?.public_signals) && r.json.public_signals.length === 13);
      check(`${name} proof present (13 signals)`, hasProof);
      if (hasProof) {
        const valid = await snarkjs.groth16.verify(gkVk, r.json.public_signals, r.json.proof);
        check(`${name} proof verifies locally`, valid);
        proofTimes.push({ case: name, ms });
        console.log(`    proof gen+roundtrip: ${ms}ms`);
      }
    } else {
      check(`${name} carries no proof`, !r.json?.proof);
    }
    return r;
  }

  const valid = await gkCase("VALID", "gk_test_valid_1", baseInput, "APPROVE", "VALID_CONDITION", true);
  await gkCase("VK_SUBSTITUTION", "gk_test_trap_vk", { ...baseInput, proof_vk: "0x13000000000000000000000000000000000000000000000000000000000000aa", proof_tx: "0xb100000000000000000000000000000000000000000000000000000000000001" }, "REJECT", "VK_SUBSTITUTION", true);
  await gkCase("PROOF_REUSED", "gk_test_trap_reused", { ...baseInput }, "REJECT", "PROOF_REUSED", false);
  await gkCase("THRESHOLD_MISMATCH", "gk_test_trap_threshold", { ...baseInput, public_balance: "999", proof_tx: "0xb200000000000000000000000000000000000000000000000000000000000002" }, "REJECT", "THRESHOLD_MISMATCH", true);
  await gkCase("EXPIRED (current==expiry)", "gk_test_trap_expired", { ...baseInput, current_block: 8430000, proof_tx: "0xb300000000000000000000000000000000000000000000000000000000000003" }, "REJECT", "EXPIRED_CONDITION", true);
  await gkCase("RECIPIENT_MISMATCH", "gk_test_trap_recipient", { ...baseInput, condition_recipient: "0xDe4200000000000000000000000000000000009f02", proof_tx: "0xb400000000000000000000000000000000000000000000000000000000000004" }, "REJECT", "RECIPIENT_MISMATCH", true);
  await gkCase("AMOUNT_OVERFLOW", "gk_test_trap_amount", { ...baseInput, amount: "1001", proof_tx: "0xb500000000000000000000000000000000000000000000000000000000000005" }, "REJECT", "AMOUNT_OVERFLOW", true);
  await gkCase("BOUNDARY balance==minimum", "gk_test_bound_balance", { ...baseInput, public_balance: "1000", proof_tx: "0xb600000000000000000000000000000000000000000000000000000000000006" }, "APPROVE", "VALID_CONDITION", true);
  await gkCase("BOUNDARY amount==max", "gk_test_bound_amount", { ...baseInput, amount: "1000", proof_tx: "0xb700000000000000000000000000000000000000000000000000000000000007" }, "APPROVE", "VALID_CONDITION", true);

  // idempotency: resend the VALID task → identical body
  const replay = await post("/", gkEnv("gk_test_valid_1", baseInput));
  check("gatekeeper retry (same task_id) → identical response", replay.text === valid.text);
  check("gatekeeper response is HMAC-signed", typeof valid.sig === "string" && verifyBody(TEST_SECRET, valid.text, valid.sig));

  // ---- 4. Steal the VFY ----
  console.log("\n[steal]");
  const matchId = "9f4e1b2a-1111-2222-3333-444455556666";
  const stealEnv = (turn, selfBalance, opponentBalance, commit = commitment) => ({
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    mode: "competition",
    matchId,
    turn,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 300000).toISOString(),
    state: { selfBalance, opponentBalance, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: commit },
    resolverVersion: "v1",
    nonce: `nonce-${turn}`,
  });

  async function stealCase(name, turn, selfBalance, opponentBalance, wantAction, wantAmount) {
    const t0 = Date.now();
    const r = await post("/", stealEnv(turn, selfBalance, opponentBalance));
    const ms = Date.now() - t0;
    const actionOk = r.status === 200 && r.json?.action?.type === wantAction
      && (wantAmount === undefined ? !("amount" in (r.json?.action || {})) : r.json?.action?.amount === wantAmount);
    check(`${name} → action ${wantAction}${wantAmount !== undefined ? " " + wantAmount : ""}`, actionOk, `got ${JSON.stringify(r.json?.action)}`);
    check(`${name} echoes matchId+turn`, r.json?.matchId === matchId && r.json?.turn === turn);
    const pp = r.json?.policyProof || {};
    const nested = Boolean(pp.proof && Array.isArray(pp.public_signals) && pp.public_signals.length === 9);
    check(`${name} proof INSIDE policyProof (9 signals)`, nested);
    check(`${name} no top-level proof/public_signals`, !("proof" in (r.json || {})) && !("public_signals" in (r.json || {})));
    if (nested) {
      const validProof = await snarkjs.groth16.verify(vfyVk, pp.public_signals, pp.proof);
      check(`${name} proof verifies locally`, validProof);
      const recomputed = publicInputsHash({
        commitment, matchId, turn, selfBalance, opponentBalance,
        action: wantAction, amount: wantAmount || 0,
      });
      check(`${name} publicInputsHash matches recomputation`, pp.publicInputsHash === recomputed);
      proofTimes.push({ case: name, ms });
      console.log(`    proof gen+roundtrip: ${ms}ms`);
    }
    check(`${name} response is HMAC-signed`, typeof r.sig === "string" && verifyBody(TEST_SECRET, r.text, r.sig));
    return r;
  }

  const extract = await stealCase("EXTRACT (95 vs 105)", 3, "95", "105", "EXTRACT", 5);
  await stealCase("FORTIFY (40 vs 105)", 4, "40", "105", "FORTIFY", undefined);
  await stealCase("HOLD (95 vs 0)", 5, "95", "0", "HOLD", undefined);

  // wrong commitment → HOLD without proof
  const wrong = await post("/", stealEnv(6, "95", "105", "0x1234"));
  check("wrong commitment → HOLD without proof", wrong.json?.action?.type === "HOLD" && !wrong.json?.policyProof?.proof);

  // replay → identical body
  const stealReplay = await post("/", stealEnv(3, "95", "105"));
  check("steal replay (same matchId:turn) → identical response", stealReplay.text === extract.text);

  // ---- summary ----
  console.log(`\n==== self-test: ${passed} passed, ${failed} failed ====`);
  console.log("proof times (ms, incl. HTTP roundtrip):", JSON.stringify(proofTimes));
  child.kill("SIGTERM");
  setTimeout(() => process.exit(failed ? 1 : 0), 500);
}

main().catch((e) => {
  console.error("self-test crashed:", e);
  process.exit(1);
});
