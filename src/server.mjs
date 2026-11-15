// SPDX-License-Identifier: MIT
// lacrade — zkVerify Agent Games agent (Proof Gatekeeper + Steal the VFY).
// Protocol: ~/workspace/zkverify-agent-games/protocol.md (OFFICIAL wins over REF).
//
// One HTTP endpoint (PORT, default 3000) handling:
//   - agent-games.preflight.v1  → {"ok":true,"protocolVersion":"v1"} (signed)
//   - agent-games.proof-gatekeeper.v1 → decision + Groth16 proof (top level)
//   - steal-the-vfy turn envelopes  → action + policy proof INSIDE policyProof
//   - GET /health → operator readiness (NOT called by the platform)
//
// Auth: x-agent-games-signature, HMAC-SHA256 over the raw body, secret from
// env AGENT_GAMES_HMAC_SECRET. If the secret is NOT set, the server starts in
// a clearly-marked "no secret configured" dev mode: requests are accepted
// without verification and responses are UNSIGNED. NEVER go live like that.
// Secrets, salts and strategy params are never logged.
import http from "node:http";
import { randomUUID } from "node:crypto";
import { signBody, verifyBody } from "./hmac.mjs";
import { assertCircuitsPresent, circuitsPresent, CIRCUITS } from "./circuits.mjs";
import {
  decideGatekeeper, validateGatekeeperInput, proveGatekeeper, REASON_CODES,
} from "./gatekeeper.mjs";
import { publicInputsHash, proveSteal, CIRCUIT_VERSION } from "./steal.mjs";
import {
  decideAction, loadStrategyParams, validateStrategyParams, computeCommitment,
} from "./strategy.mjs";
import { isConfigured as kurierConfigured, registerVk, submitProofBestEffort } from "./kurier.mjs";

const PORT = Number(process.env.PORT || 3000);
const AGENT_ID = process.env.AGENT_ID || "lacrade";
const MAX_BODY_BYTES = 1024 * 1024;

// ---------------------------------------------------------------- logging
function log(level, event, fields = {}) {
  const line = { ts: new Date().toISOString(), level, event, ...fields };
  process.stdout.write(JSON.stringify(line) + "\n");
}

// ---------------------------------------------------------------- state
const hmacSecret = process.env.AGENT_GAMES_HMAC_SECRET || null;
const noSecretMode = !hmacSecret;
const seenProofTx = new Map(); // proof_tx -> task_id (Gatekeeper trap #2)
const gatekeeperCache = new Map(); // task_id -> { status, body }
const stealCache = new Map(); // `${matchId}:${turn}` -> { status, body }
const stealNonces = new Map(); // nonce -> `${matchId}:${turn}`

let strategyParams = null;
let strategySaltHex = null;
let strategyCommitment = null; // decimal string
let strategyReady = false;

async function initStrategy() {
  try {
    strategyParams = loadStrategyParams();
    validateStrategyParams(strategyParams);
  } catch (e) {
    log("error", "strategy params invalid", { error: String(e.message).slice(0, 200) });
    process.exit(1);
  }
  strategySaltHex = (process.env.STRATEGY_SALT || "").replace(/^0x/, "") || null;
  const envCommitment = process.env.STRATEGY_COMMITMENT_HASH || null;
  if (strategySaltHex) {
    strategyCommitment = await computeCommitment(strategyParams, strategySaltHex);
    strategyReady = true;
    if (envCommitment && envCommitment !== strategyCommitment) {
      log("error", "STRATEGY_COMMITMENT_HASH does not match params+salt — re-register the computed hash in the dashboard", {});
    }
    log("info", "strategy ready", { commitment: strategyCommitment });
  } else if (envCommitment) {
    strategyCommitment = envCommitment;
    log("warn", "STRATEGY_SALT not set — Steal the VFY will answer HOLD without proof (fail closed)", {});
  } else {
    log("warn", "no strategy salt or commitment configured — Steal the VFY will answer HOLD without proof", {});
  }
}

// ---------------------------------------------------------------- responses
function sendJson(res, status, obj, sign = true) {
  const body = JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (sign && hmacSecret) headers["x-agent-games-signature"] = signBody(hmacSecret, body);
  res.writeHead(status, headers);
  res.end(body);
  return body;
}

function holdWithoutProof(matchId, turn, note) {
  return {
    matchId,
    turn,
    action: { type: "HOLD" },
    policyProof: { circuitVersion: CIRCUIT_VERSION },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: randomUUID(),
    _note: note, // stripped before sending; internal only
  };
}

// ---------------------------------------------------------------- handlers
async function handlePreflight(body) {
  return { status: 200, obj: { ok: true, protocolVersion: "v1" } };
}

async function handleGatekeeper(envelope) {
  const taskId = envelope.task_id;
  if (typeof taskId === "string" && gatekeeperCache.has(taskId)) {
    log("info", "gatekeeper retry (cached)", { task_id: taskId });
    return gatekeeperCache.get(taskId);
  }
  const input = envelope.input || {};
  const validationError = validateGatekeeperInput(input);
  if (!taskId || validationError) {
    const obj = {
      decision: "REJECT",
      reason_code: REASON_CODES.INVALID_TASK,
      proof_tx: typeof input.proof_tx === "string" ? input.proof_tx : "",
    };
    log("warn", "gatekeeper invalid task", { task_id: taskId || null, error: validationError });
    return { status: 200, obj };
  }

  const { decision, reason_code } = decideGatekeeper(input, (proofTx) => {
    const seen = seenProofTx.get(proofTx);
    return seen !== undefined && seen !== taskId;
  });
  // Record the proof reference AFTER the reuse check (a retry of the same
  // task_id never reaches here — it is served from the cache above).
  seenProofTx.set(input.proof_tx, taskId);

  const obj = { decision, reason_code, proof_tx: input.proof_tx };

  if (reason_code !== REASON_CODES.PROOF_REUSED) {
    try {
      const { proof, publicSignals, ms } = await proveGatekeeper(input, taskId, decision);
      obj.proof = proof;
      obj.public_signals = publicSignals;
      log("info", "gatekeeper proof generated", { task_id: taskId, decision, reason_code, proof_ms: ms });
      // Kurier (optional, best-effort, bounded) — fire-and-forget pointer only.
      if (kurierConfigured()) {
        submitProofBestEffort("gatekeeper", proof, publicSignals, 20000, log).catch(() => {});
      }
    } catch (e) {
      // Fail closed: return the decision WITHOUT a proof rather than crashing.
      log("error", "gatekeeper proof failed — returning decision without proof", {
        task_id: taskId, decision, reason_code, error: String(e?.message || e).slice(0, 300),
      });
    }
  } else {
    log("info", "gatekeeper PROOF_REUSED — no proof attached", { task_id: taskId });
  }

  const result = { status: 200, obj };
  gatekeeperCache.set(taskId, result);
  return result;
}

async function handleSteal(envelope) {
  const matchId = envelope.matchId;
  const turn = envelope.turn;
  const key = `${matchId}:${turn}`;
  if (stealCache.has(key)) {
    log("info", "steal replay (cached)", { match_id: matchId, turn });
    return stealCache.get(key);
  }

  const state = envelope.state || {};
  const failHold = (note) => {
    const obj = holdWithoutProof(matchId, turn, note);
    delete obj._note;
    log("warn", "steal HOLD without proof", { match_id: matchId, turn, note });
    const result = { status: 200, obj };
    stealCache.set(key, result);
    return result;
  };

  if (typeof matchId !== "string" || typeof turn !== "number" || !state
      || typeof state.selfBalance !== "string" || typeof state.opponentBalance !== "string") {
    return { status: 400, obj: { error: "malformed turn envelope" } };
  }
  // Expired turn (OFFICIAL guidance: reject expired nonces/deadlines).
  if (envelope.deadlineAt && Date.now() > new Date(envelope.deadlineAt).getTime()) {
    return failHold("past deadlineAt");
  }
  if (typeof envelope.nonce === "string") {
    const prev = stealNonces.get(envelope.nonce);
    if (prev && prev !== key) return failHold("nonce reused for a different turn");
    stealNonces.set(envelope.nonce, key);
  }
  // Commitment must match the registered one, else HOLD without proof.
  const envCommitment = envelope.strategyCommitment?.hash;
  if (!strategyCommitment || !envCommitment
      || String(envCommitment).toLowerCase() !== String(strategyCommitment).toLowerCase()) {
    return failHold("strategy commitment mismatch or not configured");
  }
  if (!strategyReady) {
    return failHold("strategy salt not configured — cannot prove");
  }

  const selfBalance = BigInt(state.selfBalance);
  const opponentBalance = BigInt(state.opponentBalance);
  const action = decideAction(Number(selfBalance), Number(opponentBalance), strategyParams);
  const amount = action.type === "EXTRACT" ? action.amount : 0;

  const actionOut = action.type === "EXTRACT"
    ? { type: "EXTRACT", amount: action.amount }
    : { type: action.type }; // amount MUST be omitted for HOLD/FORTIFY

  const hash = publicInputsHash({
    commitment: strategyCommitment,
    matchId,
    turn,
    selfBalance: state.selfBalance,
    opponentBalance: state.opponentBalance,
    action: action.type,
    amount,
  });

  const obj = {
    matchId,
    turn,
    action: actionOut,
    policyProof: {
      circuitVersion: CIRCUIT_VERSION,
      publicInputsHash: hash,
    },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: randomUUID(),
  };

  try {
    const { proof, publicSignals, ms } = await proveSteal({
      commitment: strategyCommitment,
      matchId,
      turn,
      selfBalance: state.selfBalance,
      opponentBalance: state.opponentBalance,
      action: action.type,
      amount,
      strategyParams,
      saltHex: strategySaltHex,
    });
    // OFFICIAL nesting: proof + public_signals INSIDE policyProof.
    obj.policyProof.proof = proof;
    obj.policyProof.public_signals = publicSignals;
    log("info", "steal proof generated", { match_id: matchId, turn, action: action.type, amount, proof_ms: ms });
    if (kurierConfigured()) {
      const ref = await submitProofBestEffort("vfyPolicy", proof, publicSignals, 12000, log).catch(() => null);
      if (ref) obj.policyProof.proofReference = ref;
    }
  } catch (e) {
    // Fail closed: keep the decided action, policyProof carries no proof.
    log("error", "steal proof failed — returning action without proof", {
      match_id: matchId, turn, action: action.type, error: String(e?.message || e).slice(0, 300),
    });
  }

  const result = { status: 200, obj };
  stealCache.set(key, result);
  return result;
}

// ---------------------------------------------------------------- server
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function main() {
  assertCircuitsPresent();
  await initStrategy();
  if (kurierConfigured()) {
    registerVk("gatekeeper", log).catch(() => {});
    registerVk("vfyPolicy", log).catch(() => {});
  }

  const server = http.createServer(async (req, res) => {
    const t0 = Date.now();
    try {
      if (req.method === "GET" && req.url === "/health") {
        const present = circuitsPresent();
        sendJson(res, 200, {
          ok: true,
          agent: AGENT_ID,
          mode: noSecretMode ? "no-secret (dev only — do not go live)" : "live",
          secretConfigured: !noSecretMode,
          strategyConfigured: strategyReady,
          commitment: strategyCommitment,
          circuits: present,
          kurierConfigured: kurierConfigured(),
          uptimeSec: Math.floor(process.uptime()),
        }, false);
        return;
      }
      if (req.method === "GET" && req.url === "/") {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("lacrade agent-games — ok\n");
        return;
      }
      if (req.method !== "POST") {
        sendJson(res, 405, { error: "method not allowed" });
        return;
      }

      const rawBody = await readBody(req);
      if (!noSecretMode) {
        // Verify HMAC on the RAW body BEFORE parsing (protocol.md §1.1/§4).
        const sig = req.headers["x-agent-games-signature"];
        if (!verifyBody(hmacSecret, rawBody, sig)) {
          log("warn", "bad signature", {});
          sendJson(res, 401, { error: "bad signature" });
          return;
        }
      } else {
        log("warn", "no-secret mode: accepting unsigned request (dev only)", {});
      }

      let body;
      try {
        body = JSON.parse(rawBody.toString("utf8"));
      } catch {
        sendJson(res, 400, { error: "invalid json" });
        return;
      }

      let result;
      if (body?.type === "agent-games.preflight.v1") {
        result = await handlePreflight(body);
      } else if (body?.type === "agent-games.proof-gatekeeper.v1") {
        result = await handleGatekeeper(body);
      } else if (body?.eventId === "steal-the-vfy" || (body?.matchId && typeof body?.turn === "number")) {
        result = await handleSteal(body);
      } else {
        result = { status: 400, obj: { error: "unknown request type" } };
      }
      sendJson(res, result.status, result.obj);
      log("info", "request handled", {
        type: body?.type || body?.eventId || "unknown",
        status: result.status,
        ms: Date.now() - t0,
      });
    } catch (e) {
      log("error", "request failed", { error: String(e?.message || e).slice(0, 300) });
      try { sendJson(res, 500, { error: "internal error" }); } catch { /* already sent */ }
    }
  });

  server.listen(PORT, () => {
    log("info", "server listening", {
      port: PORT,
      mode: noSecretMode ? "no-secret (dev only — set AGENT_GAMES_HMAC_SECRET before going live)" : "live",
      circuits: Object.keys(CIRCUITS),
    });
    if (noSecretMode) {
      log("warn", "AGENT_GAMES_HMAC_SECRET is not set — HMAC verification is OFF and responses are unsigned", {});
    }
  });
}

main().catch((e) => {
  log("error", "startup failed", { error: String(e?.message || e).slice(0, 300) });
  process.exit(1);
});
