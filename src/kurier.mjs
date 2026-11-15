// SPDX-License-Identifier: MIT
// Kurier (zkVerify REST verification) — OPTIONAL, best-effort, never blocking.
// Protocol.md §5.2: the platform accepts the locally-generated Groth16 proof
// in the response as the primary evidence. Kurier adds an on-chain
// finalization pointer (proofReference). If no KURIER_API_KEY is configured,
// every function below is a silent no-op and responses carry the local proof
// only. When configured, submission is bounded (20 s gatekeeper / 12 s steal)
// and any failure degrades to "no proofReference" — Kurier never breaks a
// response.
//
// API key: free, self-serve at https://kurier.xyz (email signup). Do NOT
// create accounts to get one — the user must supply the key.
import { CIRCUITS, exportVk } from "./circuits.mjs";

const BASE = "https://api.kurier.xyz/api/v1";

export function isConfigured() {
  return Boolean(process.env.KURIER_API_KEY);
}

function apiKey() {
  return process.env.KURIER_API_KEY;
}

async function postJson(url, body, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function getJson(url, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

const vkHashCache = {};

/** Register a circuit's verification key once; returns the vkHash (or null). */
export async function registerVk(name, log) {
  if (!isConfigured()) return null;
  if (vkHashCache[name]) return vkHashCache[name];
  try {
    const vk = await exportVk(name);
    const out = await postJson(`${BASE}/register-vk/${apiKey()}`, {
      proofType: "groth16",
      proofOptions: { library: "snarkjs", curve: "bn128" },
      vk,
    }, 15000);
    const hash = out?.vkHash || out?.meta?.vkHash || null;
    if (hash) {
      vkHashCache[name] = hash;
      if (hash.toLowerCase() !== CIRCUITS[name].vkHash.toLowerCase()) {
        log?.("warn", "kurier vkHash mismatch", { circuit: name, returned: hash, expected: CIRCUITS[name].vkHash });
      }
    }
    return hash;
  } catch (e) {
    log?.("warn", "kurier register-vk failed", { circuit: name, error: String(e?.message || e).slice(0, 200) });
    return null;
  }
}

/**
 * Submit a proof and poll (bounded) until Finalized. Returns the txHash when
 * finalized, else the jobId (the platform can resolve either), else null.
 * `timeoutMs`: 20000 for gatekeeper, 12000 for steal (REF bounds).
 */
export async function submitProofBestEffort(name, proof, publicSignals, timeoutMs, log) {
  if (!isConfigured()) return null;
  const deadline = Date.now() + timeoutMs;
  try {
    const vkHash = (await registerVk(name, log)) || CIRCUITS[name].vkHash;
    const out = await postJson(`${BASE}/submit-proof/${apiKey()}`, {
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: { library: "snarkjs", curve: "bn128" },
      proofData: { proof, publicSignals, vk: vkHash },
    }, Math.min(15000, timeoutMs));
    if (out?.optimisticVerify && out.optimisticVerify !== "success") {
      log?.("warn", "kurier optimisticVerify not success", { circuit: name, value: out.optimisticVerify });
      return null;
    }
    const jobId = out?.jobId;
    if (!jobId) return null;
    while (Date.now() < deadline) {
      const status = await getJson(`${BASE}/job-status/${apiKey()}/${jobId}`, 10000).catch(() => null);
      if (status?.status === "Finalized") return status.txHash || jobId;
      if (status?.status === "Failed") return null;
      await new Promise((r) => setTimeout(r, 3000));
    }
    return jobId; // still pending — the platform can resolve the jobId
  } catch (e) {
    log?.("warn", "kurier submit failed", { circuit: name, error: String(e?.message || e).slice(0, 200) });
    return null;
  }
}
