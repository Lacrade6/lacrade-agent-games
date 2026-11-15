// SPDX-License-Identifier: MIT
// Circuit artifacts — paths, official vkHashes, verification-key export.
// Artifacts are downloaded at deploy time (Dockerfile) from the official URLs
// and verified by SHA-256; they are NOT committed to the repo.
// Locally they live in <repo>/circuits/ (gitignored) or $CIRCUITS_DIR.
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import * as snarkjs from "snarkjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const CIRCUITS_DIR = process.env.CIRCUITS_DIR || path.join(REPO_ROOT, "circuits");

export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const CIRCUITS = {
  gatekeeper: {
    // Official, from GET /api/circuit-info (protocol.md §5.1).
    vkHash: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    wasm: "https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
    zkey: "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey",
    wasmFile: "gatekeeper.wasm",
    zkeyFile: "gatekeeper_final.zkey",
    // SHA-256 of the exact files as served by the official URLs on 2026-11-16.
    // The Dockerfile pins these; re-pin if the official artifacts ever change.
    wasmSha256: "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f",
    zkeySha256: "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d",
    nPublic: 13,
  },
  vfyPolicy: {
    vkHash: "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
    wasm: "https://agentgames.zkverify.io/circuits/vfy-policy.wasm",
    zkey: "https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey",
    wasmFile: "vfy-policy.wasm",
    zkeyFile: "vfy-policy_final.zkey",
    wasmSha256: "bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2",
    zkeySha256: "f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41",
    nPublic: 9,
  },
};

export function circuitPaths(name) {
  const c = CIRCUITS[name];
  return {
    wasm: path.join(CIRCUITS_DIR, c.wasmFile),
    zkey: path.join(CIRCUITS_DIR, c.zkeyFile),
  };
}

export function circuitsPresent() {
  return Object.fromEntries(
    Object.keys(CIRCUITS).map((name) => {
      const p = circuitPaths(name);
      return [name, existsSync(p.wasm) && existsSync(p.zkey)];
    }),
  );
}

export function assertCircuitsPresent() {
  const present = circuitsPresent();
  const missing = Object.entries(present)
    .filter(([, ok]) => !ok)
    .map(([name]) => name);
  if (missing.length) {
    throw new Error(
      `missing circuit artifacts for: ${missing.join(", ")} (dir ${CIRCUITS_DIR}). ` +
        "Download them from the official URLs (see README / Dockerfile).",
    );
  }
}

const vkCache = {};
export async function exportVk(name) {
  if (!vkCache[name]) {
    vkCache[name] = await snarkjs.zKey.exportVerificationKey(circuitPaths(name).zkey);
  }
  return vkCache[name];
}

export async function verifyProofLocally(name, publicSignals, proof) {
  const vk = await exportVk(name);
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

// --- field helpers ---
export function toField(value) {
  // Accepts a decimal string, a JSON number, or a 0x-hex string.
  if (typeof value === "number") return BigInt(value);
  if (typeof value === "string" && /^0x/i.test(value)) return BigInt(value);
  return BigInt(value);
}

export function hexToField(value) {
  return BigInt(value);
}
