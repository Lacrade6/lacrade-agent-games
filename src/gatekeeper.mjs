// SPDX-License-Identifier: MIT
// Proof Gatekeeper — decision logic + Groth16 proof (protocol.md §1).
// Decision rules are OFFICIAL (7 traps, first failing trap wins).
// Circuit input names / 13 public signals / taskId mapping are REF (probed
// from the official wasm — see protocol.md §1.5, §9.2): the taskId mapping
// (keccak256 of the task_id string, mod the BN128 field prime) is UNVERIFIED
// officially and must be confirmed against a practice task.
import pkg from "js-sha3";
const { keccak_256 } = pkg;
import { randomBytes } from "node:crypto";
import * as snarkjs from "snarkjs";
import { FIELD_PRIME, circuitPaths, toField } from "./circuits.mjs";

export const REASON_CODES = {
  VALID_CONDITION: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  PROOF_REUSED: "PROOF_REUSED",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
  INVALID_TASK: "INVALID_TASK", // REF-only, local fail-closed code (not an official trap)
};

/** Validate the envelope input shape. Returns an error string or null. */
export function validateGatekeeperInput(input) {
  if (!input || typeof input !== "object") return "missing input";
  const strings = ["registered_vk", "proof_vk", "minimum", "public_balance", "recipient", "condition_recipient", "amount", "max_transfer", "proof_tx"];
  for (const f of strings) {
    if (typeof input[f] !== "string" || input[f].length === 0) return `missing/invalid ${f}`;
  }
  for (const f of ["expiry_block", "current_block"]) {
    if (typeof input[f] !== "number" || !Number.isFinite(input[f])) return `missing/invalid ${f}`;
  }
  return null;
}

/**
 * The 7 traps in order. `isProofReused` is a callback: (proof_tx) => boolean.
 * Boundaries (OFFICIAL): balance == minimum is VALID; amount == max is VALID;
 * current_block == expiry_block is EXPIRED (valid only while current < expiry).
 */
export function decideGatekeeper(input, isProofReused) {
  const norm = (a) => a.toLowerCase();
  if (norm(input.proof_vk) !== norm(input.registered_vk)) {
    return { decision: "REJECT", reason_code: REASON_CODES.VK_SUBSTITUTION };
  }
  if (isProofReused(input.proof_tx)) {
    return { decision: "REJECT", reason_code: REASON_CODES.PROOF_REUSED };
  }
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return { decision: "REJECT", reason_code: REASON_CODES.THRESHOLD_MISMATCH };
  }
  if (input.current_block >= input.expiry_block) {
    return { decision: "REJECT", reason_code: REASON_CODES.EXPIRED_CONDITION };
  }
  if (norm(input.recipient) !== norm(input.condition_recipient)) {
    return { decision: "REJECT", reason_code: REASON_CODES.RECIPIENT_MISMATCH };
  }
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return { decision: "REJECT", reason_code: REASON_CODES.AMOUNT_OVERFLOW };
  }
  return { decision: "APPROVE", reason_code: REASON_CODES.VALID_CONDITION };
}

/** UNVERIFIED mapping (REF default, protocol.md §9.2): keccak256(task_id) mod p. */
export function taskIdToField(taskId) {
  return BigInt("0x" + keccak_256(taskId)) % FIELD_PRIME;
}

function buildCircuitInput(input, taskId, decision) {
  return {
    registeredVkHash: toField(input.registered_vk).toString(),
    proofVkHash: toField(input.proof_vk).toString(),
    minimum: BigInt(input.minimum).toString(),
    publicBalance: BigInt(input.public_balance).toString(),
    expiryBlock: BigInt(input.expiry_block).toString(),
    currentBlock: BigInt(input.current_block).toString(),
    recipient: toField(input.recipient).toString(),
    conditionRecipient: toField(input.condition_recipient).toString(),
    amount: BigInt(input.amount).toString(),
    maxTransfer: BigInt(input.max_transfer).toString(),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: taskIdToField(taskId).toString(),
    salt: (BigInt("0x" + randomBytes(32).toString("hex")) % FIELD_PRIME).toString(),
  };
}

/**
 * Generate the Groth16 proof for a gatekeeper task. The circuit re-evaluates
 * the decision itself — a wrong decision fails witness generation, in which
 * case this throws and the caller must return the decision WITHOUT a proof
 * (fail closed, never crash).
 */
export async function proveGatekeeper(input, taskId, decision) {
  const { wasm, zkey } = circuitPaths("gatekeeper");
  const circuitInput = buildCircuitInput(input, taskId, decision);
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, wasm, zkey);
  return { proof, publicSignals, ms: Date.now() - t0 };
}
