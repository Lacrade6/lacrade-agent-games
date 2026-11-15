// SPDX-License-Identifier: MIT
// Steal the VFY — policy proof + publicInputsHash (protocol.md §2).
// Response nesting is OFFICIAL: proof + public_signals MUST sit INSIDE
// policyProof (top-level placement is the #1 cause of lost turns).
// Circuit inputs / 9 public signals / strategy-param semantics are REF
// (probed from the official wasm — protocol.md §2.5, §9.3/§9.15).
import pkg from "js-sha3";
const { keccak_256 } = pkg;
import * as snarkjs from "snarkjs";
import { circuitPaths, toField } from "./circuits.mjs";
import { ACTION_CODE, CIRCUIT_VERSION } from "./strategy.mjs";

/**
 * publicInputsHash — OFFICIAL formula (§2.4): keccak256 of 8 ABI-packed
 * 32-byte big-endian fields, in this exact order:
 * [commitment, matchId (hyphens stripped, as 0x hex), turn, selfBalance,
 *  opponentBalance, action, amount, circuitVersion(=1)].
 * This is an off-circuit audit value; the platform verifies the actual
 * Groth16 proof + public_signals separately.
 */
export function publicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount }) {
  const fields = [
    toField(commitment),
    BigInt("0x" + String(matchId).replace(/-/g, "")),
    BigInt(turn),
    BigInt(selfBalance),
    BigInt(opponentBalance),
    BigInt(ACTION_CODE[action]),
    BigInt(amount),
    1n, // circuitVersion "v1" → 1
  ];
  const packed = Buffer.concat(
    fields.map((f) => {
      const b = Buffer.alloc(32);
      Buffer.from(f.toString(16).padStart(64, "0"), "hex").copy(b);
      return b;
    }),
  );
  return "0x" + keccak_256(packed);
}

function buildCircuitInput({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount, strategyParams, saltHex }) {
  return {
    commitment: toField(commitment).toString(),
    matchId: BigInt("0x" + String(matchId).replace(/-/g, "")).toString(),
    turnNumber: BigInt(turn).toString(),
    selfBalance: BigInt(selfBalance).toString(),
    opponentBalance: BigInt(opponentBalance).toString(),
    action: String(ACTION_CODE[action]),
    amount: BigInt(amount).toString(),
    circuitVersion: "1",
    salt: BigInt("0x" + saltHex.replace(/^0x/, "")).toString(),
    strategyParams: strategyParams.map((n) => String(n)),
  };
}

/** Generate the Groth16 policy proof for one turn. */
export async function proveSteal(args) {
  const { wasm, zkey } = circuitPaths("vfyPolicy");
  const circuitInput = buildCircuitInput(args);
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, wasm, zkey);
  return { proof, publicSignals, ms: Date.now() - t0 };
}

export { CIRCUIT_VERSION };
