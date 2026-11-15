// SPDX-License-Identifier: MIT
// Strategy configuration for Steal the VFY.
//
// ⚠️ OWNERSHIP: the strategy is the user's to decide (official /build guide:
// "leave your strategy as your own to decide"). The block below is a
// transparent, simple, DOCUMENTED default policy — not a model-invented
// strategy. The user owns the strategy choice; change the params (or override
// them with the STRATEGY_PARAMS env var, a JSON array of 8 numbers) and
// re-register the commitment hash in the dashboard before the next round pairs.
//
// POLICY (circuit-enforced — see protocol.md §2.5; the Groth16 circuit
// re-derives the action from these params and the balances, so the handler
// MUST return exactly this policy or witness generation fails):
//   mode 0 (normal), in order:
//     1. selfBalance < fortifyThreshold  → FORTIFY  (pay 2 VFY, block up to 6)
//     2. opponentBalance <= minOpponent → HOLD     (nothing worth stealing)
//     3. otherwise                       → EXTRACT extractAmount
//   mode 1 → always HOLD.
// params[4..7] are reserved and MUST be 0 (any nonzero value makes no
// action valid in the circuit).
//
// Default params [5, 50, 0, 0, 0, 0, 0, 0] (the published reference default):
//   extract 5 VFY per turn, fortify while own balance is below 50, extract
//   whenever the opponent has anything left.
// NOTE: the circuit does NOT see whether the opponent is fortified, so the
// policy cannot condition on it — an EXTRACT into a fortified opponent still
// counts as the circuit-valid action even though its gain is reduced by 6.
//
// The SALT is secret: it comes from env STRATEGY_SALT only, is never logged
// and never committed. The commitment hash (Poseidon of params + salt) is the
// only value ever printed/shared.
import { buildPoseidon } from "circomlibjs";

export const DEFAULT_STRATEGY_PARAMS = [5, 50, 0, 0, 0, 0, 0, 0];
export const CIRCUIT_VERSION = "v1"; // circuitVersion "1" as a field element

export function loadStrategyParams() {
  const raw = process.env.STRATEGY_PARAMS;
  if (!raw) return [...DEFAULT_STRATEGY_PARAMS];
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed) || parsed.length !== 8) {
    throw new Error("STRATEGY_PARAMS must be a JSON array of 8 numbers");
  }
  return parsed.map((n) => Number(n));
}

export function validateStrategyParams(params) {
  const [extract, fortifyThreshold, minOpponent, mode] = params;
  if (!Number.isInteger(extract) || extract < 1 || extract > 10) {
    throw new Error(`strategyParams[0] extract amount must be 1-10, got ${extract}`);
  }
  if (fortifyThreshold < 0 || minOpponent < 0) {
    throw new Error("strategyParams[1..2] must be >= 0");
  }
  if (mode !== 0 && mode !== 1) {
    throw new Error(`strategyParams[3] mode must be 0 or 1, got ${mode}`);
  }
  if (params.slice(4).some((v) => v !== 0)) {
    throw new Error("strategyParams[4..7] are reserved and must be 0");
  }
}

/** Circuit-enforced policy. Returns { type, amount? } (amount only for EXTRACT). */
export function decideAction(selfBalance, opponentBalance, params) {
  const [extractAmount, fortifyThreshold, minOpponent, mode] = params;
  if (mode === 1) return { type: "HOLD" };
  if (selfBalance < fortifyThreshold) return { type: "FORTIFY" };
  if (opponentBalance <= minOpponent) return { type: "HOLD" };
  return { type: "EXTRACT", amount: extractAmount };
}

export const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

let poseidonInstance = null;
async function poseidon() {
  if (!poseidonInstance) poseidonInstance = await buildPoseidon();
  return poseidonInstance;
}

/**
 * Strategy commitment = Poseidon(strategyParams[0..7], salt) — params first,
 * salt last (protocol.md §2.6; only this ordering passes witness calc).
 * Returns the commitment as a decimal string.
 */
export async function computeCommitment(params, saltHex) {
  const p = await poseidon();
  const F = p.F;
  const salt = BigInt("0x" + saltHex.replace(/^0x/, ""));
  const inputs = [...params.map((n) => BigInt(n)), salt];
  return F.toObject(p(inputs)).toString();
}
