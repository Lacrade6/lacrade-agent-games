// SPDX-License-Identifier: MIT
// Print the Steal the VFY strategy commitment hash to register in the
// dashboard (My Agents → Edit agent → Steal the VFY section).
//
// Usage:
//   STRATEGY_SALT=<hex> node scripts/commitment.mjs
//   node scripts/commitment.mjs --generate-salt   # prints a fresh salt ONCE
//
// The salt is secret: save it as the STRATEGY_SALT env var (e.g. in Railway
// env vars) and NEVER commit it, log it, or share it. Only the commitment
// hash below is ever printed/shared. If you change STRATEGY_PARAMS, you must
// re-register the new hash before the next round pairs.
import { randomBytes } from "node:crypto";
import { computeCommitment, loadStrategyParams, validateStrategyParams, DEFAULT_STRATEGY_PARAMS } from "../src/strategy.mjs";

const generate = process.argv.includes("--generate-salt");
let saltHex = (process.env.STRATEGY_SALT || "").replace(/^0x/, "");
if (generate || !saltHex) {
  saltHex = randomBytes(16).toString("hex");
  console.log("⚠️  GENERATED SALT (save it as STRATEGY_SALT now — it is shown once, never commit it):");
  console.log(`   ${saltHex}\n`);
}

const params = loadStrategyParams();
validateStrategyParams(params);
const commitment = await computeCommitment(params, saltHex);

console.log("Strategy params (defaults are the published reference defaults):");
console.log(`  [extractAmount, fortifyThreshold, minOpponentBalance, mode, 0,0,0,0] = [${params.join(", ")}]`);
console.log("  (override with STRATEGY_PARAMS env var — JSON array of 8 numbers)");
console.log("\nCommitment hash — paste this into the dashboard (Steal the VFY section):");
console.log(`  ${commitment}`);
console.log("\nPolicy: FORTIFY while own balance < fortifyThreshold; HOLD while opponent");
console.log("balance <= minOpponentBalance; otherwise EXTRACT extractAmount. Mode 1 = always HOLD.");
process.exit(0);
