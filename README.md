# lacrade-agent-games

`lacrade`'s agent for the **zkVerify Agent Games** (21 Oct – 21 Nov 2026):
**Proof Gatekeeper** + **Steal the VFY**. A Node.js HTTPS server that receives
HMAC-signed task envelopes, decides, and proves each decision with a Groth16
proof (BN128, Circom 2.x, `snarkjs`) generated locally from the event's
official circuits.

Protocol source of truth: the [builder field guide](https://agentgames.zkverify.io/build).
The full protocol spec used for this implementation is kept at
`../protocol.md` (outside this repo — it contains research notes, including
which facts are officially documented vs reverse-engineered).

## What it does

| Endpoint / request | Response |
|---|---|
| `agent-games.preflight.v1` (signed) | `{"ok": true, "protocolVersion": "v1"}` — signed. Must pass before the platform marks the agent active. |
| `agent-games.proof-gatekeeper.v1` | `{decision, reason_code, proof_tx, proof, public_signals}` — proof at the **top level**. 60 s hard deadline. |
| Steal the VFY turn (`eventId: steal-the-vfy`) | `{matchId, turn, action, policyProof: {circuitVersion, proof, public_signals, …}, agentTimestamp, idempotencyKey}` — proof **inside `policyProof`** (top-level placement is the official #1 cause of lost turns). 5 min per turn. |
| `GET /health` | Operator readiness only (the platform does not call it). |

Every response is signed with `x-agent-games-signature` = HMAC-SHA256 over the
raw response body, using the secret issued once at registration.

### Proof Gatekeeper — decision rules (official, first failing trap wins)

1. `VK_SUBSTITUTION` — `proof_vk != registered_vk`
2. `PROOF_REUSED` — `proof_tx` already seen under a different `task_id`
3. `THRESHOLD_MISMATCH` — `public_balance < minimum`
4. `EXPIRED_CONDITION` — `current_block >= expiry_block`
5. `RECIPIENT_MISMATCH` — `recipient != condition_recipient`
6. `AMOUNT_OVERFLOW` — `amount > max_transfer`
7. otherwise `VALID_CONDITION` → **APPROVE**

Boundaries: `balance == minimum` is VALID; `amount == max` is VALID;
`current_block == expiry_block` is EXPIRED. Fail closed: any timeout, error,
or uncertainty → REJECT, never approve by default. `PROOF_REUSED` responses
carry no proof. Task IDs are idempotency keys — a retry of the same `task_id`
returns the identical cached response (same proof).

### Steal the VFY — strategy (the user owns this choice)

The strategy is **the user's to decide** — the block below is a transparent,
simple, documented default, not a model-invented strategy. The Groth16
circuit re-derives the action from the committed parameters, so the handler
must return exactly this policy or witness generation fails:

> **Default policy** (params `[5, 50, 0, 0, 0, 0, 0, 0]`):
> FORTIFY while your own balance is below 50; HOLD while the opponent's
> balance is 0 (nothing worth stealing); otherwise EXTRACT 5 VFY per turn.
> (Mode 1 would always HOLD.)

Change the parameters with the `STRATEGY_PARAMS` env var (JSON array of 8
numbers) — then re-register the new commitment hash in the dashboard before
the next round pairs. The commitment is `Poseidon(params[0..7], salt)`;
compute it with `npm run commitment` (see below). The salt is secret and is
never committed or logged.

## Quick start (local)

```bash
npm ci
# circuits are downloaded at build time; locally fetch them once:
node scripts/download-circuits.mjs ./circuits

# 1. generate a strategy salt + commitment hash (salt shown ONCE — save it)
node scripts/commitment.mjs --generate-salt
#    → paste the commitment hash into the dashboard (My Agents → Edit agent
#      → Steal the VFY section) BEFORE the next Swiss round pairs.
#      Use the 0x-hex form printed by the script — the dashboard requires a
#      0x-prefixed 64-hex-char hash (the decimal form is rejected).

# 2. run the server (dev mode: no HMAC secret yet)
STRATEGY_SALT=<the salt> npm start

# 3. self-test (spawns the server on port 3456 with a test secret)
npm run selftest
```

## Environment variables

| Variable | Required | Notes |
|---|---|---|
| `PORT` | no (default 3000) | Railway sets this automatically. |
| `AGENT_GAMES_HMAC_SECRET` | **yes, for live** | 32-byte secret shown once at registration (dashboard → Rotate Secret). Without it the server starts in a clearly-marked **no-secret dev mode** (unsigned requests accepted, responses unsigned) — never go live like that. |
| `AGENT_GAMES_HMAC_FORMAT` | no (default `hex`) | `hex` or `sha256=` — the official docs do not state the header encoding; preflight decides. Switch if the platform rejects the preflight. |
| `STRATEGY_SALT` | **yes, for Steal** | 16-byte hex used in the strategy commitment. Secret — set in Railway env vars, never commit. Without it, Steal turns answer HOLD without proof (fail closed). |
| `STRATEGY_PARAMS` | no | JSON array of 8 numbers overriding the default policy. Changing it requires re-registering the commitment hash. |
| `STRATEGY_COMMITMENT_HASH` | no | If set and it differs from the hash computed from params+salt, the server logs an error (the computed hash is authoritative). |
| `KURIER_API_KEY` | no | Free key from https://kurier.xyz (email signup). Optional, best-effort: submits proofs for on-chain finalization and adds `proofReference`. Never blocks a response; without it, responses carry the local proof only. |
| `CIRCUITS_DIR` | no (default `./circuits`) | Where the `.wasm`/`.zkey` files live. |
| `AGENT_ID` | no (default `lacrade`) | Agent name. |

## Deploy to Railway

```bash
# Option A — Railway CLI (needs a Railway account + login):
railway login
railway init            # or: railway link
railway up              # builds the Dockerfile, deploys, gives a public URL

# Option B — Railway dashboard: New Project → Deploy from GitHub repo
# (select this repo) → the Dockerfile is detected automatically.

# Then set the env vars in the Railway dashboard (Variables tab):
#   AGENT_GAMES_HMAC_SECRET=<secret from the Agent Games dashboard>
#   STRATEGY_SALT=<the salt from `npm run commitment --generate-salt`>
# (STRATEGY_PARAMS / KURIER_API_KEY only if you use them.)
```

After deploy, copy the public URL (e.g. `https://lacrade-agent-games.up.railway.app`)
into the Agent Games dashboard as the agent endpoint, then confirm the
preflight passes and run at least one practice task/turn before the scored
rounds. **Uptime matters:** if the agent is offline when a task is delivered,
that task is forfeited. Do not use a host that sleeps after inactivity.

## Circuits

Both are Groth16/BN128, Circom 2.x, from the official
[`/api/circuit-info`](https://agentgames.zkverify.io/api/circuit-info):

| Circuit | vkHash | Files |
|---|---|---|
| Gatekeeper | `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0` | `gatekeeper.wasm`, `gatekeeper_final.zkey` |
| vfyPolicy | `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047` | `vfy-policy.wasm`, `vfy-policy_final.zkey` |

Artifacts are **not committed** — the Dockerfile downloads them from
`https://agentgames.zkverify.io/circuits/` and verifies SHA-256 against the
values pinned in `src/circuits.mjs`. (The official `vkHash` values above are
recorded for reference; the local vkHash formula could not be confirmed from
the public docs, so artifact integrity is pinned by SHA-256 instead, and by
Kurier's `register-vk` response when a Kurier key is configured.)

## Self-test results (2026-11-16, this VM)

`npm run selftest` — **56 checks, 0 failures**, including: signed preflight,
unsigned/bad-signature rejection (401), all 6 Gatekeeper traps + 3 boundary
cases, Gatekeeper idempotency (identical retry response), Steal EXTRACT /
FORTIFY / HOLD with proofs verified locally, `publicInputsHash` recomputation
match, wrong-commitment HOLD, 0x-hex commitment accepted, Steal replay. Every proof is verified locally
with `snarkjs.groth16.verify` before the check passes.

Proof times on this VM: Gatekeeper ~1.3–2.1 s (first ~5.9 s incl. wasm
warm-up), Steal ~2.0–2.3 s — well inside the 60 s Gatekeeper deadline and
the ~30 s Steal push window.

## Known gaps / unverified items

These come from `../protocol.md` §9 and affect the build:

- **Gatekeeper `taskId` → field mapping is UNVERIFIED officially.** The code
  uses the reference default `keccak256(task_id) mod FIELD_PRIME`. Confirm
  against a practice task; if the platform rejects the proof, switch the
  mapping in `src/gatekeeper.mjs` (`taskIdToField`).
- **HMAC header encoding** (hex vs `sha256=`) is not stated officially.
  Default is hex; switch with `AGENT_GAMES_HMAC_FORMAT=sha256=` if the
  preflight fails.
- **Strategy parameter semantics** are reverse-engineered from the circuit,
  not officially documented. The self-test proves the circuit accepts the
  default policy (EXTRACT/FORTIFY/HOLD all verify), but confirm with a
  practice turn.
- **Kurier necessity** is ambiguous: the local proof is the primary evidence;
  Kurier only adds the on-chain pointer. The code treats it as optional.
- **Health check** = the signed preflight POST; no separate health path is
  documented. `GET /health` here is operator-side only.
- The official Gatekeeper checklist mentions on-chain confirmation of the
  proof via zkVerifyJS; this implementation trusts the platform-signed
  envelope and tracks `proof_tx` reuse locally instead (see `../protocol.md`
  §8.2).

## Security notes

- Never commit `AGENT_GAMES_HMAC_SECRET`, `STRATEGY_SALT`, or a Kurier API
  key. They live in environment variables only.
- Logs are structured JSON and never contain secrets, HMAC values, salts, or
  strategy parameters.
- The server fails closed everywhere: unsigned/mismatched requests → 401;
  malformed envelopes → REJECT / HOLD without proof; proof-generation failure
  → decision/action without a proof (never a crash).

## License

MIT — see [LICENSE](LICENSE).
