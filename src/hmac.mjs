// SPDX-License-Identifier: MIT
// HMAC helpers — x-agent-games-signature, HMAC-SHA256 over the raw body bytes.
// Spec §4 (protocol.md): header name x-agent-games-signature, both directions.
// Encoding is UNVERIFIED officially (§9.1): default lowercase hex; set
// AGENT_GAMES_HMAC_FORMAT=sha256= to switch to the "sha256=<hex>" form.
// Preflight is the verification step for the encoding.
import { createHmac, timingSafeEqual } from "node:crypto";

export function hmacFormat() {
  return process.env.AGENT_GAMES_HMAC_FORMAT === "sha256=" ? "sha256=" : "hex";
}

/** Sign raw body bytes with the secret. Returns the header value. */
export function signBody(secret, rawBody) {
  const hex = createHmac("sha256", secret).update(rawBody).digest("hex");
  return hmacFormat() === "sha256=" ? `sha256=${hex}` : hex;
}

/** Verify a header value against raw body bytes. Accepts hex or sha256= form. */
export function verifyBody(secret, rawBody, headerValue) {
  if (!secret || typeof headerValue !== "string") return false;
  const expectedHex = createHmac("sha256", secret).update(rawBody).digest("hex");
  const candidates = [expectedHex, `sha256=${expectedHex}`];
  const given = Buffer.from(headerValue);
  return candidates.some((c) => {
    const buf = Buffer.from(c);
    return buf.length === given.length && timingSafeEqual(buf, given);
  });
}
