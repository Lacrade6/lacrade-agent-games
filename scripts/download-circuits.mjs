// SPDX-License-Identifier: MIT
// Download circuit artifacts from the OFFICIAL zkVerify URLs and verify
// their SHA-256 against the pinned values in src/circuits.mjs.
// Used by the Dockerfile at build time (artifacts are NOT committed).
// Usage: node scripts/download-circuits.mjs [outDir]
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { CIRCUITS } from "../src/circuits.mjs";

const outDir = process.argv[2] || path.resolve(process.cwd(), "circuits");
mkdirSync(outDir, { recursive: true });

for (const [name, c] of Object.entries(CIRCUITS)) {
  for (const kind of ["wasm", "zkey"]) {
    const url = c[kind];
    const file = kind === "wasm" ? c.wasmFile : c.zkeyFile;
    const want = kind === "wasm" ? c.wasmSha256 : c.zkeySha256;
    const dest = path.join(outDir, file);
    process.stdout.write(`downloading ${file} ... `);
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    const buf = Buffer.from(await res.arrayBuffer());
    const got = createHash("sha256").update(buf).digest("hex");
    if (got !== want) {
      throw new Error(`SHA-256 mismatch for ${file}: got ${got}, want ${want} — refusing to use it`);
    }
    writeFileSync(dest, buf);
    console.log(`ok (${buf.length} bytes, sha256 verified)`);
  }
}
console.log(`circuits ready in ${outDir}`);
process.exit(0);
