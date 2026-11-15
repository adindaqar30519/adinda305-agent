// Uji lokal server gatekeeper: 8 kasus (1 valid + 7 trap) + health + HMAC.
// Jalankan:  HMAC_SECRET=test-secret node test.mjs
// Server test berjalan di 127.0.0.1:3123 dengan secret dari env.
// Setiap kasus memakai proof_tx berbeda, kecuali kasus PROOF_REUSED yang
// sengaja memakai ulang proof_tx kasus valid.
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import * as snarkjs from "snarkjs";
import fs from "node:fs";

const PORT = 3123;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = process.env.HMAC_SECRET || "test-secret-local-only";
const OFFICIAL_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const OTHER_VK = "0x" + "a4".repeat(32); // 64 hex, berbeda dari resmi
const RECIPIENT = "0xDe42" + "00".repeat(16) + "9f01"; // 40 hex
const OTHER_ADDR = "0x1111111111111111111111111111111111111111";
const VK = JSON.parse(fs.readFileSync(new URL("./verification_key.json", import.meta.url), "utf8"));

function sign(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}
function baseTask(overInput = {}, over = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_24_9d1",
    mode: "practice",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: OFFICIAL_VK,
      proof_vk: OFFICIAL_VK,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0x" + "a1".repeat(32),
      ...overInput,
    },
    ...over,
  };
}

const CASES = [
  { name: "1 valid", task: baseTask({ proof_tx: "0x" + "a1".repeat(32) }), expect: ["APPROVE", "VALID_CONDITION"], proof: true },
  { name: "2 VK_SUBSTITUTION", task: baseTask({ proof_tx: "0x" + "b2".repeat(32), proof_vk: OTHER_VK }), expect: ["REJECT", "VK_SUBSTITUTION"], proof: true },
  { name: "3 THRESHOLD_MISMATCH", task: baseTask({ proof_tx: "0x" + "c3".repeat(32), public_balance: "900" }), expect: ["REJECT", "THRESHOLD_MISMATCH"], proof: true },
  { name: "4 PROOF_REUSED", task: baseTask({ proof_tx: "0x" + "a1".repeat(32) }), expect: ["REJECT", "PROOF_REUSED"], proof: false },
  { name: "5 EXPIRED_CONDITION", task: baseTask({ proof_tx: "0x" + "d4".repeat(32), current_block: 19842202 }), expect: ["REJECT", "EXPIRED_CONDITION"], proof: true },
  { name: "6 RECIPIENT_MISMATCH", task: baseTask({ proof_tx: "0x" + "e5".repeat(32), condition_recipient: OTHER_ADDR }), expect: ["REJECT", "RECIPIENT_MISMATCH"], proof: true },
  { name: "7 AMOUNT_OVERFLOW", task: baseTask({ proof_tx: "0x" + "f6".repeat(32), amount: "1500" }), expect: ["REJECT", "AMOUNT_OVERFLOW"], proof: true },
  { name: "8 fake-key pair (keduanya 0xaaaa, bukan resmi)", task: baseTask({ proof_tx: "0x" + "77".repeat(32), registered_vk: "0x" + "aa".repeat(32), proof_vk: "0x" + "aa".repeat(32) }), expect: ["REJECT", "VK_SUBSTITUTION"], proof: false, note: "TIDAK ADA proof yang valid: circuit memaksa decision=1 bila semua cek lapangan lolos (kesetaraan hash terpenuhi), jadi decision=0 tidak bisa diprove — sesuai sifat circuit, bukan bug server" },
];

async function post(path, task, { tamper = false, signHeader = true } = {}) {
  const body = JSON.stringify(task);
  const t0 = Date.now();
  const res = await fetch(BASE + path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(signHeader ? { "x-agent-games-signature": tamper ? sign(body + "x") : sign(body) } : {}),
    },
    body,
  });
  const raw = await res.text();
  return { status: res.status, raw, ms: Date.now() - t0, sig: res.headers.get("x-agent-games-signature") };
}

const server = spawn("node", ["server.mjs"], {
  cwd: new URL(".", import.meta.url).pathname,
  env: { ...process.env, PORT: String(PORT), HOST: "127.0.0.1", HMAC_SECRET: SECRET },
  stdio: "pipe",
});
let serverLog = "";
server.stdout.on("data", (d) => (serverLog += d));
server.stderr.on("data", (d) => (serverLog += d));

async function waitHealth() {
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(BASE + "/health");
      if (r.status === 200) return true;
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

let pass = 0, fail = 0;
try {
  if (!(await waitHealth())) throw new Error("server tidak menjawab /health\n" + serverLog);
  const h = await (await fetch(BASE + "/health")).json();
  console.log(`health: ${JSON.stringify(h)}`);

  for (const c of CASES) {
    const { status, raw, ms, sig } = await post("/gatekeeper", c.task);
    let ok = false, detail = "", proofOk = null;
    try {
      const body = JSON.parse(raw);
      const got = [body.decision, body.reason_code];
      const match = status === 200 && got[0] === c.expect[0] && got[1] === c.expect[1];
      // verifikasi HMAC respons
      const sigOk = sig && crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(sign(raw), "hex"));
      // proof: harus ada bila diharapkan; bila ada, harus verify OK
      if (c.proof) {
        if (body.proof && body.public_signals) {
          proofOk = await snarkjs.groth16.verify(VK, body.public_signals, body.proof);
        } else proofOk = false;
      } else {
        proofOk = !body.proof ? "n/a (tanpa proof, sesuai aturan)" : "SALAH: proof ikut terkirim";
      }
      ok = match && sigOk && (proofOk === true || proofOk === "n/a (tanpa proof, sesuai aturan)");
      detail = `got=${got.join("/")} expect=${c.expect.join("/")} http=${status} hmac_resp=${sigOk ? "OK" : "GAGAL"} proof=${proofOk} ${ms}ms${body.proof_ms ? ` (prove ${body.proof_ms}ms)` : ""}`;
    } catch (e) {
      detail = `parse gagal: ${e.message} raw=${raw.slice(0, 120)}`;
    }
    console.log(`[${ok ? "PASS" : "FAIL"}] ${c.name}: ${detail}`);
    ok ? pass++ : fail++;
  }

  // 9. HMAC salah -> 401
  const bad = await post("/gatekeeper", CASES[0].task, { tamper: true });
  const ok9 = bad.status === 401;
  console.log(`[${ok9 ? "PASS" : "FAIL"}] 9 HMAC dipalsukan -> http=${bad.status} (harap 401)`);
  ok9 ? pass++ : fail++;

  // 10. Tanpa header HMAC -> 401
  const nohdr = await post("/gatekeeper", CASES[0].task, { signHeader: false });
  const ok10 = nohdr.status === 401;
  console.log(`[${ok10 ? "PASS" : "FAIL"}] 10 tanpa header HMAC -> http=${nohdr.status} (harap 401)`);
  ok10 ? pass++ : fail++;

  // 11. POST ke root "/" juga diterima
  const root = await post("/", baseTask({ proof_tx: "0x" + "99".repeat(32) }));
  const rootBody = JSON.parse(root.raw);
  const ok11 = root.status === 200 && rootBody.decision === "APPROVE";
  console.log(`[${ok11 ? "PASS" : "FAIL"}] 11 POST / root -> ${rootBody.decision}/${rootBody.reason_code} (harap APPROVE/VALID_CONDITION)`);
  ok11 ? pass++ : fail++;
} finally {
  server.kill("SIGTERM");
}

console.log(`\nRINGKASAN: ${pass} PASS, ${fail} FAIL dari ${pass + fail} cek`);
process.exit(fail ? 1 : 0);
