// Proof Gatekeeper — Agent Games Season 01 (zkVerify)
// Node.js tanpa framework (node:http bawaan). Fail closed.
// Menerima task POST di /gatekeeper dan / (root), memverifikasi HMAC atas
// RAW body SEBELUM parsing, memutuskan APPROVE/REJECT lewat 7 cek trap
// deterministik, lalu membuktikan keputusan dengan Groth16 (snarkjs 0.7.6)
// memakai circuit resmi gatekeeper (Groth16/BN128, Circom 2.x).
//
// JANGAN PERNAH: menyentuh X / Agentic Wallet / akun Binance Adinda.
// JANGAN PERNAH: mencetak secret, seed, atau private key ke log/stdout/file.

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Konfigurasi
// ---------------------------------------------------------------------------
export const OFFICIAL_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"; // /api/circuit-info
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || (process.env.PORT ? "0.0.0.0" : "127.0.0.1");
const WASM_PATH = path.join(__dirname, "circuits", "gatekeeper.wasm");
const ZKEY_PATH = path.join(__dirname, "circuits", "gatekeeper_final.zkey");
const VK_PATH = path.join(__dirname, "verification_key.json");
const SEEN_PATH = path.join(__dirname, "seen.json");
const LOG_PATH = path.join(__dirname, "tasks.log");
const SECRET_FILE = path.join(__dirname, "hmac-secret.txt");
const INTERNAL_BUDGET_MS = 50_000; // batas internal, di bawah deadline platform 60 dtk

// ---------------------------------------------------------------------------
// HMAC secret: file (mode 600) > env HMAC_SECRET > placeholder DEV.
// DEV MODE: HMAC tetap diverifikasi terhadap placeholder agar bisa diuji
// lokal, TAPI task mode "competition" DITOLAK mentah (503) — fail closed —
// karena tanpa secret asli dari platform kita tidak bisa membuktikan
// keaslian task kompetisi. Task "practice" tetap dilayani di DEV mode.
// ---------------------------------------------------------------------------
let HMAC_SECRET = null;
let DEV_MODE = false;
function loadSecret() {
  if (process.env.HMAC_SECRET && process.env.HMAC_SECRET.trim()) {
    HMAC_SECRET = process.env.HMAC_SECRET.trim();
    return;
  }
  try {
    const st = fs.statSync(SECRET_FILE);
    if ((st.mode & 0o777) !== 0o600) {
      console.error(`[WARN] ${SECRET_FILE} bukan mode 600 — secret diabaikan (fail closed).`);
    } else {
      const s = fs.readFileSync(SECRET_FILE, "utf8").trim();
      if (s) {
        HMAC_SECRET = s;
        return;
      }
    }
  } catch {
    // file belum ada — normal sebelum registrasi
  }
  DEV_MODE = true;
  HMAC_SECRET = "DEV_PLACEHOLDER_NOT_A_REAL_SECRET";
  console.error(
    "[WARN] HMAC secret asli BELUM tersedia — DEV MODE aktif. " +
      "Task mode=competition akan ditolak (503). " +
      "Isi ~/workspace/agentgames/hmac-secret.txt (mode 600) atau set env HMAC_SECRET."
  );
}
loadSecret();

const VK = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));

// ---------------------------------------------------------------------------
// Seen-set persisten (proof_tx -> {task_id, decision, reason_code, ts})
// ---------------------------------------------------------------------------
let seen = {};
try {
  seen = JSON.parse(fs.readFileSync(SEEN_PATH, "utf8"));
} catch {
  seen = {};
}
function saveSeen() {
  fs.writeFileSync(SEEN_PATH, JSON.stringify(seen, null, 2));
}
function logTask(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry });
  fs.appendFileSync(LOG_PATH, line + "\n");
}

// ---------------------------------------------------------------------------
// HMAC helpers
// ---------------------------------------------------------------------------
function signHmac(rawBody) {
  return crypto.createHmac("sha256", HMAC_SECRET).update(rawBody).digest("hex");
}
function verifyHmac(rawBody, header) {
  if (!header || typeof header !== "string") return false;
  const sig = header.trim().toLowerCase().replace(/^sha256=/, "");
  if (!/^[0-9a-f]{64}$/.test(sig)) return false;
  const expected = signHmac(rawBody);
  const a = Buffer.from(sig, "hex");
  const b = Buffer.from(expected, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Encoding field element untuk circuit
//   - hash hex (vk): BigInt(hex) mod FIELD_PRIME (hash 256-bit > prima ~254-bit)
//   - alamat: BigInt(hex) apa adanya (160-bit, muat di field)
//   - task_id string: BigInt dari byte UTF-8, mod FIELD_PRIME
//   - salt (privat): sha256(task_id + ":" + proof_tx) mod FIELD_PRIME,
//     deterministik agar retry menghasilkan proof yang sama
// Asumsi ini TIDAK tercantum di halaman publik; diverifikasi secara empiris:
// fullProve + groth16.verify OK untuk skenario valid, dan circuit menolak
// keputusan yang salah (lihat gatekeeper/proof-test/probe.mjs).
// ---------------------------------------------------------------------------
function fieldFromHex(hex) {
  return (BigInt(hex) % FIELD_PRIME).toString();
}
function fieldFromTaskId(taskId) {
  return (BigInt("0x" + Buffer.from(String(taskId), "utf8").toString("hex")) % FIELD_PRIME).toString();
}
function deriveSalt(taskId, proofTx) {
  const h = crypto.createHash("sha256").update(`${taskId}:${proofTx}`).digest("hex");
  const v = BigInt("0x" + h) % FIELD_PRIME;
  return (v === 0n ? 1n : v).toString();
}
function toBigInt(v, label) {
  if (v === undefined || v === null || v === "") throw new Error(`field kosong: ${label}`);
  try {
    return typeof v === "bigint" ? v : BigInt(typeof v === "number" ? String(v) : String(v).trim());
  } catch {
    throw new Error(`field bukan angka/hex: ${label}`);
  }
}

// ---------------------------------------------------------------------------
// Keputusan: 7 cek trap, urutan deterministik (terdokumentasi).
//   1. PROOF_REUSED        — proof_tx sudah ada di seen-set lokal
//   2. VK_SUBSTITUTION     — proof_vk != registered_vk, ATAU registered_vk
//                            bukan vkHash resmi yang diterbitkan platform
//                            (circuit hanya mengecek kesetaraan; registered-ness
//                            harus dicek di sini — lihat /build §04 Security)
//   3. THRESHOLD_MISMATCH  — public_balance < minimum
//   4. EXPIRED_CONDITION   — current_block > expiry_block
//   5. RECIPIENT_MISMATCH  — recipient != condition_recipient
//   6. AMOUNT_OVERFLOW     — amount > max_transfer
//   7. (tidak ada trap)    — VALID_CONDITION → APPROVE
// Satu task diasumsikan mengandung paling banyak satu trap; bila ada lebih,
// reason_code pertama dalam urutan di atas yang dilaporkan.
// ---------------------------------------------------------------------------
function decide(task) {
  const input = task?.input;
  if (!task || typeof task !== "object" || !input || typeof input !== "object") {
    return { decision: "REJECT", reason_code: "MALFORMED_TASK", malformed: true };
  }
  const proofTx = input.proof_tx;
  if (!proofTx || typeof proofTx !== "string") {
    return { decision: "REJECT", reason_code: "MALFORMED_TASK", malformed: true };
  }
  try {
    // 1. Reuse — dicek dulu, sebelum field lain dibaca.
    if (seen[proofTx.toLowerCase()]) {
      return { decision: "REJECT", reason_code: "PROOF_REUSED" };
    }
    const registeredVk = String(input.registered_vk || "").trim().toLowerCase();
    const proofVk = String(input.proof_vk || "").trim().toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(registeredVk) || !/^0x[0-9a-f]{64}$/.test(proofVk)) {
      return { decision: "REJECT", reason_code: "MALFORMED_TASK", malformed: true };
    }
    // 2. VK substitution (termasuk pasangan kunci palsu yang sama-sama bukan resmi)
    if (proofVk !== registeredVk || registeredVk !== OFFICIAL_VK_HASH) {
      return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
    }
    const minimum = toBigInt(input.minimum, "minimum");
    const publicBalance = toBigInt(input.public_balance, "public_balance");
    const expiryBlock = toBigInt(input.expiry_block, "expiry_block");
    const currentBlock = toBigInt(input.current_block, "current_block");
    const amount = toBigInt(input.amount, "amount");
    const maxTransfer = toBigInt(input.max_transfer, "max_transfer");
    const recipient = String(input.recipient || "").trim().toLowerCase();
    const conditionRecipient = String(input.condition_recipient || "").trim().toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(recipient) || !/^0x[0-9a-f]{40}$/.test(conditionRecipient)) {
      return { decision: "REJECT", reason_code: "MALFORMED_TASK", malformed: true };
    }
    // 3. Threshold
    if (publicBalance < minimum) return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
    // 4. Expiry (current_block > expiry_block berarti kondisi kedaluwarsa)
    if (currentBlock > expiryBlock) return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
    // 5. Recipient
    if (recipient !== conditionRecipient) return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
    // 6. Amount
    if (amount > maxTransfer) return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
    // 7. Valid
    return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
  } catch (e) {
    return { decision: "REJECT", reason_code: "MALFORMED_TASK", malformed: true, error: e.message };
  }
}

// ---------------------------------------------------------------------------
// Proof Groth16 atas keputusan. Circuit memaksa decision==1 iff semua cek
// lolos (GatekeeperEvaluation_79 line 102): fullProve GAGAL bila keputusan
// yang diklaim bertentangan dengan field — itu sinyal bug logika kami, bukan
// alasan membalik keputusan. Bila proof gagal, kembalikan keputusan TANPA
// proof (skor -2) dan log keras; jangan pernah membalik keputusan.
// PROOF_REUSED tidak punya proof (dikecualikan dari skor proof).
// ---------------------------------------------------------------------------
async function proveDecision(task, decision) {
  const input = task.input;
  const circuitInput = {
    registeredVkHash: fieldFromHex(input.registered_vk),
    proofVkHash: fieldFromHex(input.proof_vk),
    minimum: toBigInt(input.minimum).toString(),
    publicBalance: toBigInt(input.public_balance).toString(),
    expiryBlock: toBigInt(input.expiry_block).toString(),
    currentBlock: toBigInt(input.current_block).toString(),
    recipient: toBigInt(input.recipient).toString(),
    conditionRecipient: toBigInt(input.condition_recipient).toString(),
    amount: toBigInt(input.amount).toString(),
    maxTransfer: toBigInt(input.max_transfer).toString(),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: fieldFromTaskId(task.task_id || ""),
    salt: deriveSalt(task.task_id || "", input.proof_tx),
  };
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH
  );
  const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
  if (!ok) throw new Error("groth16.verify mengembalikan false");
  return { proof, publicSignals, proveMs: Date.now() - t0 };
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
function sendJson(res, status, obj, sign = false) {
  const body = JSON.stringify(obj);
  const headers = { "Content-Type": "application/json" };
  if (sign) headers["x-agent-games-signature"] = signHmac(Buffer.from(body));
  res.writeHead(status, headers);
  res.end(body);
}

async function handleGatekeeper(req, rawBody, res) {
  const started = Date.now();
  // (b) HMAC atas RAW body, SEBELUM parsing.
  const sig = req.headers["x-agent-games-signature"];
  if (!verifyHmac(rawBody, sig)) {
    logTask({ task_id: null, decision: "REJECT", reason_code: "UNAUTHORIZED", duration_ms: Date.now() - started, note: "hmac mismatch" });
    return sendJson(res, 401, { error: "invalid signature" });
  }
  let task;
  try {
    task = JSON.parse(rawBody.toString("utf8"));
  } catch {
    logTask({ task_id: null, decision: "REJECT", reason_code: "MALFORMED_TASK", duration_ms: Date.now() - started });
    return sendJson(res, 400, { decision: "REJECT", reason_code: "MALFORMED_TASK", proof_tx: null }, true);
  }

  // Fail closed di DEV MODE: tolak task kompetisi nyata tanpa secret asli.
  if (DEV_MODE && task?.mode === "competition") {
    logTask({ task_id: task.task_id || null, decision: "REJECT", reason_code: "DEV_MODE_NO_SECRET", duration_ms: Date.now() - started });
    return sendJson(res, 503, { decision: "REJECT", reason_code: "DEV_MODE_NO_SECRET", proof_tx: task?.input?.proof_tx || null }, true);
  }

  const { decision, reason_code, malformed } = decide(task);
  const proofTx = task?.input?.proof_tx || null;

  // Catat proof_tx ke seen-set untuk SEMUA task yang lolos HMAC (approve
  // maupun reject) — pengiriman ulang apa pun sesudahnya = PROOF_REUSED.
  if (proofTx && !malformed) {
    seen[proofTx.toLowerCase()] = {
      task_id: task.task_id || null,
      decision,
      reason_code,
      ts: new Date().toISOString(),
    };
    saveSeen();
  }

  const response = { decision, reason_code, proof_tx: proofTx };
  if (task?.task_id) response.task_id = task.task_id;

  // (d) Proof — untuk APPROVE dan semua REJECT yang provable.
  // PROOF_REUSED dikecualikan (tidak ada proof). MALFORMED tidak diprove.
  if (!malformed && reason_code !== "PROOF_REUSED") {
    try {
      const { proof, publicSignals, proveMs } = await proveDecision(task, decision);
      response.proof = proof;
      response.public_signals = publicSignals;
      response.proof_ms = proveMs;
    } catch (e) {
      // Fail closed tapi jujur: keputusan tetap, proof absen, log keras.
      console.error(`[ERROR] proof gagal task=${task.task_id} decision=${decision}: ${e.message}`);
      response.proof_error = "proof_generation_failed";
    }
  }

  const durationMs = Date.now() - started;
  if (durationMs > INTERNAL_BUDGET_MS) {
    console.error(`[WARN] task=${task.task_id} melebihi budget internal: ${durationMs}ms`);
  }
  logTask({
    task_id: task.task_id || null,
    mode: task.mode || null,
    decision,
    reason_code,
    proof_tx: proofTx,
    duration_ms: durationMs,
    proof_ms: response.proof_ms ?? null,
    proof_included: Boolean(response.proof),
  });
  // (e) respons ditandatangani HMAC.
  return sendJson(res, 200, response, true);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  if (req.method === "OPTIONS") {
    res.writeHead(204, { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type, x-agent-games-signature" });
    return res.end();
  }
  if (req.method === "GET" && (url.pathname === "/health" || url.pathname === "/")) {
    return sendJson(res, 200, { status: "ok", dev_mode: DEV_MODE });
  }
  if (req.method === "POST" && (url.pathname === "/gatekeeper" || url.pathname === "/")) {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => handleGatekeeper(req, Buffer.concat(chunks), res).catch((e) => {
      console.error("[ERROR] handler:", e);
      sendJson(res, 500, { decision: "REJECT", reason_code: "INTERNAL_ERROR", proof_tx: null });
    }));
    req.on("error", () => sendJson(res, 400, { error: "bad request" }));
    return;
  }
  return sendJson(res, 404, { error: "not found" });
});

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__dirname, "server.mjs")) {
  server.listen(PORT, HOST, () => {
    console.log(`[gatekeeper] listening http://${HOST}:${PORT} (dev_mode=${DEV_MODE})`);
    console.log(`[gatekeeper] POST /gatekeeper dan / — GET /health`);
  });
}
export { server, decide, proveDecision, verifyHmac, signHmac };
