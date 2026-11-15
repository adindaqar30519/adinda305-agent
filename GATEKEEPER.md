# Proof Gatekeeper — Agent Games Season 01 (zkVerify)

Endpoint lokal untuk track Proof Gatekeeper milik Adinda.
Node.js tanpa framework (node:http), snarkjs 0.7.6, circuit resmi Groth16/BN128.

## Status (15 Nov 2026, ~15:08 WIB)

- Circuit terunduh & terverifikasi (lihat `../circuits/`).
- Proof Groth16 lokal OK (verify=true), ~0,3–1,2 dtk per proof.
- Server lolos 11/11 cek lokal (`test.mjs`).
- **BLOCKER: HMAC secret platform BELUM ada** — server berjalan dalam
  DEV MODE: task `mode=competition` ditolak 503 (fail closed), task
  `mode=practice` tetap dilayani untuk uji lokal.

## File

| File | Keterangan |
| --- | --- |
| `server.mjs` | Server HTTP (port default 3000). GET `/health`, POST `/gatekeeper` dan `/` |
| `test.mjs` | 8 kasus uji (1 valid + 7 trap) + cek HMAC + cek root |
| `package.json` | `npm start` / `npm test`, dep: snarkjs 0.7.6 |
| `verification_key.json` | vk diekspor dari zkey resmi (Groth16, bn128, nPublic 13) |
| `seen.json` | Seen-set persisten proof_tx (dibuat otomatis saat runtime) |
| `tasks.log` | Log JSONL tiap task (dibuat otomatis saat runtime) |
| `proof-test/` | `probe.mjs` + artefak proof uji (input/proof/public signals) |
| `../circuits/gatekeeper.wasm` | 1.755.820 byte, sha256 `be00aefe…2764f` |
| `../circuits/gatekeeper_final.zkey` | 309.750 byte, sha256 `adfe95a4…af80d` |

## Menjalankan

```bash
cd ~/workspace/agentgames/gatekeeper
npm install            # sekali saja (snarkjs 0.7.6 sudah terinstal)
npm start              # PORT=3000 HOST=127.0.0.1
# atau: PORT=3000 HMAC_SECRET=<secret> node server.mjs
```

## HMAC secret (PENTING)

Secret diterbitkan platform saat registrasi agent (32-byte, sekali tampil).
Server membacanya dengan prioritas:

1. File `~/workspace/agentgames/hmac-secret.txt` (**harus mode 600**;
   file mode lain diabaikan) — cara yang disarankan.
2. Env `HMAC_SECRET`.

Bila keduanya tidak ada → **DEV MODE**: HMAC tetap diverifikasi terhadap
placeholder agar bisa diuji lokal, tapi task `mode=competition` dijawab
`503 {"decision":"REJECT","reason_code":"DEV_MODE_NO_SECRET"}`.
Jangan pernah menulis secret ke file non-600 atau mencetaknya ke log.

## Perilaku server

- **HMAC dulu**: `x-agent-games-signature` (HMAC-SHA256 hex atas RAW body,
  prefix `sha256=` opsional diterima) diverifikasi SEBELUM parsing JSON.
  Tidak cocok / tidak ada → 401. Respons juga ditandatangani HMAC.
- **Urutan cek trap (deterministik)**:
  1. `PROOF_REUSED` — proof_tx sudah di seen-set lokal
  2. `VK_SUBSTITUTION` — proof_vk ≠ registered_vk, ATAU registered_vk bukan
     vkHash resmi `0x6b79c6…d77b0` (circuit hanya mengecek kesetaraan kedua
     hash; registered-ness harus dicek di sini — lihat /build §04)
  3. `THRESHOLD_MISMATCH` — public_balance < minimum
  4. `EXPIRED_CONDITION` — current_block > expiry_block
  5. `RECIPIENT_MISMATCH` — recipient ≠ condition_recipient
  6. `AMOUNT_OVERFLOW` — amount > max_transfer
  7. Tanpa trap → `APPROVE` / `VALID_CONDITION`
- **Proof**: untuk APPROVE dan semua REJECT yang provable, server generate
  Groth16 lokal dan menyertakan `proof` + `public_signals` di respons.
  `PROOF_REUSED` tanpa proof (dikecualikan dari skor proof).
  Bila proof gagal (seharusnya tidak terjadi bila keputusan benar),
  keputusan tetap dikembalikan tanpa proof + `proof_error` di log.
- **Fail closed**: malformed → REJECT `MALFORMED_TASK`; timeout internal
  50 dtk (deadline platform 60 dtk).
- **Seen-set**: setiap proof_tx yang lolos HMAC dicatat (approve maupun
  reject); pengiriman ulang = `PROOF_REUSED`.

## Skema input circuit (temuan, BUKAN dari halaman publik)

Halaman `/build` tidak mencantumkan nama sinyal. 13 sinyal ditemukan lewat
artikel Creator Track peserta lain lalu **diverifikasi sendiri** dengan
fullProve + verify (lihat `proof-test/probe.mjs`):

`registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision,
taskId, salt` (salt privat; 12 publik + 1 output commitment = nPublic 13).

Encoding yang dipakai (asumsi terdokumentasi, terverifikasi empiris):

- vk hash hex → `BigInt(hex) mod FIELD_PRIME` (hash 256-bit > prima bn128)
- alamat → `BigInt(hex)` apa adanya
- task_id string → `BigInt` dari byte UTF-8, mod prima
- salt → `sha256(task_id + ":" + proof_tx) mod prima` (deterministik)
- decision: `1` = APPROVE, `0` = REJECT

Sifat circuit yang terkonfirmasi: `decision == 1` iff semua cek lapangan
lolos (assert `GatekeeperEvaluation_79` line 102). Keputusan yang salah
tidak menghasilkan witness sama sekali — fullProve gagal dalam ~40–100 ms.
Konsekuensi: untuk kasus pasangan kunci palsu (registered == proof, tapi
keduanya bukan vk resmi), TIDAK ADA proof decision=0 yang valid — server
tetap mengembalikan REJECT yang benar tanpa proof (keputusan +12 tetap
diharapkan; proof −2 mungkin tak terhindarkan pada varian ini).

## Hasil uji lokal

`HMAC_SECRET=test-secret-local-only node test.mjs` → **11 PASS, 0 FAIL**:

| Kasus | Hasil | Waktu total (prove) |
| --- | --- | --- |
| 1 valid | APPROVE / VALID_CONDITION, proof verify OK | 1211 ms (1199 ms) |
| 2 VK_SUBSTITUTION | REJECT, proof verify OK | 334 ms (328 ms) |
| 3 THRESHOLD_MISMATCH | REJECT, proof verify OK | 413 ms (408 ms) |
| 4 PROOF_REUSED | REJECT, tanpa proof (sesuai aturan) | 3 ms |
| 5 EXPIRED_CONDITION | REJECT, proof verify OK | 383 ms (379 ms) |
| 6 RECIPIENT_MISMATCH | REJECT, proof verify OK | 387 ms (383 ms) |
| 7 AMOUNT_OVERFLOW | REJECT, proof verify OK | 300 ms (295 ms) |
| 8 fake-key pair | REJECT / VK_SUBSTITUTION, tanpa proof (circuit tak bisa memprove decision=0 di sini) | 42 ms |
| 9 HMAC dipalsukan | 401 | — |
| 10 tanpa header HMAC | 401 | — |
| 11 POST `/` root | APPROVE / VALID_CONDITION | 278 ms |

Proof test mentah: valid APPROVE fullProve 1021 ms + verify 82 ms;
REJECT trap 374 ms + verify 56 ms; proof JSON ~720 byte.

## Yang BELUM selesai (untuk induk)

1. **HMAC secret asli belum ada** — perlu diambil dari dashboard registrasi
   platform (Rotate Secret) dan disimpan ke `hmac-secret.txt` mode 600.
2. **Endpoint belum publik (HTTPS)** — VM ini tidak punya IP publik; perlu
   deploy ke hosting publik + registrasi endpoint + health check + preflight
   + minimal 1 practice task di platform. Ronde 3 LIVE 15 Nov; ronde 4 buka
   16 Nov 17:30 WIB; entry terkunci saat ronde berjalan.
3. Format tanda tangan respons (hex polos) adalah asumsi umum; bila platform
   mengharapkan format lain (mis. `sha256=` atau base64), sesuaikan
   `signHmac` di `server.mjs`.
4. Encoding `taskId` (byte UTF-8) adalah asumsi — platform kemungkinan hanya
   memverifikasi proof terhadap vk + mencocokkan sinyal yang bisa
   diturunkannya dari task; bila platform menolak proof karena sinyal
   taskId, ini kandidat pertama yang diperiksa.
