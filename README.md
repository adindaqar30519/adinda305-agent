# Adinda305 Agent — Verify First, Then Execute

A personal AI agent that works for one person: **Adinda**, owner of the Binance Agent ID
**adinda305.ai** on BNB Chain. The agent watches markets and mint opportunities around the
clock, **verifies everything on-chain before acting**, and executes only inside rules its
owner approved. Its operating principle is simple:

> **Verify first, then execute. A clean preview executes; a bad preview stops everything.
> Doing nothing is always preferred to a wrong irreversible action.**

## What the agent does

### 1. AGC pump watch + standing sell/claim rule — *live*
Polls the AGC/BNB price (PancakeSwap V2 pair) every 5 minutes. On a confirmed trigger
(price ≥ +80% over the 1.3265e-08 BNB baseline, cross-checked on a second independent
source), it sells the wallet's AGC balance first, then claims the remaining vested
Mode B rewards and sells that tranche too. Every execution is confirmed on a second
RPC / explorer before it is reported as done.

### 2. Free-mint hunter / verifier — *live*
Scans candidate free mints on BSC every 30 minutes. Before anything is reported to the
owner, the contract and the free quota are verified on-chain (site text is never trusted
as proof of state). The hunter never executes a mint by itself — every mint needs the
owner's explicit instruction, and paid mints always state the price first.

### 3. UNSOLVABLE solver — *live, event-driven*
For the unsolvable.art free-mint windows, the agent runs the full flow automatically:
EIP-712 login, puzzle solving, Wesolowski VDF, the 30% lottery, mint permit, and mint.

### 4. Proof Gatekeeper — *built and locally tested; public deployment pending*
A guard that sits in front of execution: an HTTP endpoint that verifies an
HMAC-SHA256 signature over the raw request body **before** parsing, runs **7 deterministic
trap checks** (VK substitution, threshold mismatch, proof reuse, expired condition,
recipient mismatch, amount overflow, valid condition), and attaches a **Groth16 proof**
(generated locally with snarkjs) to its signed response. Without the platform-issued
secret it fails closed. The code lives in this repository (`server.mjs`, `test.mjs` —
local test suite: 11 pass / 0 fail; local Groth16 prove ≈ 1.0 s, verify ≈ 82 ms).
Circuit files (`gatekeeper.wasm`, `gatekeeper_final.zkey`) are the official ones published
at agentgames.zkverify.io/circuits; their SHA-256 hashes match the values published by
the platform's `/api/circuit-info` endpoint (registered vk hash
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).

## How it works

- **Scheduled polling, not guesswork.** Each watch run is a fresh on-chain read, never
  cached site text.
- **Two-source confirmation.** Prices and execution results are confirmed on an
  independent RPC / explorer / market API before being reported. (On 15 Nov 2026 this
  rule caught two separate RPC artifacts — a fake −94% "crash" and a fake 16× price
  spike — and correctly produced *no* action and *no* alarm.)
- **Preview before execution.** Every transaction is simulated first. A reverting or
  unclean preview stops the flow immediately; it is never forced.
- **Human in the loop for irreversible choices.** Free mints execute only on the owner's
  explicit order. Paid actions state the price first and wait for explicit approval.
  Nothing is listed or sold without per-item, per-price approval — except the AGC
  auto-sell, which runs under a standing rule the owner approved on 12 Nov 2026.
- **No keys, ever.** All signing goes through the owner's Binance Agentic Wallet
  (keyless MPC). The agent never handles seed phrases or private keys; only the owner
  can re-authenticate the wallet from her own Binance app.

## On-chain evidence (BNB Chain)

Wallet: `0x5998D60e74240c094E0750211C9e53d96a94fE35` (Ptah-registry-listed owner of adinda305.ai)

| Evidence | What it shows |
|---|---|
| AGC Mode B reward claim, 12 Nov 2026 — tx [`0xd1529c49…5550b011`](https://bscscan.com/tx/0xd1529c49a3dc825a363b7cb80f1ee2762c12bcc412d4a993035088ec5550b011) | The watch claimed vested rewards during a verified +211% pump (4.1309e-08 BNB/AGC). Balance after claim: 1,805,271.34 AGC. |
| PancakeSwap pre-approval, 3,300,000 AGC — tx [`0x85344589…6cbc96c24`](https://bscscan.com/tx/0x85344589eca70c185b8e2d1c2883d224cddef9e90c8a9c009665dac8cbc96c24) | Sell path pre-approved so the standing sell rule can execute without delay. An unused allowance, not funds held by the router. |

Relevant contracts: AGC token `0x63dea5aCdbE1F27c968907D08610A5f0A0284bA6` ·
AGC/BNB pair `0xE56041CdDBB46DB01c67B7A62684F428a04Db8C6` ·
PancakeSwap V2 router `0x10ED43C718714eb63d5aA57B78B54704E256024E`.

**Honest note:** a full auto-sell sequence has not executed yet — the two pumps observed
so far (12 Nov, 14 Nov) collapsed within minutes and the sell was held by the owner at
the time. The standing rule is now sell-first on the next confirmed trigger.

## Repository layout

- `server.mjs` — the Proof Gatekeeper endpoint (HMAC verify → 7 trap checks → Groth16 proof → signed response)
- `test.mjs` — local test suite for the Gatekeeper (11 checks)
- `GATEKEEPER.md` — Gatekeeper design notes
- `verification_key.json` — the circuit verification key (public material)
- `package.json` — Node ≥ 20, single dependency: snarkjs 0.7.6

## Identity note

Adinda is a human. The agent presented here is her personal AI agent (**Muse**), which
automates on-chain verification and execution for the owner of Agent ID adinda305.ai.
It is presented as exactly that — a personal AI agent, not a human.
