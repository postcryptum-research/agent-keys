# Design review — PR #5 `docs/MOBILE_OWNER_DESIGN.md` (rev 4902619)

Reviewer: security-audit (adjudicator). Verified firsthand against the branch at
`4902619` and the deployed contracts (`P256Validator.sol`, `deployments/84532.json`)
read from `77ph/TPM_sign` at `master`. Verdict per point: **OK / CHANGE / BLOCKER**,
plus owner-decision flags where the call is product intent, not security mechanism.

**Overall:** strong spec. The core invariants — QR commitment as the trusted
channel, one parse into one `Review` with the digest released only after approval,
no laptop-chosen digest, co-randomised health digest, full addresses + 80-bit
fingerprints, the gas cap, the default-method trait change — are right and, where
they touch the code, they hold. No BLOCKER. The changes below are real and worth
making before P0; four are owner decisions.

---

## Q1 — Pins are trust-on-first-use from the laptop — **CHANGE**

TOFU-from-laptop is a genuine gap: a laptop compromised **at enrollment** (not
just at signing, which is T1) permanently poisons the pins — e.g. it labels a
malicious contract "AgentPolicy", and the phone then renders a later malicious
policy install as a *pinned, trusted* fact. That is strictly worse than T1,
because the poison is silent and durable, and the phone's whole value is that it
shows the truth.

- Your proposal (embed `deployments/84532.json` at build time; mark laptop pins
  "from the laptop") is the right direction and is **enough as the v1 baseline** —
  with two refinements:
  1. Build-embedded pins render as **"verified in this build"**; anything the
     laptop adds beyond the snapshot renders as **"from the laptop — unverified"**,
     visually subordinate, never as a fact. This matches your §6.3 label rule;
     extend it to the pin set itself.
  2. **Token decimals** from an unverified source are dangerous (they scale the
     displayed amount). A laptop-added token shows raw units + "unverified
     decimals", never a scaled amount.
- The snapshot goes stale (agentPolicy already has V1–V5 on 84532). So the
  build-embedded set must include the **version history** actually deployed, and
  "superseded version" must be a build-verified fact, not a laptop claim.
- The durable answer to freshness is the on-chain Registry (Addendum 1), but that
  needs the phone's own chain access → **v2**. v1 = snapshot + labels.

## Q2 — D4: warn-only on unknown external calls for the root key — **CHANGE (owner decision)**

Under T1 this is the weakest point in the signing path. An unknown external call
from the **root** key is unbounded: the gas cap bounds the ETH prefund, but the
call itself can move everything the account holds (token transfers, approvals,
arbitrary contract state). So for unknown-target calls the only barrier is "user
approves past a warning" — exactly the barrier T1 says not to rely on.

- The counter-argument (your D4 rationale: "`op send --root` exists to call
  arbitrary targets") is legitimate — refusing all unknown calls defeats its
  purpose. So this is a product-intent call, not a pure security call → **owner
  decides**.
- My recommendation: **default refuse** unknown root external calls; a
  per-enrollment **expert-mode toggle, default-off**, re-enables them with
  warn + second confirmation. Then the safe default is safe, and the power path
  is an explicit, opt-in, per-device choice — which is what "expert mode" should
  mean. The second confirmation, when enabled, must state the **unbounded
  effect** in plain words ("this calls an unknown contract that can move
  everything this account holds").

## Q3 — Tamper invariant §9.2 + gas §6.4 — **CHANGE**

You are right, and it is sharper than stated: swapping `verificationGasLimit` ↔
`callGasLimit` (both packed in `accountGasLimits` in v0.7) changes `userOpHash`
but leaves `verificationGasLimit + callGasLimit` — and therefore the only
displayed number, max cost — **unchanged**. That **violates the §9.2 invariant**
("no byte may change the hash without changing the text").

Two distinct fixes, both needed:
1. **Show all gas fields + the nonce under "details"** — `verificationGasLimit`,
   `callGasLimit`, `preVerificationGas`, both paymaster limits, `maxFeePerGas`,
   `maxPriorityFeePerGas`, full `nonce`. Then every hash input maps to displayed
   text; the swap changes the text. This is necessary and sufficient for §9.2.
2. **The §9.2 *test* as worded does not enforce the invariant.** "Each flip is
   refused, or changes the text, *or* changes the hash" — the swap *changes the
   hash*, so it passes the test while violating the invariant. Tighten the test
   to: **every flip that changes the hash must change the displayed text** (hash
   change ⇒ text change). Keep "refused" as the third branch for bytes that fail a
   §6.2 check.

Cap formula: `(vgl + cgl + pvg + pmVerificationGasLimit + pmPostOpGasLimit) ×
maxFeePerGas` is **correct for v0.7's max prefund**. But the paymaster case has a
hole: when a paymaster sponsors, the account's **ETH** exposure is ~0, yet a
paymaster can charge the account in **tokens** in `postOp` (the x402 path the
mandate references). That outflow is **not bounded by the ETH gas cap**. So:
with a paymaster, show "ETH sponsored by `<paymaster>`" **and** surface + cap any
token the paymaster is authorised to pull — otherwise a pinned-but-malicious or a
mis-pinned paymaster is an unbounded token drain the gas cap never sees.

## Q4 — one signature with a bundler; verificationGas underestimate — **CHANGE**

The real hazard is the **placeholder-signature length**, and the code makes it
concrete. `P256Validator._verify` does `if (signature.length != 64) return false;`
**before** `P256.verifySignature`. If the estimation placeholder is not exactly 64
bytes, estimation short-circuits before the P-256 verify, so the measured
`verificationGasLimit` **omits** the verify cost; the real 64-byte signature then
runs the full P-256 path → AA23 out-of-gas in validation → the op fails **and**
you've spent a biometric prompt for nothing.

- **Requirement:** the estimation placeholder must be **exactly 64 bytes** (a
  dummy `r‖s`), so `_verify` runs the full `P256.verifySignature` during
  estimation. P-256 verify gas does not depend on validity, so a 64-byte garbage
  sig measures the same gas as the real one — *as long as it clears the length
  gate*.
- Precompile vs fallback: `P256.verifySignature` (Solady) uses the RIP-7212
  precompile when present (~3.4k gas) and a pure-Solidity fallback when not
  (~hundreds of k). Presence is a chain constant, so estimation and execution use
  the same path — the divergence risk is the length gate above, not the
  precompile. Still, because the two differ ~100× and estimation is the only
  guard, add a **verificationGasLimit margin (~15–20%)**. Confirm Base Sepolia
  exposes RIP-7212 at `0x100` and record the expected ~3.4k so a regression (op
  routed to the fallback) is visible.
- `validateUserOp` returning `SIG_VALIDATION_FAILED` (not revert) — verified in
  the contract — is what lets estimation complete at all; keep relying on it.

## Q5 — plan B: `DIGEST_NONE` + `DIGEST_SHA256` on one key — **OK, with a CHANGE**

No practical cross-protocol collision. `P256Validator` verifies raw ECDSA over
`userOpHash` (NONEwithECDSA: the 32-byte hash *is* the message). ZeroDev's
WebAuthn validator verifies over `sha256(authenticatorData ‖ sha256(clientDataJSON))`
(SHA256withECDSA). For one validator's signature to verify on the other you would
need `userOpHash == sha256(authData ‖ sha256(clientDataJSON))` — a SHA-256
preimage/collision. Infeasible. (And `userOpHash` is keccak-based, a different
family again.) So enabling both digests does **not** by itself widen the exploitable
surface.

What must hold, as explicit requirements:
1. **Only one validator is root at a time.** Plan B is a one-way `set-root` that
   **retires** the old `P256Validator` in the same operation (your §2.2 already
   retires on handover; keep that for the switch). Two live validators accepting
   the same key is the only way the latent capability becomes a real dual-accept
   surface.
2. **Gate `SHA256withECDSA` to the plan-B WebAuthn-envelope builder only.** The
   key *can* sign a WebAuthn envelope; `owner-core` must be the sole caller and
   only for that envelope — never over an arbitrary `clientDataJSON`, which would
   be a laptop-chosen-digest path through the back door (§6.5).
3. **Add a cross-protocol test:** a signature produced for one validator must not
   verify for the other.

Health digest: **safe.** `sha256("TPM_sign/v1/health" ‖ laptopNonce ‖ phoneNonce)`
is domain-separated, co-randomised by the phone (laptop can't choose it), and in a
different hash family from `userOpHash`; it cannot be a valid WebAuthn digest
(would need a SHA-256 collision) nor a `userOpHash`. Keep it NONE-path.

## Q6 — D2 biometric-only — **OK (owner decision)**

Security posture is right: no PIN fallback removes the shoulder-surf path, and
`invalidatedByBiometricEnrollment` removes the add-my-own-fingerprint path. The
cost — a broken sensor or changed biometric forces recovery — is acceptable
*because* recovery is already mandatory (`RESILIENCE.md`) and the key is
one-per-account, so a dead key loses one account's control, not everything.

The one condition: biometric-only **leans entirely on recovery**, so recovery must
be genuinely robust and tested before this ships — don't adopt biometric-only
without that. Whether the availability cost is acceptable is the owner's call;
default biometric-only is the right default, and offering `DEVICE_CREDENTIAL` as a
per-enrollment opt-in (not the default) is a reasonable escape valve if the owner
wants it.

## Q7 — D5 iOS App Attest — **OK (owner decision), keep it**

App Attest adds real, bounded value: it binds `K` to a genuine instance of *our*
app (our team/bundle id) on genuine Apple hardware, which defeats a third-party
fake app or emulator enrolling an exportable key. It does **not** prove SE
residency — correctly stated in §5.3. So it does not solve T6 (our own build
going bad), but it is strictly stronger than "no attestation + T2". "No
attestation + T2" is weaker: the on-chain T2 check catches a wrong *key*, but a
legitimately-enrolled-but-software/exportable key passes T2 while not being
hardware-bound. So **keep App Attest as the default** + `--allow-no-attestation`
for users who refuse the network (already designed) + T2 as a *complement*, not a
replacement. The doc's honesty about what it proves is correct — keep that wording.

## Q8 — threat model additions

Add / strengthen:
- **T19 Enrollment-time pin poisoning** (distinct from T2, which is about the
  *key*): a laptop compromised at enrollment poisons the pinned addresses/labels,
  so later malicious installs render as trusted. Mitigation = Q1 (build-embedded,
  verified-vs-laptop labels; Registry in v2).
- **T2 residual understated — the handover window race.** Even with the
  third-device check, between the `set-root` landing and the first check the
  substituted key **holds root** and can re-rotate or drain. State this window in
  the residual, and prefer the prevention fix (Addendum 2(d)) over detection.
- **T20 Paymaster token charge beyond the ETH gas cap** (Q3): a sponsored op that
  pulls tokens in `postOp` is an outflow the ETH cap does not bound.
- **T21 No independent chain view in v1 (D1, LAN-only)** — the umbrella residual:
  the phone takes *all* chain facts (pins, which validator is root, whether its
  key still controls the account, balances) from the laptop. Everything in Q1 /
  Addendum 1 / Addendum 2 is an instance of this. Name it, so v1's security
  ceiling is explicit: v1 shows what it can **decode** and what is
  **build-embedded**, but verifies **no** chain state.
- (If Q3 fix is deferred) the `vgl↔cgl` display/hash mismatch is itself a threat.

---

## Addendum 1 — on-chain Registry

- **(a) Who reads it — correct concern, decisive.** A Registry read **by the
  laptop** adds nothing: the laptop can lie about the result. It only helps if the
  **phone** reads it over its **own** RPC, independent of the laptop. So the
  Registry presupposes phone chain access → **v2** (v1 is LAN-only, D1). A
  trustless read needs a light client; an RPC provider is a weaker but acceptable
  v2 start (see Addendum 2(b)).
- **(b) Compromised multisig / signer error — mitigated, not prevented.** The
  asymmetric timelock (adds after N days; removals + revocations immediate) +
  events + "registered N days ago" is a sound *monitoring-and-response* design:
  immediate revocation is the right fail-safe direction, and the delay gives
  detection time. But it does not *prevent* a bad entry from going live after N
  days, and a project-level Registry is a single point of failure for **all**
  users at once. So: keep the timelock + immediate-revoke, **and** keep the phone
  showing the full address + "registered N days ago" + treating a Registry entry
  as "the project vouches", never as "safe". Defense in depth: the Registry
  informs the display, it does not replace the user reading the address.
- **(c) Hybrid — this is the right design.** App carries the Registry's CREATE2
  address + a build-embedded baseline snapshot; the phone reads the Registry over
  its own RPC only for what the snapshot lacks; laptop pins stay labelled. This
  gives the offline/verified common case (snapshot) + freshness (Registry) +
  clear subordination (laptop). Adopt as the **v2 target**.
- **(d) Codehash pins (EXTCODEHASH) for stateless singletons — worth it, v2.**
  `P256Validator`, `P256Signer`, `AgentPolicy` are non-proxy stateless logic, so
  pinning `EXTCODEHASH` lets the phone catch a **code** swap, not only an address
  swap — but checking it requires reading the chain → v2 (phone RPC). Pin **both**
  address and codehash. Do **not** codehash-pin anything behind a proxy (you'd pin
  the proxy, not the implementation); none of these three are proxies, so it's
  clean. Confirm before relying on it.

**v1 / v2 split (recommendation):**
- **v1** — build-embedded snapshot (verified) + laptop pins labelled; LAN-only;
  no phone RPC. Handover prevention via Addendum 2(d), which needs no RPC.
- **v2** — phone gets its own chain access, and it unlocks, together: Registry
  freshness, codehash verification, and the handover/root-status on-chain checks
  (Addendum 2). These three are one feature — "the phone can see the chain" — and
  should ship together.

## Addendum 2 — phone verifies the handover on-chain

- **(a) Does it close T2? Improves, does not close — the window race.** A
  post-handover + periodic read of `P256Validator.publicKeys(account) == own key`,
  `rootValidator() == pinned P256Validator`, and the installed-validator list is a
  good **detection** layer. But it is detection, not prevention: in the window
  between the malicious `set-root` landing and the first check, the attacker holds
  root and can change root again or drain. So it narrows but does not eliminate
  T2. The root cause is signing `set-root` **blind**; fix that at the source (d).
- **(b) RPC trust.** Single provider = trust that provider (it can lie about
  `publicKeys`). Reasonable **v2 minimum: a 2-of-3 quorum of independent public
  RPCs** agreeing on `publicKeys(account)` and `rootValidator()`. A mobile light
  client (Helios-style) is the aspirational target (trust-minimised via a block
  header) but heavy; don't gate v2 on it. Start with the quorum, note the
  light-client upgrade.
- **(c) v1/v2 split — agree, with one carve-out.** Own-RPC belongs in v2 (it's the
  same "phone sees the chain" feature as Addendum 1). **But** the handover is the
  single most dangerous operation — it is where a compromised laptop *permanently*
  steals the account — so it deserves protection in **v1**. The right v1
  protection is **(d)**, which needs no RPC, not a v1 phone-RPC check.
- **(d) Decode the `set-root` on a phone — yes, this is the real T2 fix (v1).**
  The blind `set-root` signed on the laptop is the root problem. Route it through
  the same decode-and-show phone flow: the **current** owner signs `set-root` on a
  phone that decodes it and shows "**hand control to key `<fingerprint>`**". A
  substituted key is then **visible** (shown fingerprint ≠ the intended new
  phone's fingerprint) — prevention, not detection, and no network.
  - This works directly for **phone → phone** handovers (the old phone decodes).
  - The hard residual is the **first** handover (a non-phone owner key → the first
    phone): the old key signs on the laptop, under T1. For that case keep the
    fingerprint match (phone shows its fingerprint at enrollment; the laptop's
    `set-root` must name exactly that fingerprint; the signer confirms it on a
    clean view) **plus** the third-device on-chain check. Document the first
    handover as the one step to do from a clean machine.
  - Recommendation: adopt (d) for v1; add the phone-RPC checks (a) as v2
    defense-in-depth once the phone has chain access.

---

## Summary

- **BLOCKER:** none.
- **CHANGE (security, do before P0):** Q1 (build-embed + labels), Q3 (show all
  gas fields + tighten the §9.2 test + paymaster token-charge), Q4 (64-byte
  placeholder + margin), Q5 (one-validator-at-a-time + gate SHA256withECDSA +
  cross-protocol test). Addendum 2(d) (decode `set-root` on a phone) for v1.
- **OWNER DECISIONS (product intent, flagged):** Q2 (refuse-by-default +
  expert-mode vs warn-only), Q6 (biometric-only availability cost), Q7 (App Attest
  + Apple dependency), and the v1/v2 split — specifically that v1 cannot verify
  chain state (T21) and v2 = "phone sees the chain" (Registry + codehash +
  handover check shipped together).
- **OK as proposed:** Q5 cross-protocol safety and the health digest; the QR
  commitment channel; one-parse-one-Review; no laptop-chosen digest; full
  addresses + fingerprints; the default-method trait change.

---

## Since this review (added 2026-11-19; not part of the review)

What the code does on 2026-11-19 with the points above. The review itself
is unchanged.

Implemented:
- **Q1** — build-embedded names render as "(verified in this build)" and
  laptop pins as "(pinned by the laptop at enrollment — unverified)"; a
  token the build does not know shows "(raw units, unverified decimals)"
  (`mobile/owner-core/src/review.rs`). Superseded versions are named by the
  build, from the embedded `deployments/84532.json`
  (`mobile/owner-core/src/facts.rs`).
- **Q2** — refuse by default; expert mode is per enrollment and off by
  default (`review.rs`, `expert_mode`).
- **Q3**, gas fields — the "Details" section shows the nonce,
  `verificationGasLimit`, `callGasLimit`, `preVerificationGas`,
  `maxFeePerGas` and `maxPriorityFeePerGas`, and the paymaster's two limits
  when there is one (`review.rs`).
- **Q4** — the estimation placeholder is a 64-byte `r‖s`
  (`PLACEHOLDER_SIGNATURE`) and the bundler's verification estimate gets a
  20% margin (`signer/crates/agent-signer/src/chain.rs`).
- **Addendum 2(d)** — the phone decodes a root change and shows "Hand
  control of this account to key `<fingerprint>`" (`review.rs`).

Done differently:
- **Q3**, paymaster token charge — not surfaced and capped: the phone
  accepts only paymasters without a `postOp` (`review.rs`, §6.4 of the
  design).

Not done:
- **Q7** — App Attest is not built. `agent-signer` verifies Android key
  attestation only, the iOS app sends no attestation, and an iOS key is
  enrolled only with `--allow-no-attestation`
  (`signer/crates/agent-signer/src/phone.rs`, `docs/APP_ATTEST_ORG.md`).

Two facts of the review that have moved or need a qualifier:
- Q1, "agentPolicy already has V1–V5 on 84532": `deployments/84532.json`
  now lists V1–V6.
- Addendum 1(d), "non-proxy stateless logic": the three contracts are not
  proxies, but each holds per-account storage (`publicKeys`, `configs`),
  which `EXTCODEHASH` does not cover; the codehash argument needs only that
  their code cannot change.
