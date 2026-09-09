# XLS-0096 Test Suite Threat-Model Coverage Audit

**Scope:** Local workspace only. No remote, GitHub, PR, or prior-branch inspection.
**Artifacts audited:** crypto unit tests, protocol surface tests, app/jtx suites, invariants, `ConfidentialProofHarness`, helpers, autogen TX wrappers.
**Goal:** Identify production bugs the current suite would miss (not merely uncovered lines), with exact file evidence and concrete tests prioritized by security value.

---

## 1. Inventory (what exists)

| Layer | Files | Role |
| --- | --- | --- |
| Crypto unit | `src/test/crypto/Secp256k1_test.cpp`, `CompactSigma_test.cpp`, `Bulletproofs_test.cpp` | Group/ElGamal/field; sigma PoKs; range proofs |
| Protocol surface | `src/test/protocol/ConfidentialTransferProtocol_test.cpp` | Feature/SField/ledger flag/jss registration only |
| Autogen wrappers | `src/tests/libxrpl/protocol_autogen/transactions/ConfidentialMPT*.cpp` | Builder round-trip / serialize; **no** crypto semantics |
| Harness | `src/test/jtx/ConfidentialProofHarness.h` | Context encoding, splice/mutate/foreign BP helpers |
| App/jtx | `ConfidentialMPTIssuance_test.cpp`, `Convert_test.cpp`, `Send_test.cpp`, `ConvertBackClawback_test.cpp` | End-to-end TX + adversarial bindings |
| Invariants | `Invariants_test.cpp` → `testConfidentialMPT()`; impl `MPTInvariant.cpp` / `ValidConfidentialMPT` | Structural SLE rules + OA/COA conservation hooks |
| Helpers | `ConfidentialMPTHelpers.{h,cpp}` | EncZero, context ID, CT parse/homo — **no dedicated unit test file** |
| Fuzz/sanitizer | `sanitizers/` (generic); **no** CMPT/ElGamal/BP/sigma fuzzer targets found |

---

## 2. Threat model (from-scratch)

Derived from `xls-0096.md` §13–14 / FAQ A.7 and `Updated_ConfidentialMPT_20260612.md` (TOB-RIPCTXR-5, compact sigma, Enc(0;e) re-randomization).

### T1 — Soundness / false proofs accepted
Attacker forges a verifying ZK for a false statement (overdraft, wrong balance linkage, wrong sk, unbound amount).

### T2 — Replay / domain separation
Reuse a valid proof across tx type, account, issuance, sequence/ticket, CBS version, destination/holder, or Fiat–Shamir domain tag.

### T3 — Binding splits (sigma vs Bulletproof)
Valid sigma + foreign/unrelated BP (or vice versa) applied to wrong commitments; verifier-split bugs.

### T4 — Ciphertext / commitment algebra
Mismatched C1, PC_m blinding ≠ ElGamal `r`, PC_b unlink from spending CT, ConvertBack `pcRem = PC_b − m·G` wrong formula, EncZero / Enc(0;e) cancellation DoS (TOB-RIPCTXR-5).

### T5 — Accounting / supply
COA/OA/MA invariant breaks; Send mutates COA; Convert/ConvertBack Δ mismatch; clawback burns wrong amounts.

### T6 — Authorization / policy
Auth, lock, dest tag, deposit auth, auditor presence, transfer-fee mutex, issuer-as-holder, amendment gating.

### T7 — Encoding / canonicalization
Non-canonical points/scalars, wrong lengths, infinity, order-n scalars, odd-y / uncompressed, transcript byte-order drift.

### T8 — State machine / concurrency
Stale CBS version, ticket vs sequence context, open-ledger races, version wrap, merge-before-spend, delete-with-confidential-state.

### T9 — Privacy / cross-key misuse
Shared holder keys across accounts (test fixture habit), auditor/issuer key confusion, selective-disclosure gaps (observability only).

### T10 — Implementation oracle / test vacuity
Tests that cannot fail when production verify is wrong the same way prove is wrong; silent mutators; wrong TER stage masks missing preclaim checks.

---

## 3. Coverage matrix

Legend: **S** = strong, **P** = partial, **W** = weak/absent, **V** = vacuous risk.

| Threat | Crypto unit | Harness | App/jtx | Invariant | Protocol/autogen | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| T1 overdraft / range | P | S (foreign BP) | S | W | — | App overdraft tests assert BP stage; crypto has no inconsistent-witness soundness cases |
| T1 balance linkage | P | — | S | — | — | `balance commitment binding` isolates sigma |
| T1 sk / PoK | P | — | S (convert register) | — | — | No cross-type 64-byte PoK swap test |
| T2 context bind | P (random ctx) | S encoders | S (seq/ver/iss/dest/holder) | — | — | **No Ticket**; no cross-tx-type byte reuse |
| T2 FS domain tags | W | — | W | — | — | Tags hardcoded; no KAT / cross-tag reject vectors |
| T3 sigma/BP split | P (header mutate) | S annotate/foreign | S | — | — | IPA interior / multi-limb mutation sparse |
| T4 C1 / role order | P | — | S | — | — | Good role-permutation + sameC1 |
| T4 PC_m ↔ r | W | — | W | — | — | Witness builder always uses same `r` for CT and PC_m |
| T4 Enc(0;e) / EncZero | — | — | S (rerand + M1 cancel) | W | — | Helpers EncZero untested as unit KATs |
| T5 COA/OA | — | — | P (happy paths) | P (synthetic) | — | Synthetic blobs; no real Send conservation case |
| T6 auth/policy | — | — | S | P (flag) | P (flags only) | Strong app coverage |
| T7 canonical enc | S (parse) | V (silent mutate) | P (preflight) | V (Blob{1,2,3}) | V | Invariant ignores CT validity |
| T8 tickets/races | — | — | W | W | — | Seq tested; Ticket/concurrency absent |
| T9 cross-key | — | — | P (one lifecycle) | — | — | Most fixtures share `kScalar1`/`kKeyG` |
| T10 shared oracle | **V** | V | **V** | — | — | prove+verify same impl everywhere; no external vectors |
| Fuzz/ASan crypto | W | — | W | — | — | No CMPT fuzz targets |

---

## 4. What the suite does well (security-relevant)

1. **Verifier-split adversarial tests** — Send/ConvertBack overdraft with foreign BP + annotations (`ConfidentialMPTSend_test.cpp` `testActualOverdraft`, `ConfidentialMPTConvertBackClawback_test.cpp` `testConvertBackActualOverdraft`; harness `makeForeign*Bulletproof` / `annotate*Zk`).
2. **Context bindings** — wrong destination, CBS version, sequence, issuance, holder, amount (clawback), role permutation, C1 mismatch (`testSendContextAndRoleBindings`, `testConvertBackAdversarialBindings`, `testClawbackAdversarialBindings`, convert register PoK bindings).
3. **TOB-RIPCTXR-5 class** — Enc(0;e) must change dest mirrors vs naive add (`testEncZeroRerandomization`); M1 cancel → `tecINTERNAL` on convert/merge/send.
4. **Negative TER + state unchanged** — many `tecBAD_PROOF` cases snapshot version/spending/inbox/COA.
5. **Preflight vs preclaim separation** — Send malformed fields expect `temMALFORMED`/`temBAD_CIPHERTEXT` before proof work (`testSendPreflightMalformed`).
6. **Group encoding gates** — Secp256k1/ElGamal reject short/long/uncompressed/infinity; scalars reject 0 and `n`.
7. **BP Protocol-1 scalar binding** — mid-byte flips on A,S,T1,T2,tauX,mu,tHat (`Bulletproofs_test.cpp` `testProtocol1ScalarBinding`).

---

## 5. Critical findings (bugs the suite would miss)

### F1 — Shared prove/verify implementation oracle (T10 / T1 / T2)
**Evidence:** Crypto and app tests always `proveX` then `verifyX` from `CompactSigma.cpp` / `Bulletproofs.cpp`. Explicit residual in `Bulletproofs_test.cpp:178–181` (“fixed cross-library proof vectors are unavailable”).
**Missed bug class:** Systematic Fiat–Shamir transcript bug (append order, endianness, missing domain byte, hashing SHA-512 vs SHA-512-Half inconsistently between prove and verify) that keeps prove↔verify consistent but diverges from the addendum. Interop clients / alternate implementations would disagree; consensus nodes sharing the bug would still agree.
**Also:** App tests re-implement EncZero message assembly (`encZeroRandomness` in Send/Convert/ConvertBack tests) calling the same `hashToCurveScalar` as production `encZero()` — cannot detect tag typo shared across both.

### F2 — No independent KATs for NUMS H, EncZero, context ID, domain tags (T2 / T7)
**Evidence:**
- `pedersenH()` only checked `H==H2` and `H≠G` (`CompactSigma_test.cpp:83–93`) — no fixed compressed hex.
- `confidentialTxContextID` / EncZero have **no** dedicated unit tests; only used via app helpers.
- Domain tags `"CMPT_*"` appear only in production `.cpp`; no test asserts exact ASCII bytes or rejects cross-tag proofs.
**Missed bug:** Wrong NUMS counter / even-y prefix; EncZero tag `"EncZero"` vs `"ENCZERO"`; context ID using LE sequence; ConvertBack TxSpecific using Destination≠Account.

### F3 — PC_m blinding ≠ ciphertext `r` never attacked (T4 / T1)
**Evidence:** `buildSendWitness` always does `pedersenCommit(amount, r)` with the same `r` used for ElGamal (`ConfidentialMPTSend_test.cpp:334–387`). No case builds CTs under `r` and PC_m under `r'≠r` (with honest BP on those commitments) and expects `tecBAD_PROOF` from **sigma**.
**Missed bug:** Production `verifySendSigma` dropping PC_m linkage equations while still verifying CT equality / balance — overdraft tests would still pass via BP; balance-binding test uses wrong **balance**, not unlinked amount commitment.

### F4 — ConvertBack `pcRem = PC_b − m·G` shared with test oracle (T4)
**Evidence:** Production `ConfidentialMPTConvertBack.cpp:227–233` and test `makeConvertBackZk` (`ConvertBackClawback_test.cpp:232–238`) both subtract `m·G`. If production incorrectly used `PC_b − PC_m` (Send-style) **and** tests copied it, suite stays green while amount blinding/`r` semantics break.
**Missed bug:** Algebraic rem construction drift vs addendum §4.6; needs an assertion that `pcRem == pedersenCommit(b−m, ρ)` from known openings, independent of proveRange.

### F5 — Register PoK ↔ Clawback size alias (64 bytes) (T2)
**Evidence:** `kRegisterPoKSize == kClawbackSigmaSize == 64` (`CompactSigma.h:17–20`). No app/crypto test submits a **valid** register PoK blob as Clawback `sfZKProof` (or reverse) under matching context length.
**Missed bug:** Missing/confused domain tag check; accidental verify-register path in clawback; silent accept if tags ever unified.

### F6 — Ticket sequences unbound in tests (T2 / T8)
**Evidence:** Production binds `tx.getSeqProxy().value()` (`ConfidentialMPTSend.cpp:345`, Convert/ConvertBack/Clawback similarly). Grep of Confidential* app tests: **zero** Ticket/`sfTicketSequence` usage. Only Account Sequence mismatches are tested.
**Missed bug:** Context built from AccountRoot Sequence while tx uses Ticket (or vice versa) → replay across ticketed submissions or false rejects.

### F7 — Mutation harness can silently no-op (T10)
**Evidence:** `mutateProofByte` (`ConfidentialProofHarness.h:168–172`) returns without failing if `offset >= size`. A wrong offset in a “tamper → tecBAD_PROOF” test would submit a **valid** proof; if Env unexpectedly succeeds, only later assertions might catch it — or a flaky path could mask a missing verify.
**Missed bug:** False confidence in mutation coverage; IPA limbs rarely targeted (Send BP mutate uses only `bpTauXMidOffset()`).

### F8 — Invariant tests use non-ciphertexts (T7 / T5 vacuity)
**Evidence:** `Invariants_test.cpp:4524–4525` uses `Blob{0x01,0x02,0x03}` as “spending/issuer” fields. `ValidConfidentialMPT` checks presence/version/COA≤OA/flag — **not** 66-byte parseability (`MPTInvariant.h:120–143`).
**Missed bug:** doApply writing truncated/invalid CT bytes that still pass invariants; ledger stuck with unparsable balances (DoS) without invariant fire. App paths often catch via later parse → `tecNO_PERMISSION`, but invariant is not a backstop.

### F9 — No crypto-layer inconsistent-witness / empty-n tests (T1)
**Evidence:** `CompactSigma_test` only honest + tamper + wrong context/point. `proveSendSigma` allows `recipientPks.empty()` → nullopt (`CompactSigma.cpp:342–344`) but **no test**. No “prove with amount≠ciphertext plaintext then verify fails” case.
**Missed bug:** verify accepting empty recipient list; prove/verify disagreeing on n=0/1 edge; completeness-only suite missing soundness regressions.

### F10 — Concurrency / same-version double-spend (T8)
**Evidence:** Suites are single-threaded `Env` with `env.close()` between txs. No open-ledger two-Send with identical CBS version / competing spends.
**Missed bug:** Version bump omitted in doApply but preclaim checked once; second tx in same ledger applies on stale spending (classic TOCTOU). Current happy-path asserts `version+1` after one Send but never races two.

### F11 — Spec TER stage mismatches only documented, not locked (T6 / T10)
**Evidence:** Comments note §8.3.1 `temMALFORMED` vs implementation `tecNO_PERMISSION` for issuer-as-sender (`ConfidentialMPTSend.cpp:233–236`, test `issuer as sender`). Tests lock **implementation** TER, so a “fix” that returns `tesSUCCESS` would fail — but a change to wrong soft-fail that still claims fee differently than spec intended is only partially constrained.
**Lower severity** than F1–F10; still a protocol-compliance gap.

### F12 — No sanitizer/fuzzer coverage for CMPT crypto (T1 / T7)
**Evidence:** No fuzz targets under `src/` for Bulletproofs/CompactSigma/ElGamal; `sanitizers/` has no CMPT-specific harness. Random completeness loops use `cryptoPrng` but not structure-aware mutation of proofs/points.
**Missed bug:** Memory/UB in verify on malformed IPA; timing-unsafe scalar paths; parser crashes on adversarial VL lengths that pass preflight size checks via other fields.

### F13 — Protocol_test + autogen are registration-only (T10)
**Evidence:** `ConfidentialTransferProtocol_test.cpp` asserts field numbers/flags/jss; autogen tests round-trip builders with `canonical_VL()` junk proofs.
**Missed bug:** None cryptographic — but reviewers may over-count these as “protocol security tests.”

---

## 6. ConfidentialProofHarness review

| Helper | Intent | Gap |
| --- | --- | --- |
| `*ContextID` / `encode*TxSpecific` | Mirror production context | Duplicates production layout; if both wrong, tests pass (F2) |
| `splice*Zk` | Concatenate sigma‖BP | Does not assert sizes against production `kSendZkProofSize` constants in transactors (duplicated magic in tests) |
| `mutate*Byte` | Adversarial bitflip | Silent OOB (F7); no “must mutate” assert |
| `makeForeign*Bulletproof` | Split verifier | Strong; used correctly in overdraft tests |
| `annotate*Zk` | Document intent | Flags never consumed by asserts beyond BEAST_EXPECT on the flags themselves — documentation-only |
| Missing | | `expectRejectAt(sigma\|bp\|preflight)`, Ticket context, cross-domain proof swap, PC_m unlink builder, fixed KATs |

---

## 7. Concrete tests to add (prioritized)

### P0 — Highest security value

1. **Independent Fiat–Shamir / NUMS / EncZero / Context KATs**  
   - File: new `src/test/crypto/ConfidentialTranscript_test.cpp` + `src/test/unit` or `src/test/app` helper test.  
   - Freeze hex for: `pedersenH()`, EncZero(r) for fixed (account,issuer,issuance,pk), `confidentialTxContextID` for each tx type with fixed inputs, and one full Send/ConvertBack/Clawback/Register proof verify against **canned** public statement + proof bytes checked into the tree (even if generated once by a script).  
   - Catches F1/F2.

2. **Send: PC_m blinding ≠ ElGamal `r`**  
   - In `ConfidentialMPTSend_test.cpp`: encrypt under `r`, set `PC_m = pedersen(m,r')`, `PC_b` honest, BP aggregated on `(PC_m, PC_b−PC_m)` with openings `(m,r')` and rem, sigma proved with inconsistent witnesses **or** honest sigma for CT/`r` but swapped commitment — expect `tecBAD_PROOF`, and assert `verifySendSigma` false while `verifyRange64Aggregated` true (stage isolation like balance-binding test).  
   - Catches F3.

3. **ConvertBack rem opening identity**  
   - With known `(b,ρ)`, assert `pointSubtract(PC_b, m·G) == pedersenCommit(b−m, ρ)` before BP; separately assert BP verifies that commitment. Do **not** only call the shared `makeConvertBackZk`.  
   - Catches F4.

4. **Cross-type 64-byte proof swap**  
   - Valid `proveRegisterPoK` submitted as Clawback ZKProof → `tecBAD_PROOF`; valid clawback as Convert register → `tecBAD_PROOF`.  
   - Crypto unit: `verifyClawbackSigma(..., registerProof, ...)` false and vice versa for same ctx size.  
   - Catches F5.

5. **Ticket-bound context**  
   - Create Ticket for sender/issuer; build proof with `getSeqProxy()` ticket value; success path; proof built with Account Sequence while tx uses Ticket → `tecBAD_PROOF`.  
   - Catches F6.

### P1 — High value

6. **Harness harden:** `mutateProofByte` `XRPL_ASSERT`/`BEAST_EXPECT` on in-range; add `mutateSendBpIpaByte` targeting L/R mid-limb and `a`/`b` scalars; require annotated flags in overdraft tests to match observed reject stage (hook via test-only verify order probes).

7. **CompactSigma soundness edges:** empty recipients; n=1; prove with wrong amount vs CT then verify false; prove ConvertBack with `pcB` not matching balance CT; clawback amount≠CT without relying only on app.

8. **Domain-tag negative unit tests:** append wrong tag in a local transcript rebuild of verify (or temporary test hook) — at minimum, feed Send sigma bytes into `verifyConvertBackSigma` (size mismatch) and truncated Send into Clawback.

9. **Invariant ciphertext parseability (optional amendment):** when confidential fields present, require `ElGamalCiphertext::parse` success — or a new invariant test that applies a synthetic after-SLE with 3-byte CT and expects failure **if** product decides this is in-scope. Today it is explicitly out of `ValidConfidentialMPT`; document or extend.

10. **Open-ledger double Send:** two Send txs in one ledger with proofs for the same CBS version; first succeeds, second `tecBAD_PROOF` (or seq), spending not double-decremented. Catches F10.

11. **Helpers unit tests:** `encZero` determinism + difference across account/issuer/issuance; `homomorphicAdd/Sub` infinity; `validateElGamalCiphertext` TER; context ID byte layout (BE uint16/uint32).

### P2 — Important hardening

12. **BP aggregated KAT + domain cross:** single proof rejected by aggregated verify (partially present); aggregated proof under `"CMPT_BP_RANGE64"` tag swap if testable; values `(0,0)`, `(2^64−1,2^64−1)`.

13. **Scalar boundary:** `n−1` accepted; challenge reduction counter path (force via crafted transcript if possible).

14. **Clawback m=0** already rejected in crypto; add app `tem`/`tec` gate for amount 0 if preflight allows.

15. **Version `UINT32_MAX` wrap:** spending modify with version overflow behavior documented/tested.

16. **Distinct-key default fixtures:** change `fundConvertMerge` defaults to distinct holder keys (or assert inequality) to avoid masking pk mix-ups (T9).

17. **Structure-aware fuzzers** under ASan/UBSan for `verifySendSigma` / `verifyRange64*` / `ElGamalCiphertext::parse` with size-correct random bytes.

18. **Spec TER compliance tests** (optional): document expected intentional deviations; add compile-time or test comments linking XLS clause → TER so silent drift is reviewed.

---

## 8. Suggested reject-stage checklist (for new negative tests)

Every adversarial proof test should assert **which** check fails, not only `tecBAD_PROOF`:

| Stage | How to isolate |
| --- | --- |
| Preflight | Expect `temMALFORMED` / `temBAD_CIPHERTEXT`; proof verify not reached |
| Auth/policy | Expect `tecNO_*` / `tecLOCKED` with **valid** proofs |
| sameC1 | Valid sigma for matched C1; replace one CT r → `tecBAD_PROOF` before sigma (already done) |
| Sigma | Foreign/valid BP; corrupt sigma only; or false statement with valid BP |
| BP | Valid sigma; foreign or mutated BP |
| Homomorphic representability | M1 cancel / infinity add paths (`tecBAD_PROOF` vs `tecINTERNAL`) |

Use harness annotations + optional local `verify*` probes (as in `testBalanceCommitmentBinding`) so deleting the production stage check fails the test.

---

## 9. File evidence index

| Topic | Path |
| --- | --- |
| Harness | `src/test/jtx/ConfidentialProofHarness.h` |
| Sigma/BP/ElGamal tests | `src/test/crypto/{CompactSigma,Bulletproofs,Secp256k1}_test.cpp` |
| Protocol registration | `src/test/protocol/ConfidentialTransferProtocol_test.cpp` |
| App suites | `src/test/app/ConfidentialMPT{Issuance,Convert,Send,ConvertBackClawback}_test.cpp` |
| Invariants | `src/test/app/Invariants_test.cpp` (`testConfidentialMPT`), `src/libxrpl/tx/invariants/MPTInvariant.cpp` |
| Production verify order | `src/libxrpl/tx/transactors/token/ConfidentialMPT{Send,Convert,ConvertBack,Clawback,MergeInbox}.cpp` |
| Helpers | `include/xrpl/ledger/helpers/ConfidentialMPTHelpers.h`, `src/libxrpl/ledger/helpers/ConfidentialMPTHelpers.cpp` |
| Spec threat notes | `xls-0096.md` §13.8, FAQ A.7; `Updated_ConfidentialMPT_20260612.md` §1 (TOB-RIPCTXR-5), Remarks 3.1–3.4, 4.1 |

---

## 10. Executive verdict

The app-level adversarial suite is **unusually strong** on context binding, verifier-split overdraft, Enc(0;e) re-randomization, and TER+ledger snapshots. The largest residual risk is **shared-implementation oracle blindness**: transcript/NUMS/EncZero/context bugs that preserve prove↔verify consistency, plus **untested PC_m↔r unlink**, **Ticket context**, **64-byte cross-type proof aliasing**, and **no fuzz/KAT backbone**. Invariants are structural only and will not catch invalid ciphertext bytes or cryptographic forgery.

Prioritize P0 items 1–5 before expanding more policy gate tables.
