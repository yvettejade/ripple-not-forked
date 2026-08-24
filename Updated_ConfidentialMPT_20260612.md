# Unified and Compact Zero-Knowledge Proofs for Confidential MPT Transfers on the XRPL with Ciphertext Re-randomization

## 1 Introduction

This document specifies the updated transaction-level cryptographic proof constructions for Confidential Multi-Purpose Tokens (Confidential MPTs) on the XRP Ledger, incorporating the compact AND-composed sigma protocol of [2]. It supersedes the following sections of the original Confidential MPT specification [1]: Appendix B (Schnorr proof of knowledge of secret key, updated to compact form); Appendix C (Chaum–Pedersen ciphertext–amount consistency proof for ConfidentialMPTClawback); Appendix D (same-plaintext equality proof for ConfidentialMPTSend); Appendix E in both variants (Variant A: amount linkage for ConfidentialMPTSend; Variant B: balance linkage for ConfidentialMPTSend and ConfidentialMPTConvertBack); the ZKProof field definitions and proof size entries in the transaction field tables of Section 6; and the transaction size analysis of Section 9. All other protocol elements — state transitions, ledger accounting invariants, supply semantics, and security definitions — remain as specified in the original document.

The original Confidential MPT specification introduced a protocol for hiding individual account balances and transfer amounts on the XRP Ledger while preserving public, trustless verification of total token supply. Confidentiality is achieved through EC–ElGamal encryption over secp256k1, with correctness enforced by non-interactive zero-knowledge proofs (NIZKPs). The original proof constructions followed a modular design: each correctness property — same-plaintext equality across ciphertexts, linkage between ElGamal ciphertexts and Pedersen commitments, and balance sufficiency — was established by a separate, independently verified proof. While correct and sound, this modular approach resulted in redundant witness material and inflated proof sizes, particularly for the ConfidentialMPTSend transaction, which required three independent sigma proofs totalling approximately 619 bytes before the Bulletproof range proof.

The key observation motivating the present revision is that reusing the ciphertext randomness $r$ as the blinding factor in the amount Pedersen commitment $\mathrm{PC}_m = m \cdot G + r \cdot H$ unifies the amount commitment with the recipient ciphertexts under the same witness pair $(m, r)$. Once this choice is made, the same-plaintext equality proof and the amount linkage proof are no longer independent statements — both are expressed in $(m, r)$ simultaneously, and the shared-randomness equality proof structure already present in the original construction extends naturally to cover $\mathrm{PC}_m$ at no additional cost. Combined with the balance linkage equations over $(b, \rho, \mathrm{sk}_A)$, all proof obligations fold into a single AND-composed sigma protocol over the joint witness $w = (m, r, b, \rho, \mathrm{sk}_A)$ under one shared Fiat–Shamir challenge, eliminating redundant commitments and response scalars. This reduces the sigma proof component of ConfidentialMPTSend from approximately 619 bytes to 192 bytes — a saving of 427 bytes — while preserving the same security guarantees under the discrete logarithm assumption and the random oracle model.

Beyond the unification of ConfidentialMPTSend, the remaining transactions are also revised to transmit all sigma proofs in compact Fiat–Shamir form, where only the challenge scalar and response scalars are transmitted and the verifier reconstructs the first-round commitments locally. This provides two benefits: consistency of proof serialization across all transaction types, simplifying implementation and reducing the risk of encoding mismatches, and a modest but uniform reduction in proof size. The balance linkage proof in ConfidentialMPTConvertBack reduces from 195 bytes to 128 bytes, the Chaum–Pedersen proof in ConfidentialMPTClawback reduces from 98 bytes to 64 bytes, and the Schnorr proof of knowledge in ConfidentialMPTConvert reduces from 65 bytes to 64 bytes. In each case the saving is a direct consequence of dropping the explicit transmission of first-round commitment points, which the verifier can recover from the response scalars and public statement alone.

**Ciphertext re-randomization.** A security audit identified a denial-of-service vulnerability (TOB-RIPCTXR-5) arising from publicly known ciphertext randomness. After ConfidentialMPTConvert and ConfidentialMPTClawback, the on-ledger ciphertext randomness of the affected account becomes publicly known: after Convert it is the disclosed blinding factor $r$, and after Clawback the balances are reset to canonical encryptions of zero whose randomness is trivially derivable. A malicious sender can exploit this by crafting a ConfidentialMPTSend with chosen randomness that causes the recipient’s subsequent ConfidentialMPTMergeInbox to produce the group identity (point at infinity), which cannot be serialized, locking the victim’s inbox funds.

The fix is to re-randomize the receiver’s inbox ciphertext as part of every ConfidentialMPTSend state update, using the Fiat–Shamir challenge $e$ already computed during Send proof verification as the re-randomization scalar. Concretely, after crediting the inbox with the transfer amount, the ledger homomorphically adds $\mathrm{Enc}_B(0; e)$ to $\mathrm{CB}_{\mathrm{IN}}(B)$ and $\mathrm{Enc}_I(0; e)$ to $\mathrm{Enc}_I(B)$. Since $e$ is derived deterministically from the full transaction transcript — including the sender’s ciphertext $C_1 = r \cdot G$ — an attacker faces a circular dependency and cannot pre-compute a cancellation randomness. The re-randomization introduces no new cryptographic objects and requires only two additional scalar multiplications per Send. Since $e$ is computed from public data, the computation is publicly verifiable by any party, and all validators arrive at identical results by construction. This addresses TOB-RIPCTXR-5 without any change to transaction size or proof structure.

The proof unification affects each Confidential MPT transaction differently, depending on the structure of its cryptographic proof obligations. Table 1 summarizes the changes across all five transaction types.

**Table 1:** Summary of proof changes across Confidential MPT transaction types.

| Transaction | Change | Before | After | Saving |
|---|---|---|---|---|
| Convert | PoK compact form | 65 bytes | 64 bytes | −1 byte |
| Send | Three proofs → one combined proof | 619 bytes | 192 bytes | −427 bytes |
| Send | Inbox re-randomization via Fiat–Shamir $e$ (state update only) | — | — | — |
| MergeInbox | No change (ZKP-free by design) | — | — | — |
| ConvertBack | Balance linkage compact form | 195 bytes | 128 bytes | −67 bytes |
| Clawback | Chaum–Pedersen compact form | 98 bytes | 64 bytes | −34 bytes |

For ConfidentialMPTConvert, the only ZKP is the Schnorr proof of knowledge of the ElGamal secret key, required solely at first use for public key registration. This proof is updated to compact Fiat–Shamir form for consistency with all other proofs in the protocol; the saving of one byte is incidental. For ConfidentialMPTSend, the full unification applies. All three original sigma proofs are replaced by a single AND-composed compact sigma proof over the five-scalar witness, reducing the total transaction size from 1604 bytes to 1177 bytes (−27%). In addition, the state transition is extended to re-randomize the receiver’s inbox ciphertext using the Fiat–Shamir challenge $e$, addressing TOB-RIPCTXR-5 without any increase in transaction size. For ConfidentialMPTMergeInbox, no change is required. This transaction is ZKP-free by design: the merge operation is entirely determined by on-ledger data and requires no prover-supplied witness or zero-knowledge argument. For ConfidentialMPTConvertBack, the amount $m$ is publicly revealed and verified deterministically via the disclosed blinding factor $r$. The ZKP covers only the balance linkage relation $R_{\mathrm{bal}}$ over the three-scalar witness $(b, \rho, \mathrm{sk}_A)$, replacing the original Variant B ElGamal–Pedersen linkage proof with a compact sigma proof of 128 bytes. For ConfidentialMPTClawback, the issuer establishes ciphertext–amount consistency via knowledge of $\mathrm{sk}_{\mathrm{iss}}$ rather than encryption randomness, since the original ciphertext randomness is unknown to the issuer. The Chaum–Pedersen proof over this single witness scalar is transmitted in compact form as $(e, z_{\mathrm{sk}})$, reducing the proof from 98 bytes to 64 bytes.

## 2 ConfidentialMPTConvert: Public to Confidential and Account Initialization

### Changes from Previous Version

The ConfidentialMPTConvert transaction does not employ a ZKP for the transferred amount, because the plaintext amount $m$ is publicly revealed and ciphertext correctness is verified deterministically via disclosed encryption randomness. However, the Schnorr proof of knowledge of the ElGamal secret key, required only at first use for public key registration, is updated to compact Fiat–Shamir form for consistency with all other proofs in the protocol. Key changes include:

- **Amount verification:** Unchanged; deterministic check via disclosed $r$.
- **PoK proof:** Uncompressed $(T, s)$ (65 bytes) → compact form $\pi_{\mathrm{PoK}} = (e, s)$ (64 bytes, −1 byte).
- **PoK domain tag:** `"MPT_POK_SK_REGISTER"` → `"CMPT_POK_SK_REGISTER"`.
- **Motivation:** Uniformity with all other compact proofs in the protocol; the byte saving is negligible but consistent serialization simplifies implementations.
- **State transition, validation rules, and all other fields:** Unchanged.

The ConfidentialMPTConvert transaction converts a publicly visible MPT balance into its confidential form. It has a single, uniform meaning for all holders, including the issuer’s designated second account. The issuer does not directly mint confidential supply. Instead, it must first transfer public tokens to its second account using standard XLS-33 mechanisms; that account—treated as an ordinary non-issuer holder—then performs ConfidentialMPTConvert. This preserves XLS-33 issuance semantics and avoids introducing special-case confidential minting logic. Semantically, ConfidentialMPTConvert reveals an amount $m$ and moves it from the holder’s public balance into an encrypted confidential balance under the holder’s ElGamal public key. The conversion increases COA by $m$ while preserving the invariant that OA remains unchanged.

### 2.1 Account Initialization and Key Registration

Participation in the Confidential MPT protocol requires on-ledger registration of an ElGamal public key $\mathrm{pk}_A$. This initialization is performed via ConfidentialMPTConvert itself and does not require a separate enrollment transaction. Before an account $A$ can receive, hold, or spend confidential value, it must publish $\mathrm{pk}_A$. Validators reject any confidential transaction targeting an account whose ElGamal public key is not already registered. Initialization may be performed in two equivalent ways:

1. **Zero-amount initialization.** The holder submits a ConfidentialMPTConvert transaction with $\mathrm{Amount} = 0$. This registers $\mathrm{pk}_A$ and initializes the confidential balance fields without moving value or affecting supply fields.
2. **Non-zero conversion.** The holder submits a ConfidentialMPTConvert transaction with $\mathrm{Amount} > 0$, simultaneously initializing the confidential state and converting public balance into confidential form.

Once the validator processes this transaction, the holder’s MPToken object is updated to include the provided ElGamal public key $\mathrm{pk}_A$, and the confidential spending balance version `CB_S_Version` is initialized. This makes the account cryptographically addressable: other participants can now encrypt confidential amounts under $\mathrm{pk}_A$, and any subsequent ZKPs involving the holder’s spending balance are bound to a well-defined initial version. When the issuer’s designated second account executes ConfidentialMPTConvert, it undergoes the same holder-side initialization semantics as any other account.

### 2.2 State Transition

For a holder account $A$ (which may be the issuer’s second account), the ledger applies the following deterministic state updates:

$$
\mathrm{CB}_{\mathrm{IN}}(A) \leftarrow \mathrm{CB}_{\mathrm{IN}}(A) \oplus \mathrm{Enc}_A(m), \tag{1}
$$

$$
\mathrm{Enc}_I(A) \leftarrow \mathrm{Enc}_I(A) \oplus \mathrm{Enc}_I(m), \tag{2}
$$

$$
\mathrm{COA} \leftarrow \mathrm{COA} + m. \tag{3}
$$

The confidential amount is credited to the inbox balance to prevent immediate proof staleness. A parallel issuer-encrypted mirror is updated to maintain audit and clawback consistency. If an auditor policy is active for the issuance, an additional auditor-encrypted ciphertext may be updated analogously. Because the converting account is already counted as a non-issuer holder, OA remains unchanged.

### 2.3 Encryption Verification

Each ConfidentialMPTConvert transaction includes ElGamal ciphertexts encrypting a publicly revealed amount $m$. Since the plaintext value is known, the protocol does not require ZKPs for encryption correctness. Instead, the prover reveals the encryption randomness $r$, allowing validators to deterministically verify that each ciphertext correctly encrypts the public amount. Concretely, for each ciphertext included in the transaction (holder, issuer, and optional auditor), validators check:

$$
C_1 \stackrel{?}{=} r \cdot G \quad \text{and} \quad C_{2,i} \stackrel{?}{=} m \cdot G + r \cdot \mathrm{pk}_i, \tag{4}
$$

where $\mathrm{pk}_i$ is the corresponding recipient public key. These checks ensure that all confidential balances created by the conversion are mutually consistent and correspond exactly to the revealed amount $m$.

### 2.4 ZKP for Key Registration

The only ZKP in ConfidentialMPTConvert is required solely when a new ElGamal public key $\mathrm{pk}_A$ is being registered, i.e., on first use. The proof is a Schnorr proof of knowledge of the corresponding secret key $\mathrm{sk}_A$, establishing that $\mathrm{pk}_A = \mathrm{sk}_A \cdot G$. It is structurally independent of the amount ciphertexts and is unaffected by the proof unification work of [2].

**Prover Algorithm.** Given witness $\mathrm{sk}_A$ and public key $\mathrm{pk}_A$:

1. **Sample nonce.** Sample $k \stackrel{R}{\leftarrow} \mathbb{Z}_q$.
2. **Compute commitment.** Compute $T = k \cdot G$.
3. **Compute challenge.**

$$
e = H(\texttt{"CMPT\_POK\_SK\_REGISTER"} \parallel \mathrm{pk}_A \parallel T \parallel \mathrm{TransactionContextID}). \tag{5}
$$

4. **Compute response.** $s = k + e \cdot \mathrm{sk}_A \pmod{q}$.
5. **Output compact proof.**

$$
\pi_{\mathrm{PoK}} = (e, s) \in \mathbb{Z}_q^2. \tag{6}
$$

**Verifier Algorithm.** Given $\mathrm{pk}_A$ and compact proof $\pi_{\mathrm{PoK}} = (e, s)$:

1. **Validate scalars.** Verify that both scalars are valid elements of $\mathbb{Z}_q$ (i.e., in the range $[1, q-1]$).
2. **Reconstruct commitment.**

$$
T = s \cdot G - e \cdot \mathrm{pk}_A. \tag{7}
$$

3. **Recompute challenge.** Compute $e'$ using the same hash expression above with the reconstructed $T$.
4. **Accept or reject.** Accept if and only if $e' = e$ (using constant-time comparison).

> **Remark 2.1 (Proof size).** The compact proof $\pi_{\mathrm{PoK}}$ consists of two $\mathbb{Z}_q$ scalars, yielding $2 \times 32 = 64$ bytes. This replaces the previous uncompressed form $(T, s)$ of $33 + 32 = 65$ bytes, saving 1 byte. The change is motivated by uniformity with all other compact proofs in the protocol rather than the byte saving itself. This proof is submitted only when `HolderEncryptionPublicKey` is present in the transaction; it is absent for all subsequent conversions by the same account.

### 2.5 Validation Rules

Before applying the state transition, validators perform the following checks:

- Confidential transfers are enabled for the token issuance.
- The revealed amount $m$ is non-negative and conforms to XRPL decimal semantics.
- The converting account has sufficient public balance to cover the conversion.
- All submitted ciphertexts are well-formed secp256k1 group elements.
- The revealed encryption randomness $r$ correctly reconstructs each ciphertext for the public amount $m$ under the corresponding public keys.
- If a confidential public key is registered in this transaction, a valid proof of knowledge of the corresponding secret key is provided and verifies successfully.

Failure of any check causes the transaction to be rejected.

### 2.6 Effect

The ConfidentialMPTConvert transaction moves value from public to confidential form while preserving full public accountability of total supply. It is the only transaction type that increases COA. Once value enters confidential circulation, its aggregate amount remains publicly tracked via COA, even though its distribution across individual holders—including the issuer’s mirror account—remains hidden.

### 2.7 Transaction Fields

A ConfidentialMPTConvert transaction includes the fields summarized in Table 2.

**Table 2:** Fields of the ConfidentialMPTConvert transaction.

| Field | Description | Req. |
|---|---|---|
| `TransactionType` | Identifies the transaction as ConfidentialMPTConvert. | M |
| `Account` | The XRPL account initiating the conversion. | M |
| `MPTokenIssuanceID` | The unique identifier of the associated MPT issuance. | M |
| `MPTAmount` | Public plaintext amount $m$ to convert from public to confidential form. | M |
| `HolderEncryptionPublicKey` | The holder’s encryption public key $\mathrm{pk}_A$. Required only when initializing a confidential balance and no key is already registered; forbidden otherwise. | C |
| `HolderEncryptedAmount` | A 66-byte ElGamal ciphertext credited to the holder’s confidential inbox balance $\mathrm{CB}_{\mathrm{IN}}$. | M |
| `IssuerEncryptedAmount` | A 66-byte ElGamal ciphertext credited to the issuer’s encrypted mirror balance. | M |
| `AuditorEncryptedAmount` | A 66-byte ElGamal ciphertext for auditor visibility. Required when an auditor key is configured on the issuance. | C |
| `BlindingFactor` | The 32-byte scalar $r$ used during ElGamal encryption. Validators use it to verify ciphertext consistency with `MPTAmount`. | M |
| `ZKProof` | A Schnorr proof of knowledge $\pi_{\mathrm{PoK}}$ proving ownership of the secret key corresponding to `HolderEncryptionPublicKey`. Required only when the public key is included; absent otherwise. | C |

M = Mandatory, C = Conditional

### 2.8 Transaction Size

Table 3 summarizes the size breakdown for a ConfidentialMPTConvert transaction in the auditor-enabled configuration, for the non-zero-amount case including key registration.

**Table 3:** Size breakdown for ConfidentialMPTConvert (auditor-enabled, with key registration).

| Component | Size (bytes) | Notes |
|---|---|---|
| Holder ciphertext $(C_1, C_{2,H})$ | 66 | $2 \times 33$ |
| Issuer ciphertext $C_{2,I}$ | 33 | $1 \times 33$ |
| Auditor ciphertext $C_{2,A}$ | 33 | $1 \times 33$ |
| Blinding factor $r$ | 32 | 1 scalar |
| Holder public key $\mathrm{pk}_A$ | 33 | $1 \times 33$ (first use only) |
| PoK proof $\pi_{\mathrm{PoK}}$ | 64 | $2 \times 32$ (first use only) |
| **Total (first use)** | **261** | |
| **Total (subsequent uses)** | **164** | without key and PoK |

## 3 ConfidentialMPTSend: Confidential Transfer

### Changes from Previous Version

This section incorporates the compact AND-composed sigma protocol from [2], which replaces the three separate sigma proofs (same-plaintext equality, amount linkage, and balance linkage) with a single AND-composed protocol under a shared Fiat–Shamir challenge transmitted in compact form. In addition, the state transition is extended to re-randomize the receiver’s inbox ciphertext using the Fiat–Shamir challenge $e$, addressing the inbox-locking vulnerability TOB-RIPCTXR-5. Key changes include:

- **Proof structure:** Three independent proofs → one combined proof.
- **Sigma proof size:** ∼619 bytes → 192 bytes (6 scalars).
- **Total transaction size:** 1604 bytes → 1177 bytes (−27%).
- **Commitment $\mathrm{PC}_m$:** Now reuses ciphertext randomness $r$ as blinding factor.
- **Transaction fields:** `ZKProof` replaced by `CompactSigmaProof`.
- **State transition:** Receiver inbox $\mathrm{CB}_{\mathrm{IN}}(B)$ and issuer mirror $\mathrm{Enc}_I(B)$ are re-randomized by homomorphically adding $\mathrm{Enc}_B(0; e)$ and $\mathrm{Enc}_I(0; e)$ respectively, where $e$ is the Fiat–Shamir challenge. No change to transaction size (re-randomization is a validator-side state update).
- **Appendix references:** Appendices D and E (separate proof constructions) are superseded by the combined protocol specified inline.

The ConfidentialMPTSend transaction performs a confidential transfer of MPT value between two non-issuer accounts while keeping the transferred amount hidden. The sender’s confidential spending balance is debited, and the receiver’s confidential inbox balance is credited. The receiver may later consolidate incoming funds into their spending balance using ConfidentialMPTMergeInbox.

### 3.1 Notation

Table 4 reconciles notation between this specification and the compact sigma protocol construction [2].

**Table 4:** Notation for ConfidentialMPTSend. All scalars are elements of $\mathbb{Z}_q$ where $q$ is the order of the secp256k1 group.

| Symbol | Description | Domain |
|---|---|---|
| $G$ | Base generator of secp256k1 | $\mathbb{G}$ |
| $H$ | Independent NUMS generator for Pedersen commitments | $\mathbb{G}$ |
| $m$ | Transfer amount | $\mathbb{Z}_q$ |
| $r$ | Shared encryption randomness for transfer ciphertexts | $\mathbb{Z}_q$ |
| $b$ | Sender’s confidential spending balance (pre-transfer) | $\mathbb{Z}_q$ |
| $\rho$ | Blinding factor for balance commitment $\mathrm{PC}_b$ | $\mathbb{Z}_q$ |
| $\mathrm{sk}_A$ | Sender’s ElGamal secret key | $\mathbb{Z}_q$ |
| $P_i$ | Recipient public key ($i = 1, \ldots, n$) | $\mathbb{G}$ |
| $P_A$ | Sender’s ElGamal public key ($P_A = \mathrm{sk}_A \cdot G$) | $\mathbb{G}$ |
| $C_1$ | Shared ciphertext component ($C_1 = r \cdot G$) | $\mathbb{G}$ |
| $C_{2,i}$ | Per-recipient ciphertext component | $\mathbb{G}$ |
| $\mathrm{PC}_m$ | Pedersen commitment to transfer amount | $\mathbb{G}$ |
| $\mathrm{PC}_b$ | Pedersen commitment to sender’s balance | $\mathbb{G}$ |
| $B_1, B_2$ | Sender’s on-ledger balance ciphertext components | $\mathbb{G}$ |

### 3.2 State Transition

Let $A$ denote the sender account and $B$ the receiver account. Upon successful validation, the ledger applies the following deterministic updates.

**Sender account $A$:**

$$
\mathrm{CB}_S(A) \leftarrow \mathrm{CB}_S(A) \ominus \mathrm{Enc}_A(m), \tag{8}
$$

$$
\mathrm{CB\_S\_Version}(A) \leftarrow \mathrm{CB\_S\_Version}(A) + 1, \tag{9}
$$

$$
\mathrm{Enc}_I(A) \leftarrow \mathrm{Enc}_I(A) \ominus \mathrm{Enc}_I(m). \tag{10}
$$

**Receiver account $B$:**

$$
\mathrm{CB}_{\mathrm{IN}}(B) \leftarrow \mathrm{CB}_{\mathrm{IN}}(B) \oplus \mathrm{Enc}_B(m) \oplus \mathrm{Enc}_B(0; e), \tag{11}
$$

$$
\mathrm{Enc}_I(B) \leftarrow \mathrm{Enc}_I(B) \oplus \mathrm{Enc}_I(m) \oplus \mathrm{Enc}_I(0; e). \tag{12}
$$

If an auditor policy is active, corresponding auditor-encrypted ciphertexts are updated analogously. No public balances are modified, and the global supply fields OA and COA remain unchanged.

> **Remark 3.1 (Ciphertext re-randomization via Fiat–Shamir challenge).** The term $\mathrm{Enc}_B(0; e)$ denotes an encryption of zero under the receiver’s public key $\mathrm{pk}_B$ using the Fiat–Shamir challenge $e$ from Equation (26) as randomness:
>
> $$
> \mathrm{Enc}_B(0; e) = (e \cdot G,\ e \cdot \mathrm{pk}_B). \tag{13}
> $$
>
> Since $e$ is derived deterministically from the full transaction transcript — including the sender’s ciphertext $C_1 = r \cdot G$ — an attacker who submits a ConfidentialMPTSend with chosen randomness $r$ cannot pre-compute the resulting inbox randomness $r + e$, because $e$ itself depends on $r$ via the Fiat–Shamir hash. This circular dependency prevents any attacker from targeting a specific cancellation randomness and blocks the inbox-locking denial-of-service attack described in TOB-RIPCTXR-5. The re-randomization requires only two additional scalar multiplications per Send and introduces no new cryptographic objects or transaction fields, since $e$ is already computed during proof verification. Because $e$ is derived entirely from public data, the computation is publicly verifiable by any party, and all validators arrive at identical results by construction.

### 3.3 Ciphertexts and Commitments

Confidential balance updates on-ledger are performed using EC–ElGamal ciphertexts with shared randomness. For $n$ recipients with public keys $P_1, \ldots, P_n$, the transfer amount $m$ is encrypted as:

$$
C_1 = r \cdot G, \tag{14}
$$

$$
C_{2,i} = m \cdot G + r \cdot P_i, \quad i = 1, \ldots, n. \tag{15}
$$

Bulletproof range proofs operate over Pedersen commitments with generators independent of ElGamal encryption keys. Each ConfidentialMPTSend transaction includes the following Pedersen commitments:

$$
\mathrm{PC}_m = m \cdot G + r \cdot H, \tag{16}
$$

$$
\mathrm{PC}_b = b \cdot G + \rho \cdot H, \tag{17}
$$

where $\mathrm{PC}_m$ commits to the transferred amount $m$ (reusing the ciphertext randomness $r$ as the blinding factor), and $\mathrm{PC}_b$ commits to the sender’s confidential spending balance $b$ at the time of the transfer.

> **Remark 3.2 (Randomness reuse in $\mathrm{PC}_m$).** The commitment $\mathrm{PC}_m$ intentionally reuses the ciphertext randomness $r$ rather than introducing an independent blinding factor. This design choice reduces the witness size from six to five scalars and eliminates the need for a separate amount-linkage proof, as the relationship between $\mathrm{PC}_m$ and the ElGamal ciphertexts is captured directly in the combined sigma protocol.

Within the ZKP, the verifier derives a Pedersen commitment to the post-transfer remainder balance as:

$$
\mathrm{PC}_{\mathrm{rem}} := \mathrm{PC}_b - \mathrm{PC}_m = (b - m) \cdot G + (\rho - r) \cdot H, \tag{18}
$$

and the prover demonstrates in zero knowledge that this derived commitment encodes a non-negative value. The commitment $\mathrm{PC}_{\mathrm{rem}}$ is not transmitted or stored on-ledger; it is computed by the verifier from $\mathrm{PC}_b$ and $\mathrm{PC}_m$ during proof verification.

### 3.4 Combined Relation

The ZKP establishes membership in the combined relation $R_{\mathrm{send}}$, which captures ciphertext equality, Pedersen commitment linkage, and balance verification in a single statement.

**Definition 3.1 (Combined relation $R_{\mathrm{send}}$).** The prover’s witness is $w = (m, r, b, \rho, \mathrm{sk}_A) \in \mathbb{Z}_q^5$. The combined relation is:

$$
R_{\mathrm{send}} =
\left\{
(x, w)
\;\middle|\;
\begin{aligned}
C_1 &= r \cdot G, \\
C_{2,i} &= m \cdot G + r \cdot P_i \quad (i = 1, \ldots, n), \\
\mathrm{PC}_m &= m \cdot G + r \cdot H, \\
\mathrm{PC}_b &= b \cdot G + \rho \cdot H, \\
P_A &= \mathrm{sk}_A \cdot G, \\
B_2 - b \cdot G &= \mathrm{sk}_A \cdot B_1
\end{aligned}
\right\}, \tag{19}
$$

where $x = (C_1, \{C_{2,i}\}_{i=1}^n, \mathrm{PC}_m, \mathrm{PC}_b, B_1, B_2, P_1, \ldots, P_n, P_A, H)$ is the public statement.

This relation captures three consistency requirements simultaneously:

1. All amount ciphertexts encrypt the same value $m$ using shared randomness $r$.
2. The Pedersen commitment $\mathrm{PC}_m$ commits to the same amount $m$ with blinding factor $r$.
3. The Pedersen commitment $\mathrm{PC}_b$ commits to the same balance $b$ as the sender’s existing balance ciphertext $(B_1, B_2)$, verified via knowledge of $\mathrm{sk}_A$.

### 3.5 Compact AND-Composed Sigma Protocol

The ZKP for $R_{\mathrm{send}}$ is instantiated as an AND-composed sigma protocol under a shared Fiat–Shamir challenge, transmitted in compact form [2]. This construction reduces the sigma-proof overhead from approximately 619 bytes (three separate proofs) to 192 bytes (six scalars), independent of the number of recipients $n$.

**Prover Algorithm.** Given witness $w = (m, r, b, \rho, \mathrm{sk}_A)$ and statement $x$:

1. **Sample nonces.** Sample $\alpha_m, \alpha_r, \alpha_b, \alpha_\rho, \alpha_{\mathrm{sk}} \stackrel{R}{\leftarrow} \mathbb{Z}_q$.
2. **Compute commitments.** Compute $n + 5$ first-round commitments:

$$
T_1 = \alpha_r \cdot G, \tag{20}
$$

$$
T_{2,i} = \alpha_m \cdot G + \alpha_r \cdot P_i \quad (i = 1, \ldots, n), \tag{21}
$$

$$
T_m = \alpha_m \cdot G + \alpha_r \cdot H, \tag{22}
$$

$$
T_b = \alpha_b \cdot G + \alpha_\rho \cdot H, \tag{23}
$$

$$
T_{\mathrm{sk},1} = \alpha_{\mathrm{sk}} \cdot G, \tag{24}
$$

$$
T_{\mathrm{sk},2} = \alpha_b \cdot G + \alpha_{\mathrm{sk}} \cdot B_1. \tag{25}
$$

3. **Compute challenge.** Compute the Fiat–Shamir challenge:

$$
\begin{aligned}
e = H(&\texttt{"CMPT\_SEND\_SIGMA"} \parallel P_1 \parallel \cdots \parallel P_n \parallel P_A \parallel \\
&C_1 \parallel C_{2,1} \parallel \cdots \parallel C_{2,n} \parallel \mathrm{PC}_m \parallel \mathrm{PC}_b \parallel B_1 \parallel B_2 \parallel \\
&T_1 \parallel T_{2,1} \parallel \cdots \parallel T_{2,n} \parallel T_m \parallel T_b \parallel T_{\mathrm{sk},1} \parallel T_{\mathrm{sk},2} \parallel \mathrm{TransactionContextID}).
\end{aligned} \tag{26}
$$

> **Remark 3.3 (Domain separation tag).** The domain separation tag `"CMPT_SEND_SIGMA"` is canonical and must be used exactly as specified (ASCII encoding, no null terminator). Implementations must ensure this tag matches precisely; any deviation will produce invalid proofs.

> **Remark 3.4 (Hash input ordering).** The order of elements in the hash input is normative. Implementations must serialize elements in exactly the order specified in Equation (26): (1) domain tag, (2) public keys $P_1, \ldots, P_n, P_A$, (3) ciphertexts $C_1, C_{2,1}, \ldots, C_{2,n}$, (4) commitments $\mathrm{PC}_m, \mathrm{PC}_b$, (5) balance ciphertext $B_1, B_2$, (6) reconstructed commitments $T_1, T_{2,1}, \ldots, T_{2,n}, T_m, T_b, T_{\mathrm{sk},1}, T_{\mathrm{sk},2}$, (7) transaction context. All group elements are serialized as 33-byte compressed secp256k1 points.

4. **Compute responses.**

$$
z_m = \alpha_m + e \cdot m \pmod{q}, \tag{27}
$$

$$
z_r = \alpha_r + e \cdot r \pmod{q}, \tag{28}
$$

$$
z_b = \alpha_b + e \cdot b \pmod{q}, \tag{29}
$$

$$
z_\rho = \alpha_\rho + e \cdot \rho \pmod{q}, \tag{30}
$$

$$
z_{\mathrm{sk}} = \alpha_{\mathrm{sk}} + e \cdot \mathrm{sk}_A \pmod{q}. \tag{31}
$$

5. **Output compact proof.**

$$
\pi_{\mathrm{send}} = (e, z_m, z_r, z_b, z_\rho, z_{\mathrm{sk}}) \in \mathbb{Z}_q^6. \tag{32}
$$

**Verifier Algorithm.** Given statement $x$ and compact proof $\pi_{\mathrm{send}} = (e, z_m, z_r, z_b, z_\rho, z_{\mathrm{sk}})$:

1. **Validate scalars.** Verify that all six scalars are valid elements of $\mathbb{Z}_q$ (i.e., in the range $[1, q-1]$).
2. **Reconstruct commitments.** Compute:

$$
T_1 = z_r \cdot G - e \cdot C_1, \tag{33}
$$

$$
T_{2,i} = z_m \cdot G + z_r \cdot P_i - e \cdot C_{2,i} \quad (i = 1, \ldots, n), \tag{34}
$$

$$
T_m = z_m \cdot G + z_r \cdot H - e \cdot \mathrm{PC}_m, \tag{35}
$$

$$
T_b = z_b \cdot G + z_\rho \cdot H - e \cdot \mathrm{PC}_b, \tag{36}
$$

$$
T_{\mathrm{sk},1} = z_{\mathrm{sk}} \cdot G - e \cdot P_A, \tag{37}
$$

$$
T_{\mathrm{sk},2} = z_b \cdot G + z_{\mathrm{sk}} \cdot B_1 - e \cdot B_2. \tag{38}
$$

3. **Recompute challenge.** Compute $e'$ using Equation (26) with the reconstructed commitments.
4. **Accept or reject.** Accept if and only if $e' = e$ (using constant-time comparison).

> **Remark 3.5 (Proof size).** The compact proof $\pi_{\mathrm{send}}$ consists of six $\mathbb{Z}_q$ scalars, yielding a fixed size of $6 \times 32 = 192$ bytes, independent of the number of recipients $n$. Verification cost remains $O(n)$ group operations due to the reconstruction of $T_{2,i}$ for each recipient.

### 3.6 Range Proof

In addition to the compact sigma proof, each ConfidentialMPTSend transaction includes an aggregated Bulletproof [3] establishing:

$$
0 \le m < 2^{64} \quad \text{and} \quad 0 \le b - m < 2^{64}. \tag{39}
$$

The range proof operates over the Pedersen commitments $\mathrm{PC}_m$ and $\mathrm{PC}_{\mathrm{rem}} = \mathrm{PC}_b - \mathrm{PC}_m$. For two 64-bit values, the aggregated Bulletproof consists of 18 group elements and 5 scalars, yielding $18 \times 33 + 5 \times 32 = 754$ bytes.

### 3.7 Transaction Context Binding

The `TransactionContextID` included in the Fiat–Shamir challenge (26) is defined as:

$$
\mathrm{TransactionContextID} := H(\mathrm{TxType} \parallel \mathrm{Account} \parallel \mathrm{MPTokenIssuanceID} \parallel \mathrm{SequenceOrTicket} \parallel \mathrm{TxSpecific}), \tag{40}
$$

where for ConfidentialMPTSend:

$$
\mathrm{TxSpecific} := \mathrm{Destination} \parallel \mathrm{CBS\_Version}(A). \tag{41}
$$

The inclusion of $\mathrm{CBS\_Version}(A)$ binds the proof to the sender’s current confidential spending balance state, preventing replay attacks using proofs generated against stale balance snapshots.

### 3.8 Validation Rules

Before applying the state transition, validators perform the following checks:

- Confidential transfers are enabled for the issuance.
- The sender is not the issuer account.
- Sender and receiver addresses are distinct and valid ledger accounts.
- The receiver’s ElGamal public key is already registered.
- All submitted ciphertexts and Pedersen commitments are well-formed secp256k1 group elements.
- The number of recipients $n \ge 1$.
- All proof scalars $(e, z_m, z_r, z_b, z_\rho, z_{\mathrm{sk}})$ are valid elements of $\mathbb{Z}_q$.
- Any auditor ciphertext conforms to the active auditor policy.
- The compact sigma proof $\pi_{\mathrm{send}}$ verifies successfully per Section 3.5.
- The aggregated Bulletproof range proof verifies successfully.
- The re-randomized inbox ciphertext $\mathrm{CB}_{\mathrm{IN}}(B) \oplus \mathrm{Enc}_B(m) \oplus \mathrm{Enc}_B(0; e)$ is a well-formed secp256k1 group element (i.e., the result is not the point at infinity).

Failure of any check causes the transaction to be rejected.

### 3.9 Security Properties

The compact AND-composed sigma protocol satisfies the following security properties under the discrete logarithm assumption in the secp256k1 group and the random oracle model for the Fiat–Shamir transform:

- **Completeness.** If the prover holds a valid witness $w$ for statement $x \in R_{\mathrm{send}}$, the verifier always accepts.
- **2-Special Soundness.** Given two accepting transcripts with the same commitments but distinct challenges $e \neq e'$, an extractor can efficiently recover a valid witness $(m, r, b, \rho, \mathrm{sk}_A)$.
- **Honest-Verifier Zero-Knowledge.** There exists a simulator that, given any challenge $e$ and a valid statement (but no witness), produces a transcript indistinguishable from a real proof.
- **Non-Interactive Zero-Knowledge.** The Fiat–Shamir transform yields a NIZK proof of knowledge in the random oracle model.

Full security proofs are provided in [2].

### 3.10 Effect and Leakage

The ConfidentialMPTSend transaction redistributes value entirely within confidential circulation. Observers learn only the identities of the sender and receiver and the fact that a confidential transfer occurred. The transferred amount, individual balances, and the distribution of confidential supply remain hidden under the cryptographic transcript alone; see 4.11 for the privacy implications when public Send, Convert, and ConvertBack events are combined in low-volume issuances.

### 3.11 Transaction Fields

A ConfidentialMPTSend transaction includes the fields summarized in Table 5.

**Table 5:** Fields of the ConfidentialMPTSend transaction.

| Field | Description | Req. |
|---|---|---|
| `TransactionType` | Identifies the transaction as ConfidentialMPTSend. | M |
| `Account` | The sender’s XRPL account. | M |
| `Destination` | The receiver’s XRPL account. | M |
| `MPTokenIssuanceID` | Identifier of the MPT issuance being transferred. | M |
| `SenderEncryptedAmount` | Ciphertext used to homomorphically debit the sender’s confidential spending balance. | M |
| `DestinationEncryptedAmount` | Ciphertext credited to the receiver’s confidential inbox balance. | M |
| `IssuerEncryptedAmount` | Ciphertext used to update the issuer mirror balance. | M |
| `AuditorEncryptedAmount` | Ciphertext for auditor visibility. Required when an auditor key is configured on the issuance. | C |
| `AmountCommitment` | Pedersen commitment $\mathrm{PC}_m$ to the transfer amount (33 bytes). | M |
| `BalanceCommitment` | Pedersen commitment $\mathrm{PC}_b$ to the sender’s confidential spending balance (33 bytes). | M |
| `ZKproof` | ZKP bundle including the compact AND-composed sigma proof $\pi_{\mathrm{send}}$ and the aggregated Range Proof for amount and remainder. | M |

M = Mandatory, C = Conditional

### 3.12 Transaction Size

Table 6 summarizes the size breakdown for an auditor-enabled ConfidentialMPTSend transaction. This represents a reduction of 427 bytes (27%) compared to the previous construction using three separate sigma proofs (1604 bytes). The inbox re-randomization is a validator-side state update and does not increase transaction size.

**Table 6:** Size breakdown for ConfidentialMPTSend with compact sigma proof ($n = 4$ recipients: sender, receiver, issuer, auditor).

| Component | Size (bytes) | Notes |
|---|---|---|
| Shared $C_1$ | 33 | $1 \times 33$ |
| Recipient ciphertexts $C_{2,i}$ | 132 | $4 \times 33$ |
| Amount commitment $\mathrm{PC}_m$ | 33 | $1 \times 33$ |
| Balance commitment $\mathrm{PC}_b$ | 33 | $1 \times 33$ |
| Compact sigma proof $\pi_{\mathrm{send}}$ | 192 | $6 \times 32$ |
| Aggregated Bulletproof | 754 | $18 \times 33 + 5 \times 32$ |
| **Total** | **1177** | |

## 4 ConfidentialMPTConvertBack: Confidential to Public

### Changes from Previous Version

The amount $m$ is publicly revealed in this transaction, so ciphertext correctness continues to be verified deterministically via disclosed encryption randomness, exactly as in ConfidentialMPTConvert. However, the balance linkage proof (previously Variant B of Appendix E, 195 bytes) is replaced by a compact AND-composed sigma protocol over the balance witness $(b, \rho, \mathrm{sk}_A)$, reducing that component from 195 bytes to 128 bytes. The Bulletproof range proof is unchanged. Key changes include:

- **Amount verification:** Unchanged; deterministic check via disclosed $r$.
- **Balance linkage proof:** Variant B (195 bytes) → compact sigma proof $\pi_{\mathrm{bal}} = (e, z_b, z_\rho, z_{\mathrm{sk}})$ (128 bytes, −67 bytes).
- **Range proof:** Unchanged; single 64-bit Bulletproof (688 bytes).
- **Transaction fields:** `ZKProof` includes the Pedersen balance linkage and RangeProof.
- **Appendix references:** Appendix E Variant B is superseded by the combined protocol specified inline.

The ConfidentialMPTConvertBack transaction converts confidential MPT value back into a publicly visible (plaintext) MPT balance. It reveals a plaintext amount $m$ on-ledger and proves that this amount is consistent with a decrement applied to the account’s confidential spending balance. At a high level, ConfidentialMPTConvertBack decreases the confidential pool tracked by COA since value leaves confidential circulation and re-enters the public accounting domain. Because the converting account remains the owner of the value, OA is unchanged.

### 4.1 Notation

Table 7 defines the symbols used in this section.

**Table 7:** Notation for ConfidentialMPTConvertBack. All scalars are elements of $\mathbb{Z}_q$ where $q$ is the order of the secp256k1 group.

| Symbol | Description | Domain |
|---|---|---|
| $G$ | Base generator of secp256k1 | $\mathbb{G}$ |
| $H$ | Independent NUMS generator for Pedersen commitments | $\mathbb{G}$ |
| $m$ | Publicly revealed conversion amount | $\mathbb{Z}_q$ |
| $r$ | Disclosed encryption randomness for amount ciphertexts | $\mathbb{Z}_q$ |
| $b$ | Sender’s confidential spending balance (pre-conversion) | $\mathbb{Z}_q$ |
| $\rho$ | Blinding factor for balance commitment $\mathrm{PC}_b$ | $\mathbb{Z}_q$ |
| $\mathrm{sk}_A$ | Sender’s ElGamal secret key | $\mathbb{Z}_q$ |
| $P_A$ | Sender’s ElGamal public key ($P_A = \mathrm{sk}_A \cdot G$) | $\mathbb{G}$ |
| $\mathrm{PC}_b$ | Pedersen commitment to sender’s balance | $\mathbb{G}$ |
| $B_1, B_2$ | Sender’s on-ledger balance ciphertext components | $\mathbb{G}$ |

### 4.2 State Transition

Let $A$ be the converting account. Upon successful validation, the ledger applies the following deterministic updates:

$$
\mathrm{CB}_S(A) \leftarrow \mathrm{CB}_S(A) \ominus \mathrm{Enc}_A(m), \tag{42}
$$

$$
\mathrm{Enc}_I(A) \leftarrow \mathrm{Enc}_I(A) \ominus \mathrm{Enc}_I(m), \tag{43}
$$

$$
\mathrm{CB\_S\_Version}(A) \leftarrow \mathrm{CB\_S\_Version}(A) + 1, \tag{44}
$$

$$
\mathrm{COA} \leftarrow \mathrm{COA} - m. \tag{45}
$$

No other confidential or public balance fields are modified, and the outstanding amount OA remains unchanged.

### 4.3 Amount Ciphertext Verification

The publicly revealed amount $m$ is included in the transaction as `MPTAmount`. Since $m$ is known, ciphertext correctness does not require a ZKP. The prover discloses the encryption randomness $r$ via the `BlindingFactor` field, and validators deterministically verify each submitted ciphertext (holder, issuer, and optional auditor) by checking:

$$
C_1 \stackrel{?}{=} r \cdot G \quad \text{and} \quad C_{2,i} \stackrel{?}{=} m \cdot G + r \cdot \mathrm{pk}_i, \tag{46}
$$

where $\mathrm{pk}_i$ is the corresponding recipient public key. No ZKP is required for this step.

### 4.4 Balance Linkage Relation

Although $m$ is public, the sender’s confidential spending balance $b$ remains hidden. The ZKP must establish that the Pedersen commitment $\mathrm{PC}_b$ encodes the same balance $b$ as the sender’s on-ledger balance ciphertext $(B_1, B_2)$, and that the post-conversion remainder $b - m$ is non-negative. The balance linkage relation is:

$$
R_{\mathrm{bal}} =
\left\{
(x, w)
\;\middle|\;
\begin{aligned}
P_A &= \mathrm{sk}_A \cdot G, \\
B_2 &= b \cdot G + \mathrm{sk}_A \cdot B_1, \\
\mathrm{PC}_b &= b \cdot G + \rho \cdot H
\end{aligned}
\right\}, \tag{47}
$$

where the public statement is $x = (P_A, B_1, B_2, \mathrm{PC}_b, H)$ and the witness is $w = (b, \rho, \mathrm{sk}_A) \in \mathbb{Z}_q^3$. This is precisely the balance sub-relation of $R_{\mathrm{send}}$ (Definition 3.1), now standing alone since the amount witness $(m, r)$ is not hidden. The compact sigma protocol from [2] applies directly to this three-scalar witness.

### 4.5 Compact Balance Sigma Protocol

The ZKP for $R_{\mathrm{bal}}$ is instantiated as a compact AND-composed sigma protocol under a shared Fiat–Shamir challenge, yielding a proof $\pi_{\mathrm{bal}} = (e, z_b, z_\rho, z_{\mathrm{sk}}) \in \mathbb{Z}_q^4$ of 128 bytes.

**Prover Algorithm.** Given witness $w = (b, \rho, \mathrm{sk}_A)$ and statement $x$:

1. **Sample nonces.** Sample $\alpha_b, \alpha_\rho, \alpha_{\mathrm{sk}} \stackrel{R}{\leftarrow} \mathbb{Z}_q$.
2. **Compute commitments.**

$$
T_{\mathrm{sk},1} = \alpha_{\mathrm{sk}} \cdot G, \tag{48}
$$

$$
T_{\mathrm{sk},2} = \alpha_b \cdot G + \alpha_{\mathrm{sk}} \cdot B_1, \tag{49}
$$

$$
T_b = \alpha_b \cdot G + \alpha_\rho \cdot H. \tag{50}
$$

3. **Compute challenge.**

$$
e = H(\texttt{"CMPT\_CONVERTBACK\_SIGMA"} \parallel P_A \parallel B_1 \parallel B_2 \parallel \mathrm{PC}_b \parallel T_{\mathrm{sk},1} \parallel T_{\mathrm{sk},2} \parallel T_b \parallel \mathrm{TransactionContextID}). \tag{51}
$$

> **Remark 4.1 (Domain separation tag).** The domain separation tag `"CMPT_CONVERTBACK_SIGMA"` is canonical and must be used exactly as specified (ASCII encoding, no null terminator). It is distinct from the tag used in ConfidentialMPTSend to prevent any cross-transaction proof reuse.

4. **Compute responses.**

$$
z_b = \alpha_b + e \cdot b \pmod{q}, \tag{52}
$$

$$
z_\rho = \alpha_\rho + e \cdot \rho \pmod{q}, \tag{53}
$$

$$
z_{\mathrm{sk}} = \alpha_{\mathrm{sk}} + e \cdot \mathrm{sk}_A \pmod{q}. \tag{54}
$$

5. **Output compact proof.**

$$
\pi_{\mathrm{bal}} = (e, z_b, z_\rho, z_{\mathrm{sk}}) \in \mathbb{Z}_q^4. \tag{55}
$$

**Verifier Algorithm.** Given statement $x$ and compact proof $\pi_{\mathrm{bal}} = (e, z_b, z_\rho, z_{\mathrm{sk}})$:

1. **Validate scalars.** Verify that all four scalars are valid elements of $\mathbb{Z}_q$ (i.e., in the range $[1, q-1]$).
2. **Reconstruct commitments.**

$$
T_{\mathrm{sk},1} = z_{\mathrm{sk}} \cdot G - e \cdot P_A, \tag{56}
$$

$$
T_{\mathrm{sk},2} = z_b \cdot G + z_{\mathrm{sk}} \cdot B_1 - e \cdot B_2, \tag{57}
$$

$$
T_b = z_b \cdot G + z_\rho \cdot H - e \cdot \mathrm{PC}_b. \tag{58}
$$

3. **Recompute challenge.** Compute $e'$ using Equation (51) with the reconstructed commitments.
4. **Accept or reject.** Accept if and only if $e' = e$ (using constant-time comparison).

> **Remark 4.2 (Proof size).** The compact proof $\pi_{\mathrm{bal}}$ consists of four $\mathbb{Z}_q$ scalars, yielding $4 \times 32 = 128$ bytes. This replaces the previous Variant B ElGamal–Pedersen linkage proof of 195 bytes, saving 67 bytes.

### 4.6 Range Proof

In addition to the compact sigma proof, each ConfidentialMPTConvertBack transaction includes a single Bulletproof [3] establishing:

$$
0 \le b - m < 2^{64}. \tag{59}
$$

Since $m$ is publicly known, the verifier derives the remainder commitment directly as:

$$
\mathrm{PC}_{\mathrm{rem}} := \mathrm{PC}_b - m \cdot G, \tag{60}
$$

and the Bulletproof is applied to $\mathrm{PC}_{\mathrm{rem}}$ alone. For a single 64-bit value, the Bulletproof consists of 16 group elements and 5 scalars, yielding $16 \times 33 + 5 \times 32 = 688$ bytes. This is unchanged from the previous version.

> **Remark 4.3 (Blinding factor of $\mathrm{PC}_{\mathrm{rem}}$).** The remainder commitment $\mathrm{PC}_{\mathrm{rem}} = (b - m) \cdot G + \rho \cdot H$ retains the same blinding factor $\rho$ as $\mathrm{PC}_b$, since $m$ is a public scalar and its subtraction does not introduce a new blinding term. The prover uses $\rho$ directly as the blinding input to the Bulletproof over $\mathrm{PC}_{\mathrm{rem}}$.

### 4.7 Transaction Context Binding

The `TransactionContextID` included in the Fiat–Shamir challenge (51) is defined as:

$$
\mathrm{TransactionContextID} := H(\mathrm{TxType} \parallel \mathrm{Account} \parallel \mathrm{MPTokenIssuanceID} \parallel \mathrm{SequenceOrTicket} \parallel \mathrm{TxSpecific}), \tag{61}
$$

where for ConfidentialMPTConvertBack:

$$
\mathrm{TxSpecific} := \mathrm{Account} \parallel \mathrm{CBS\_Version}(A). \tag{62}
$$

The inclusion of $\mathrm{CBS\_Version}(A)$ binds the proof to the sender’s current confidential spending balance state, preventing replay attacks using proofs generated against stale balance snapshots. Following the convention of the previous version, Receiver is set equal to Account to preserve a uniform context structure across transaction types.

### 4.8 Validation Rules

Before applying the state transition, validators perform the following checks:

- The referenced issuance exists and has confidential transfers enabled.
- The revealed amount satisfies $m \ge 0$ and conforms to XRPL amount formatting and token precision rules.
- All required ElGamal ciphertext fields are present and are well-formed secp256k1 group elements.
- For each ciphertext, direct verification using the disclosed encryption randomness $r$ confirms correct encryption of the revealed amount $m$ under the corresponding public keys.
- The Pedersen commitment $\mathrm{PC}_b$ is a well-formed secp256k1 group element.
- All proof scalars $(e, z_b, z_\rho, z_{\mathrm{sk}})$ are valid elements of $\mathbb{Z}_q$.
- The compact sigma proof $\pi_{\mathrm{bal}}$ verifies successfully per Section 4.5.
- The Bulletproof range proof over $\mathrm{PC}_{\mathrm{rem}}$ verifies successfully, establishing that the post-conversion remainder balance is non-negative.
- If an auditor ciphertext is provided, an AuditorPolicy must be active and the auditor key must match the policy.
- All proofs are transcript-bound to $\mathrm{CBS\_Version}(A)$ and to the transaction context.

Failure of any check causes the transaction to be rejected.

### 4.9 Security Properties

The compact sigma protocol for $R_{\mathrm{bal}}$ satisfies the following security properties under the discrete logarithm assumption in the secp256k1 group and the random oracle model for the Fiat–Shamir transform:

- **Completeness.** If the prover holds a valid witness $w = (b, \rho, \mathrm{sk}_A)$ for statement $x \in R_{\mathrm{bal}}$, the verifier always accepts.
- **2-Special Soundness.** Given two accepting transcripts with the same commitments but distinct challenges $e \neq e'$, an extractor can efficiently recover $(b, \rho, \mathrm{sk}_A)$.
- **Honest-Verifier Zero-Knowledge.** There exists a simulator that, given any challenge $e$ and a valid statement (but no witness), produces a transcript indistinguishable from a real proof.
- **Non-Interactive Zero-Knowledge.** The Fiat–Shamir transform yields a NIZK proof of knowledge in the random oracle model.

Full security proofs for the compact AND-composed sigma construction are provided in [2].

### 4.10 Effect and Accounting

ConfidentialMPTConvertBack is one of the two transaction families that decrease COA (the other being ConfidentialMPTClawback). For holders, the transaction moves value from confidential to public form without changing OA. In all cases, the transaction directly reveals the conversion amount $m$ and the affected accounts; see 4.11 for the privacy implications when these revealed quantities are combined with prior public-ledger events.

### 4.11 Leakage Discussion

The ConfidentialMPTConvertBack transaction necessarily reveals the plaintext conversion amount $m$, since value is moved from confidential to public form. This disclosure is intentional and mirrors the visibility of issuance and redemption events in standard XLS-33 semantics. ElGamal encryptions are randomized and semantically secure: after a conversion, an observer cannot directly determine from the cryptographic transcript alone whether the converting account’s confidential balance was fully depleted or whether it retains a nonzero confidential balance. In general, observers cannot infer whether any other specific account holds part of the remaining confidential supply. However, in low-volume issuances with few active participants, publicly visible transaction data including plaintext amounts in Convert and ConvertBack transactions and the sender-receiver account pairs visible in Send transactions can allow observers to infer constraints on hidden balances.

### 4.12 Transaction Fields

A ConfidentialMPTConvertBack transaction includes the fields summarized in Table 8.

**Table 8:** Fields of the ConfidentialMPTConvertBack transaction.

| Field | Description | Req. |
|---|---|---|
| `TransactionType` | Identifies the transaction as ConfidentialMPTConvertBack. | M |
| `Account` | The XRPL account performing the confidential-to-public conversion. | M |
| `MPTokenIssuanceID` | The unique identifier of the associated MPT issuance. | M |
| `MPTAmount` | Plaintext amount $m$ credited back to the public MPT balance. | M |
| `HolderEncryptedAmount` | A 66-byte ciphertext subtracted from the holder’s confidential spending balance. | M |
| `IssuerEncryptedAmount` | A 66-byte ciphertext subtracted from the issuer’s encrypted mirror balance. | M |
| `AuditorEncryptedAmount` | A 66-byte ciphertext for auditor visibility. Required when an auditor key is configured on the issuance. | C |
| `BlindingFactor` | The 32-byte scalar $r$ used during ElGamal encryption. Validators use it to verify ciphertext consistency with `MPTAmount`. | M |
| `BalanceCommitment` | A 33-byte Pedersen commitment $\mathrm{PC}_b$ to the holder’s confidential spending balance. | M |
| `ZKProof` | A bundle containing the Pedersen Linkage Proof $\pi_{\mathrm{bal}}$ (linking the ElGamal balance to the commitment) and the Range Proof. | M |

M = Mandatory, C = Conditional

### 4.13 Transaction Size

Table 9 summarizes the size breakdown for an auditor-enabled ConfidentialMPTConvertBack transaction.

**Table 9:** Size breakdown for ConfidentialMPTConvertBack with compact sigma proof (auditor-enabled).

| Component | Size (bytes) | Notes | Changed? |
|---|---|---|---|
| Holder ciphertext $(C_1, C_{2,H})$ | 66 | $2 \times 33$ | No |
| Issuer ciphertext $C_{2,I}$ | 33 | $1 \times 33$ | No |
| Auditor ciphertext $C_{2,A}$ | 33 | $1 \times 33$ | No |
| Blinding factor $r$ | 32 | 1 scalar | No |
| Balance commitment $\mathrm{PC}_b$ | 33 | $1 \times 33$ | No |
| Compact sigma proof $\pi_{\mathrm{bal}}$ | 128 | $4 \times 32$ | Yes (−67 bytes) |
| Bulletproof range proof | 688 | $16 \times 33 + 5 \times 32$ | No |
| **Total** | **1013** | | |

## 5 ConfidentialMPTClawback: Issuer-Enforced Reclamation

### Changes from Previous Version

The Chaum–Pedersen ciphertext–amount consistency proof (previously 98 bytes: two group elements and one scalar) is replaced by its compact Fiat–Shamir form, transmitting only the challenge and response scalars. Key changes include:

- **Proof structure:** Uncompressed Chaum–Pedersen (98 bytes) → compact form $\pi_{\mathrm{claw}} = (e, z_{\mathrm{sk}})$ (64 bytes, −34 bytes).
- **No Bulletproof:** Unchanged; clawback reclaims the entire confidential balance atomically, so no range proof for a remainder is required.
- **Transaction fields:** `ZKProof` replaced by `CompactClawbackProof`.
- **Appendix references:** Appendix C (issuer secret-key instantiation) is superseded by the compact protocol specified inline.

The ConfidentialMPTClawback transaction allows the issuer to forcibly reclaim confidential MPT value from a holder. This operation is issuer-only and is fundamentally distinct from ordinary confidential transfers. Because the issuer does not possess the holder’s private ElGamal key, it cannot construct a standard ConfidentialMPTSend transaction on the holder’s behalf. Instead, the protocol defines a single privileged transaction that enables verifiable reclamation in one atomic ledger operation. Clawback converts a holder’s entire confidential balance directly into the issuer’s public reserve. Partial clawbacks are not supported. This restriction simplifies verification, prevents ambiguous intermediate states, and ensures that public supply accounting remains consistent and auditable.

### 5.1 Notation

Table 10 defines the symbols used in this section.

**Table 10:** Notation for ConfidentialMPTClawback. All scalars are elements of $\mathbb{Z}_q$ where $q$ is the order of the secp256k1 group.

| Symbol | Description | Domain |
|---|---|---|
| $G$ | Base generator of secp256k1 | $\mathbb{G}$ |
| $m$ | Publicly revealed clawback amount (holder’s total confidential balance) | $\mathbb{Z}_q$ |
| $\mathrm{sk}_{\mathrm{iss}}$ | Issuer’s ElGamal secret key | $\mathbb{Z}_q$ |
| $P_{\mathrm{iss}}$ | Issuer’s ElGamal public key ($P_{\mathrm{iss}} = \mathrm{sk}_{\mathrm{iss}} \cdot G$) | $\mathbb{G}$ |
| $C_1, C_2$ | Issuer-encrypted mirror ciphertext components stored on-ledger for the holder | $\mathbb{G}$ |

### 5.2 Operational Overview

The clawback process proceeds as follows. First, the issuer decrypts the issuer-encrypted mirror ciphertext $(C_1, C_2)$ stored on the holder’s MPToken object using $\mathrm{sk}_{\mathrm{iss}}$, revealing the holder’s total confidential balance $m$. The issuer then submits a ConfidentialMPTClawback transaction that declares $m$ in plaintext and includes a compact ZKP attesting that $m$ is indeed the value encrypted in the on-ledger issuer ciphertext. Validators verify the proof and, if successful, apply the clawback state transition atomically.

> **Remark 5.1 (Front-running and issuer lock).** Clawback proofs bind to the concrete on-ledger ciphertext $(C_1, C_2)$ at the time of proof generation. If an intervening holder transaction (e.g., ConfidentialMPTSend) modifies the holder’s balance before the clawback executes, the issuer ciphertext will have changed and the proof will be rejected. Issuers should therefore freeze or lock the holder’s confidential activity before preparing a clawback proof, in accordance with the XRPL account freeze mechanism (TOB-RIPCTXR-13).

### 5.3 State Transition

Let $A$ denote the holder being clawed back. Upon successful validation, the ledger applies the following updates:

$$
\mathrm{CB}_S(A) \leftarrow \mathrm{EncZero}(A), \tag{63}
$$

$$
\mathrm{CB}_{\mathrm{IN}}(A) \leftarrow \mathrm{EncZero}(A), \tag{64}
$$

$$
\mathrm{Enc}_I(A) \leftarrow \mathrm{EncZero}_I(A), \tag{65}
$$

$$
\mathrm{CB\_S\_Version}(A) \leftarrow \mathrm{CB\_S\_Version}(A) + 1, \tag{66}
$$

$$
\mathrm{OA} \leftarrow \mathrm{OA} - m, \tag{67}
$$

$$
\mathrm{COA} \leftarrow \mathrm{COA} - m. \tag{68}
$$

All confidential balances associated with the holder are reset to canonical encryptions of zero. The issuer’s public reserve is increased by the revealed amount $m$, and both global accounting fields are updated accordingly. This transaction is atomic: either all updates are applied, or none are.

> **Remark 5.2 (Canonical zero reset and TOB-RIPCTXR-5).** After Clawback, all balances are reset to canonical encrypted zero with publicly known deterministic randomness. This does not reintroduce the inbox-locking vulnerability described in TOB-RIPCTXR-5 because the fix operates at the ConfidentialMPTSend level: every subsequent Send re-randomizes the receiver’s inbox ciphertext using the Fiat–Shamir challenge $e$, making the final inbox randomness unpredictable regardless of the starting state.

### 5.4 Clawback Relation

The issuer does not know the original encryption randomness used to form the on-ledger ciphertext $(C_1, C_2)$. Ciphertext–amount consistency is therefore established via knowledge of the issuer secret key $\mathrm{sk}_{\mathrm{iss}}$. The relation to be proved is:

$$
R_{\mathrm{claw}} =
\left\{
(x, w)
\;\middle|\;
\begin{aligned}
P_{\mathrm{iss}} &= \mathrm{sk}_{\mathrm{iss}} \cdot G, \\
C_2 - m \cdot G &= \mathrm{sk}_{\mathrm{iss}} \cdot C_1
\end{aligned}
\right\}, \tag{69}
$$

where the public statement is $x = (P_{\mathrm{iss}}, C_1, C_2, m)$, the witness is $w = \mathrm{sk}_{\mathrm{iss}} \in \mathbb{Z}_q$, and $m \cdot G$ is derived from the publicly revealed plaintext. This is a standard Chaum–Pedersen equality-of-discrete-logarithms relation over the single witness scalar $\mathrm{sk}_{\mathrm{iss}}$, instantiated in the issuer secret-key variant.

### 5.5 Compact Clawback Sigma Protocol

The ZKP for $R_{\mathrm{claw}}$ is instantiated as a compact Chaum–Pedersen sigma protocol under a shared Fiat–Shamir challenge, yielding a proof $\pi_{\mathrm{claw}} = (e, z_{\mathrm{sk}}) \in \mathbb{Z}_q^2$ of 64 bytes.

**Prover Algorithm.** Given witness $w = \mathrm{sk}_{\mathrm{iss}}$ and statement $x$:

1. **Sample nonce.** Sample $\alpha_{\mathrm{sk}} \stackrel{R}{\leftarrow} \mathbb{Z}_q$.
2. **Compute commitments.**

$$
T_1 = \alpha_{\mathrm{sk}} \cdot G, \tag{70}
$$

$$
T_2 = \alpha_{\mathrm{sk}} \cdot C_1. \tag{71}
$$

3. **Compute challenge.**

$$
e = H(\texttt{"CMPT\_CLAWBACK\_SIGMA"} \parallel P_{\mathrm{iss}} \parallel C_1 \parallel C_2 \parallel m \cdot G \parallel T_1 \parallel T_2 \parallel \mathrm{TransactionContextID}). \tag{72}
$$

> **Remark 5.3 (Inclusion of $m \cdot G$).** The group element $m \cdot G$ is included explicitly in the hash rather than the scalar $m$, ensuring the challenge is bound to the elliptic-curve representation of the plaintext as used in the ciphertext relation $C_2 - m \cdot G = \mathrm{sk}_{\mathrm{iss}} \cdot C_1$. Implementations must compute $m \cdot G$ and serialize it as a 33-byte compressed point.

4. **Compute response.**

$$
z_{\mathrm{sk}} = \alpha_{\mathrm{sk}} + e \cdot \mathrm{sk}_{\mathrm{iss}} \pmod{q}. \tag{73}
$$

5. **Output compact proof.**

$$
\pi_{\mathrm{claw}} = (e, z_{\mathrm{sk}}) \in \mathbb{Z}_q^2. \tag{74}
$$

**Verifier Algorithm.** Given statement $x$ and compact proof $\pi_{\mathrm{claw}} = (e, z_{\mathrm{sk}})$:

1. **Validate scalars.** Verify that both scalars are valid elements of $\mathbb{Z}_q$ (i.e., in the range $[1, q-1]$).
2. **Reconstruct commitments.**

$$
T_1 = z_{\mathrm{sk}} \cdot G - e \cdot P_{\mathrm{iss}}, \tag{75}
$$

$$
T_2 = z_{\mathrm{sk}} \cdot C_1 - e \cdot (C_2 - m \cdot G). \tag{76}
$$

3. **Recompute challenge.** Compute $e'$ using Equation (72) with the reconstructed commitments.
4. **Accept or reject.** Accept if and only if $e' = e$ (using constant-time comparison).

> **Remark 5.4 (Proof size).** The compact proof $\pi_{\mathrm{claw}}$ consists of two $\mathbb{Z}_q$ scalars, yielding $2 \times 32 = 64$ bytes. This replaces the previous uncompressed Chaum–Pedersen proof of 98 bytes (two group elements and one scalar), saving 34 bytes.

> **Remark 5.5 (No Bulletproof required).** Unlike ConfidentialMPTSend and ConfidentialMPTConvertBack, no range proof is required in ConfidentialMPTClawback. The clawback operation reclaims the holder’s entire confidential balance in a single atomic step, so there is no remainder to prove non-negative. The non-negativity of $m$ is enforced by the standard XRPL amount validation check.

### 5.6 Transaction Context Binding

The `TransactionContextID` included in the Fiat–Shamir challenge (72) is defined as:

$$
\mathrm{TransactionContextID} := H(\mathrm{TxType} \parallel \mathrm{Account} \parallel \mathrm{MPTokenIssuanceID} \parallel \mathrm{SequenceOrTicket} \parallel \mathrm{TxSpecific}), \tag{77}
$$

where for ConfidentialMPTClawback:

$$
\mathrm{TxSpecific} := \mathrm{Holder} \parallel 0. \tag{78}
$$

Version binding is intentionally omitted. Binding the proof to `CB_S_Version` would allow the holder to invalidate an issuer-prepared clawback by deliberately triggering a version increment through an intervening transaction. Replay and substitution resistance are preserved through the full proof transcript, which is bound to the concrete issuer ciphertext $(C_1, C_2)$ and the revealed plaintext amount $m$.

### 5.7 Validation Rules

Before applying the state transition, validators perform the following checks:

- The transaction is signed by the issuer account defined in the issuance.
- The referenced issuance exists and supports confidential transfers and clawback.
- The holder account exists and has a corresponding MPToken object.
- The revealed amount $m$ is non-negative and well-formed.
- The issuer-encrypted ciphertext $(C_1, C_2)$ referenced by the transaction matches the on-ledger issuer mirror ciphertext and is a valid secp256k1 group element.
- All proof scalars $(e, z_{\mathrm{sk}})$ are valid elements of $\mathbb{Z}_q$.
- The compact clawback proof $\pi_{\mathrm{claw}}$ verifies successfully per Section 5.5.
- The proof transcript is correctly bound to the transaction context, preventing replay or substitution.

Failure of any check causes the transaction to be rejected.

### 5.8 Security Properties

The compact Chaum–Pedersen sigma protocol for $R_{\mathrm{claw}}$ satisfies the following security properties under the discrete logarithm assumption in the secp256k1 group and the random oracle model for the Fiat–Shamir transform:

- **Completeness.** If the prover holds valid witness $\mathrm{sk}_{\mathrm{iss}}$ for statement $x \in R_{\mathrm{claw}}$, the verifier always accepts.
- **2-Special Soundness.** Given two accepting transcripts with the same commitments but distinct challenges $e \neq e'$, an extractor can efficiently recover $\mathrm{sk}_{\mathrm{iss}}$.
- **Honest-Verifier Zero-Knowledge.** There exists a simulator that, given any challenge $e$ and a valid statement (but no witness), produces a transcript indistinguishable from a real proof. In particular, $\mathrm{sk}_{\mathrm{iss}}$ is not revealed.
- **Non-Interactive Zero-Knowledge.** The Fiat–Shamir transform yields a NIZK proof of knowledge in the random oracle model.
- **Issuer Authority.** Only the party holding $\mathrm{sk}_{\mathrm{iss}}$ can produce a valid proof. An adversary without the issuer secret key cannot forge a clawback for any holder.

Full security proofs for the compact AND-composed sigma construction are provided in [2].

### 5.9 Effect and Accounting

ConfidentialMPTClawback is the only transaction that simultaneously: (i) reveals a holder’s confidential balance, (ii) reduces both OA and COA, and (iii) transfers value directly into the issuer’s public reserve. This operation preserves public supply soundness while enabling issuer-enforced recovery for compliance, regulatory, or emergency scenarios.

### 5.10 Leakage Discussion

Clawback intentionally reveals the total confidential balance of the affected holder. This disclosure is unavoidable by design and reflects the issuer’s explicit exercise of reclaim authority. In general, beyond the revealed amount and the identity of the holder, no additional information is leaked. In particular, the confidential balances of all other holders remain hidden. Observers can verify that global supply invariants are maintained, but cannot infer information about the distribution of remaining confidential supply across accounts. However, in low-volume issuances with few active participants, revealing a holder’s total confidential balance via Clawback, combined with visible Send transaction pairs and prior Convert amounts, can allow observers to infer the amounts transferred to that holder and constrain the balances of related accounts.

### 5.11 Transaction Fields

A ConfidentialMPTClawback transaction includes the fields summarized in Table 11.

**Table 11:** Fields of the ConfidentialMPTClawback transaction.

| Field | Description | Req. |
|---|---|---|
| `TransactionType` | Identifies the transaction as ConfidentialMPTClawback. | M |
| `Account` | The issuer account initiating the clawback transaction. | M |
| `Holder` | The holder account from which confidential funds are being clawed back. | M |
| `MPTokenIssuanceID` | The unique identifier of the associated MPT issuance. | M |
| `MPTAmount` | The plaintext total amount $m$ removed from the holder’s confidential balance and credited to the issuer’s public reserve. | M |
| `ZKProof` | The compact Chaum–Pedersen proof $\pi_{\mathrm{claw}} = (e, z_{\mathrm{sk}})$ (64 bytes) validating that the revealed plaintext amount matches the issuer-encrypted balance representation. | M |

M = Mandatory

### 5.12 Transaction Size

Table 12 summarizes the size breakdown for a ConfidentialMPTClawback transaction.

**Table 12:** Size breakdown for ConfidentialMPTClawback with compact proof.

| Component | Size (bytes) | Notes | Changed? |
|---|---|---|---|
| Compact clawback proof $\pi_{\mathrm{claw}}$ | 64 | $2 \times 32$ | Yes (−34 bytes) |
| **Total proof material** | **64** | | |

> **Remark 5.6 (Transaction size scope).** The clawback transaction carries no ciphertexts, commitments, or blinding factors beyond the mandatory transaction fields and the compact proof. The issuer ciphertext $(C_1, C_2)$ referenced by the proof is read directly from the on-ledger MPToken object of the holder and is not re-transmitted in the transaction body. Accordingly, the cryptographic payload of the transaction is dominated entirely by the 64-byte compact proof, compared to 98 bytes in the previous version.

## References

[1] Murat Cenk, Aanchal Malhotra, and Joseph A. Akinyele. Confidential Transfers for Multi-Purpose Tokens on the XRP Ledger. Cryptology ePrint Archive, Paper 2026/602, 2026. <https://eprint.iacr.org/2026/602>.

[2] Tess Dore and Murat Cenk. Compact Sigma Protocols for Standard EC-ElGamal in Confidential Multi-Purpose Tokens on XRPL. RippleX Research, March 2026.

[3] Benedikt Bünz, Jonathan Bootle, Dan Boneh, Andrew Poelstra, Pieter Wuille, and Greg Maxwell. Bulletproofs: Short proofs for confidential transactions and more. In IEEE Symposium on Security and Privacy, pages 315–334, 2018.

[4] Ronald Cramer, Ivan Damgård, and Berry Schoenmakers. Proofs of partial knowledge and simplified design of witness hiding protocols. In CRYPTO ’94, volume 839 of LNCS, pages 174–187. Springer, 1994.
