# Wormhole Bridge Hack (2022) — Solidity Signature Verification Bypass

**Language:** Solidity
**Vulnerability Type:** Signature Verification Bypass, Deprecated Function Usage
**Loss:** $326 Million (120,000 wETH)
**Date:** February 2, 2022
**Platform:** Wormhole — Solana ↔ Ethereum Bridge

## Overview

The Wormhole bridge hack was one of the largest DeFi exploits in history. An attacker exploited a **deprecated Solana smart contract function** to forge validator signatures, minting 120,000 wETH (~$326M at the time) from the Wormhole bridge without depositing any collateral. Jump Crypto (Wormhole's parent company) eventually replenished the funds.

## Root Cause

The Wormhole bridge on Solana used a function from a **deprecated Solana library** (`solana_program::sysvar::instructions::load_instruction_at`). This function had a different behavior than its replacement — it did not properly verify that the instructions being signed were actually part of the validator's signing context. The attacker exploited this discrepancy to forge signature verification.

## Technical Details

### The Vulnerability

```solidity
// The Solidity/Wormhole bridge on Ethereum side:
// (Simplified — actual exploit was on the Solana side in Rust)
// but the vulnerable contract pattern is similar:

contract WormholeBridge {
    struct VMSignature {
        bytes32 r;
        bytes32 s;
        uint8 v;
        uint8 guardianIndex;
    }
    
    mapping(uint256 => bool) public processedVMs;
    
    // ⚠️ VULNERABLE: Accepts arbitrary guardian signatures
    function executeGovernanceAction(
        bytes memory vm,
        VMSignature[] memory signatures,
        uint256 guardianSetIndex
    ) public {
        // ⚠️ Insufficient signature verification!
        // The Solana side had the real bug:
        // Using deprecated load_instruction_at instead of
        // the correct instruction data verification
        
        require(
            verifySignatures(vm, signatures, guardianSetIndex),
            "Invalid signatures"
        );
        
        // Process governance action
        bytes32 hash = keccak256(vm);
        require(!processedVMs[hash], "Already processed");
        processedVMs[hash] = true;
        
        executeVM(vm);
    }
}
```

### Actual Exploit Chain (Solana Side)

The real vulnerability was in the Solana smart contract (written in Rust/C):

```rust
// VULNERABLE: Using deprecated sysvar
// solana_program::sysvar::instructions::load_instruction_at
// This function did NOT validate that the instruction belonged
// to the transaction's signing context

let instruction = load_instruction_at(
    index as usize,
    &sysvar_account.data.borrow()
)?;

// The attacker could craft a transaction where:
// 1. An instruction that appeared to be a valid guardian signature
// 2. Was actually from a different transaction context
// 3. The deprecated function didn't verify instruction ownership

// The correct API (post-security-fix):
// Use instructions::get_instruction_relative or
// validate that the instruction index belongs to the current tx
```

### Attack Flow

1. Attacker identifies the deprecated `load_instruction_at` function being used for signature verification
2. Attacker crafts a transaction with specially crafted instructions
3. The deprecated function returns a "valid" signature that was never actually signed by a guardian
4. The bridge mints 120,000 wETH (~$326M) to the attacker's account
5. The attacker bridges the funds to Ethereum and begins converting to other assets

## Impact

- **$326 Million stolen** (120,000 wETH)
- **Second-largest DeFi hack** at the time (behind Poly Network's $610M)
- **Solana ecosystem severely impacted** — bridge paused for weeks
- **Jump Crypto replenished** the stolen funds (deposited 120,000 ETH)
- **New Solana bridge security standards** established

## Lessons

1. **Never use deprecated library functions** — they often have subtle behavioral differences
2. **Signature verification is the most security-critical function** in a bridge
3. **Cross-chain logic is inherently risky** — two different chains' security models must match
4. **Audit both sides of a bridge** — Solana side was audited but the deprecated function was missed
5. **Defense in depth**: Even if signatures are "verified", limit mint amounts per time period

## Secure Code Pattern

```solidity
// SECURE: Multiple layers of verification
contract SecureBridge {
    // 1. Use only currently audited library functions
    // 2. Implement multiple verification methods
    // 3. Rate-limit minting
    
    mapping(bytes32 => bool) public processedVMs;
    mapping(uint256 => uint256) public dailyMintLimit;
    
    function executeWithMultipleChecks(
        bytes memory vm,
        VMSignature[] memory signatures
    ) public {
        // Check 1: Use verified, non-deprecated signature verification
        require(
            verifyWithCurrentFunction(vm, signatures),
            "Invalid signatures"
        );
        
        // Check 2: Rate limit
        uint256 today = block.timestamp / 1 days;
        require(
            dailyMintLimit[today] < MAX_DAILY_MINT,
            "Daily limit exceeded"
        );
        
        // Check 3: Integrity check
        bytes32 hash = keccak256(vm);
        require(!processedVMs[hash], "Already processed");
        processedVMs[hash] = true;
        
        // ... execute
    }
    
    // Use current, audited signature verification
    // Implement fresh in each upgrade, never reuse deprecated code
}
```

## References

- [Halborn — Explained: The Wormhole Hack](https://www.halborn.com/blog/post/explained-the-wormhole-hack-february-2022)
- [Chainalysis — Lessons from the Wormhole Exploit](https://www.chainalysis.com/blog/wormhole-hack-february-2022/)
- [Elliptic — $325M Stolen from Wormhole](https://www.elliptic.co/blog/325-million-stolen-from-wormhole-defi-service)
- [ReKT News — Wormhole](https://rekt.news/wormhole-hack/)
- [Jump Crypto Replenishment Statement](https://wormhole.com/jump-crypto-has-deposited-120000-eth/)
