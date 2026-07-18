---
source: "languages/solidity/weak-randomness.md"
title: "🟡 Weak Randomness On-Chain"
heading: "Secure Fix (VRF / commit-reveal / off-chain)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 5/8
---

## Secure Fix (VRF / commit-reveal / off-chain)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// --- 1) Chainlink VRF v2.x (summary pattern) ---
// import "@chainlink/contracts/src/v0.8/vrf/VRFConsumerBaseV2.sol";
// requestRandomWords → fulfillRandomWords callback (separate TX, different model from builder manipulation)

// --- 2) Commit-reveal (multi-party / user seed) ---
contract CommitRevealRand {
    mapping(address => bytes32) public commit;
    mapping(address => uint256) public revealed;
    uint256 public revealDeadline;

    function commitHash(bytes32 h) external {
        commit[msg.sender] = h; // keccak256(abi.encodePacked(secret, msg.sender))
    }

    function reveal(uint256 secret) external {
        require(
            commit[msg.sender] == keccak256(abi.encodePacked(secret, msg.sender)),
            "bad"
        );
        revealed[msg.sender] = secret;
    }

    // Combine multiple reveals: seed = xor/keccak of secrets + optional prevrandao
    function combinedSeed(address a, address b) external view returns (bytes32) {
        return keccak256(abi.encodePacked(revealed[a], revealed[b], block.prevrandao));
    }
}

// --- 3) Delayed blockhash (caution: 256 limit + miner bias still exists; weak on its own) ---
// Only for low-value, with additional commit; for high value use VRF

// --- 4) Off-chain fair: sign seed with oracle network / drand / RANDAO + delay games ---
```

**Practical guide:**

| Value risk | Recommendation |
|------------|---------------|
| High (vault, large lottery) | **Chainlink VRF** or equivalent multi-party randomness |
| Medium | Commit-reveal + time lock + multiple participants |
| Low cosmetic | `prevrandao` + documented bias; still snipable |
| Never | `block.timestamp` / `blockhash` / `msg.sender` alone as "secure random" |

Bets amplified by flash loans amplify weak randomness → [flash-loan.md](flash-loan.md).

---