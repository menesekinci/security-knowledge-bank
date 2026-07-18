# 🟡 Weak Randomness On-Chain

| Field | Value |
|-------|-------|
| **Severity** | 🟠 High (gambling / NFT rarity / lottery drain) |
| **SWC** | [SWC-120](https://swcregistry.io/docs/SWC-120) — Weak Sources of Randomness from Chain Attributes |
| **CWE** | [CWE-330](https://cwe.mitre.org/data/definitions/330.html) Use of Insufficiently Random Values |
| **Related** | [front-running.md](front-running.md), [flash-loan.md](flash-loan.md), [access-control.md](access-control.md) |

---

## What Is It? (Explanation)

The EVM **does not provide a secure random number generator**. The following are **predictable** or **manipulatable**:

| Source | Why weak? |
|--------|-----------|
| `block.timestamp` | Miner/builder can set it within a limited range; everyone can see it |
| `block.number` | Known, changes slowly |
| `blockhash(block.number - 1)` | Past hash is public; last 256 blocks; miner influence |
| `block.prevrandao` (old `difficulty`) | Beacon random; uses **validator** info but every contract in the **same block** sees the same value; commit + predict/snipe scenarios still a design risk |
| `keccak256(abi.encodePacked(msg.sender, tx.gasprice, ...))` | Attacker controls inputs |
| `blockhash(future)` | `blockhash` only past; future = 0 |

Result: lottery, card shuffle, NFT trait, random winner, "50% chance drop" can be **biased by the attacker**. Attacker:

1. Finds winning TX via simulation (eth_call / local fork),
2. Only broadcasts profitable TXs,
3. Or cancels losing attempts via `revert` in their contract,
4. Selects order via MEV ([front-running.md](front-running.md)).

---

## AI / Vibe Coding Patterns

| Prompt | AI error |
|--------|----------|
| "Lottery random winner" | `uint(keccak(block.timestamp)) % n` |
| "NFT random rarity" | `blockhash` at mint time |
| "Coin flip bet" | Randomness + payout in the same TX |
| "Shuffle array" | On-chain pseudo-random seed weak |
| "Secure random with difficulty" | `prevrandao` alone insufficient for gambling |

```
Prompt: "Simple coinflip dapp"
AI:
function flip() external payable {
  require(msg.value == 1 ether);
  if (uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 2 == 0) {
    payable(msg.sender).transfer(2 ether); // 💀 predict + only win
  }
}
```

---

## Vulnerable Code (Solidity)

### 1) block.timestamp "random"

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableLottery {
    address[] public players;

    function enter() external payable {
        require(msg.value == 0.1 ether);
        players.push(msg.sender);
    }

    // 💀 timestamp + player count predictable/manipulatable
    function pickWinner() external {
        uint256 idx = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.difficulty, players.length))
        ) % players.length;
        payable(players[idx]).transfer(address(this).balance);
        delete players;
    }
}
```

### 2) Same-block predict & win

```solidity
contract VulnerableFlip {
    // 💀 All entropy from pre-TX known fields
    function play(uint256 guess) external payable {
        require(msg.value == 1 ether);
        uint256 roll = uint256(blockhash(block.number - 1)) % 100;
        if (guess == roll) {
            payable(msg.sender).transfer(2 ether);
        }
    }
}

// Attacker:
// 1) Compute roll with eth_call
// 2) Send TX with correct guess
// 3) Or contract: if (wrong) revert;
```

### 3) "Hide" seed in block.number + no future reveal

```solidity
// 💀 No commit; everyone computes traits at mint / sniper bot
function mint() external {
    uint256 rarity = uint256(keccak256(abi.encodePacked(block.prevrandao, msg.sender))) % 100;
    _mintWithRarity(msg.sender, rarity);
}
```

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

## Prevention Checklist

- [ ] Grep for `block.timestamp` / `blockhash` / `prevrandao` used for "random"
- [ ] Gambling/lottery: VRF or commit-reveal present?
- [ ] Are randomness and payout in the **same TX**? (critical anti-pattern)
- [ ] Can attacker's contract cancel losing attempts via `revert`?
- [ ] NFT rarity: reveal phase separate; metadata pre-image commit
- [ ] Economic test: EV of grinding / simulation attack
- [ ] Documentation: randomness trust model clearly stated

---

## Real Incidents

| Incident | Year | Summary | Source |
|----------|------|---------|--------|
| **Fomo3D / airdrop-style PRNG** | 2018 | On-chain "random" airdrop/bonus; bots and block vars give advantage | Public analyses, SWC-120 discussions |
| **SmartBillions** | ~2017 | `blockhash`-based lottery design flaws | Historical Ethereum lottery write-ups |
| **Countless vulnerable coin-flip CTF/mainnet copies** | continuous | `keccak(timestamp)` pattern | [SWC-120](https://swcregistry.io/docs/SWC-120) samples |
| **NFT mint trait sniping** | 2021+ | Predictable rarity at mint | Industry reports (class pattern) |

---

## Vibe Coding Red Flags

```
🚩 block.timestamp % n
🚩 keccak256(block.timestamp, msg.sender, ...)
🚩 blockhash(block.number - 1) with payout in same function
🚩 "difficulty/prevrandao is sufficient" for high TVL gambling
🚩 AI: "blockchain random is secure"
🚩 User guess + resolve in single TX
🚩 Secret seed in plain contract storage
🚩 msg.sender as sole entropy
```

### AI Prompt Snippet

```
Don't use block.timestamp/blockhash for on-chain gambling/lottery/NFT rarity.
High value: Chainlink VRF (separate request/fulfill).
Medium: commit-reveal + multi-party seed.
Don't allow predict-and-win in the same transaction.
```

---

**Severity: 🟠 High** — Protocol vault can be systematically drained.
**SWC: SWC-120** · **Refs:** [SWC-120](https://swcregistry.io/docs/SWC-120), [ConsenSys — randomness](https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/randomness/), [Chainlink VRF docs](https://docs.chain.link/vrf)
