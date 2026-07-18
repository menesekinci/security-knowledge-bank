---
source: "languages/solidity/weak-randomness.md"
title: "🟡 Weak Randomness On-Chain"
heading: "Vulnerable Code (Solidity)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, language-vuln, prevention, secure, solidity, vibe, vulnerable, what]
chunk: 4/8
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