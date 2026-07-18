---
source: "languages/solidity/unchecked-calls.md"
title: "🟡 Unchecked External Calls"
heading: "Secure Fix (OZ SafeERC20 + checked call)"
category: "language-vuln"
language: "solidity"
severity: "high"
tags: [checklist, code, incidents, language-vuln, prevention, real, secure, solidity, vibe, vulnerable]
chunk: 4/7
---

## Secure Fix (OZ SafeERC20 + checked call)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract SecurePayout is ReentrancyGuard {
    using SafeERC20 for IERC20;
    using Address for address payable;

    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "zero");
        balances[msg.sender] = 0; // CEI
        // Address.sendValue: call + require success
        payable(msg.sender).sendValue(amount);
        // or:
        // (bool ok, ) = msg.sender.call{value: amount}("");
        // require(ok, "ETH xfer");
    }

    function withdrawToken(IERC20 token, address to, uint256 amount) external nonReentrant {
        // fee-on-transfer may require a separate balance-before/after design
        token.safeTransfer(to, amount);
    }
}

// external contract via try/catch (when the return data matters)
contract SecureExternal {
    function callOther(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "call fail");
        return ret;
    }
}
```

**Rules:**

1. Every `call` / `send` / `delegatecall`: **check success**, or a deliberate "best-effort" + documentation (rarely).
2. ETH: `Address.sendValue` or `call` + `require`.
3. ERC20: **SafeERC20** (`safeTransfer`, `safeTransferFrom`, `forceApprove`).
4. **CEI** + **nonReentrant** — a success check does not solve reentrancy.
5. `transfer()` (2300 gas) can fall short with modern recipient contracts; prefer `call` + check.
6. Batch: a success policy per sub-call (all-or-nothing vs. continue + event).
7. Return data: check `ok` before `abi.decode`.

---