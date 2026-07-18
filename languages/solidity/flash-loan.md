# 🔴 Solidity Flash Loan Attacks

## What Is It?
Flash loan: An **uncollateralized** loan that is borrowed and repaid in the same block.
An attacker temporarily borrows millions of dollars, manipulates the price, takes profit, and repays the loan.

## Example (Oracle Manipulation)
```solidity
// 💀 VULNERABLE — a lending market that reads the DEX SPOT price directly:
function getPrice() public view returns (uint) {
    // Reads the instantaneous spot price of a single DEX pool — can be manipulated!
    return dexPair.getSpotPrice();
}

// This price is used to value collateral:
function borrow(uint amount) external {
    uint collateralValue = collateralAmount[msg.sender] * getPrice();
    require(collateralValue >= amount, "Undercollateralized");
    // ... lends `amount` out based on the manipulated valuation
}

// Flash Loan Attack — the key is a SEPARATE VICTIM that trusts the DEX price:
// 1. Borrow a large amount of TOKEN via a flash loan.
// 2. Dump it into the DEX pool → the pool's spot price of the collateral asset
//    swings sharply (up or down, depending on which side you need).
// 3. Call the VICTIM protocol (the lending market / vault above) while the price
//    is distorted. Because it reads getPrice() from that same pool, it now
//    mis-values collateral:
//      - Inflated: borrow far more than your collateral is really worth, or
//      - Deflated: liquidate other users' positions cheaply / mint too many shares.
// 4. Extract the over-borrowed funds (or seized collateral) from the victim.
// 5. Reverse the DEX trade to recover most of the TOKEN and repay the flash loan.
// 6. Net profit = value drained from the victim minus DEX/flash-loan fees. 💀
//
// NOTE: simply sell-then-buy-back in the SAME pool is NOT profitable — you lose
// the swap fees on both legs. The profit comes from a third-party protocol that
// prices assets off the manipulated pool during the attack window.
```

## Prevention
- Use **TWAP (Time-Weighted Average Price)** — average price, not spot price
- Use **Chainlink Oracle** — decentralized price feed
- Add **minimum liquidity** check
- **Flash loan detection** — detect buy-sell pattern in the same block

---

**Severity: 🔴 Critical** — Million $ loss.
