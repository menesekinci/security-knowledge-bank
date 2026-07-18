# Euler Finance Flash Loan Attack (2023) — Solidity / DeFi

> **Severity:** Critical
> **Loss:** ~$197 million
> **Date:** March 13, 2023
> **Class:** Missing solvency check + dynamic (soft) liquidation abuse, amplified by a flash loan

---

## 📅 When Did It Happen?

March 13, 2023. Euler Finance, an Ethereum lending protocol, was drained of roughly **$197 million** across DAI, WBTC, stETH and USDC in a single attack transaction sequence.

## 🔴 What Happened?

The attacker used a flash loan to enter an oversized, deliberately **insolvent** position, then liquidated *themselves* at a steep discount created by Euler's own liquidation logic — walking away with far more collateral than they put in.

Simplified attack sequence:

1. Take a **30M DAI flash loan** from Aave.
2. Deposit into Euler and repeatedly **mint** (leverage up), ending with a heavily leveraged eDAI / dDAI position.
3. Call **`donateToReserves()`** to donate a large amount of eDAI to the protocol reserves. This shrinks the account's own collateral **without any health check**, pushing the account into insolvency (e.g. ~310M eDAI collateral vs ~390M dDAI debt).
4. **Self-liquidate** the now-unhealthy position. Euler's dynamic "soft" liquidation grants the liquidator a large discount on unhealthy collateral (up to ~75% in bad-debt territory), so the attacker-as-liquidator receives more value than the debt they clear.
5. Withdraw the surplus and repay the flash loan. Repeat across pools.

## 🧠 Root Cause

The core bug was a **missing solvency/health check in `donateToReserves()`**. Every other balance-reducing operation in Euler ran `checkLiquidity()` to ensure the account stayed solvent — but `donateToReserves()` did not. That let a user intentionally make *their own* account unhealthy.

On its own that would be harmless; the damage came from **combining it with Euler's dynamic liquidation discount**. The less healthy a position is, the larger the discount a liquidator receives. By self-donating into deep insolvency and then self-liquidating, the attacker turned that discount into direct profit.

> ⚠️ **Corrigendum:** this incident is frequently mis-summarized as "price oracle manipulation." It was **not** an oracle attack. The root cause was a missing health check on `donateToReserves()` plus abusable soft-liquidation math. An earlier draft of this KB entry repeated the oracle claim; it has been corrected against published post-mortems.

## 💥 Vulnerable Pattern

```solidity
// Simplified illustration of the missing-check class (NOT the exact Euler code)
function donateToReserves(uint256 amount) external {
    // Reduces the caller's collateral balance...
    balanceOf[msg.sender] -= amount;
    totalReserves        += amount;
    // ...but never verifies the caller is still solvent afterwards.
    // Every OTHER exit path calls checkLiquidity(msg.sender) here.  <-- missing
}
```

## 🛠️ Secure Fix

```solidity
function donateToReserves(uint256 amount) external {
    balanceOf[msg.sender] -= amount;
    totalReserves        += amount;
    checkLiquidity(msg.sender); // enforce the same solvency invariant as every other balance-reducing path
}
```

Euler patched the function to run the liquidity check, and later protocol changes tightened liquidation behavior.

## 🤖 How AI / Vibe Coding Recreates This Class

AI-generated lending/vault contracts almost never model adversarial, single-transaction sequences:

- They apply solvency/health checks to obvious paths (borrow, withdraw) but **forget "unusual" balance-reducing paths** like donate, gift, rescue, or reserve transfers — exactly the gap here.
- They copy "dynamic liquidation discount" ideas from tutorials without reasoning about **self-liquidation** or flash-loan atomicity.
- Unit tests pass because the happy path works; the missing **invariant** ("an account must stay solvent after *every* balance change") is never asserted.

## ✅ Prevention Checklist

- [ ] Enforce the solvency invariant after **every** function that reduces collateral — no exceptions for donate/rescue/admin paths.
- [ ] Write **invariant / fuzz tests** (Foundry `invariant_`) such as "no user can end a transaction insolvent and profitable."
- [ ] Model **flash-loan atomicity** and **self-liquidation** explicitly in the threat model.
- [ ] Prefer battle-tested libraries (OpenZeppelin, audited ERC-4626) over hand-rolled accounting.
- [ ] Multiple independent audits **and** a bug bounty before scaling TVL.
- [ ] Never deploy AI-authored Solidity to mainnet without human adversarial review.

## 🚩 Vibe-Coding Red Flags

- A balance-reducing function that does **not** call the same health/liquidity check as its siblings.
- Liquidation logic with a discount that grows as health drops, with no guard against liquidating your own position.
- "Tests green over a weekend" treated as production-ready DeFi.

## 🔗 Sources

- Cyfrin — Deep Dive Exploit Analysis: https://www.cyfrin.io/blog/how-did-the-euler-finance-hack-happen-hack-analysis
- BlockSec — Root Cause of Euler's $200M Loss: https://blocksec.com/blog/defi-exploit-analysis-root-cause-euler-s-200m
- Hacken — The Euler Finance Hack Explained: https://hacken.io/discover/euler-finance-hack/
- Immunebytes — Euler Finance Hack (Mar 13, 2023): https://immunebytes.com/blog/euler-finance-hack-mar-13-2023-detailed-hack-analysis/
- SlowMist — Analysis of the Attack on Euler Finance: https://slowmist.medium.com/slowmist-an-analysis-of-the-attack-on-euler-finance-5143abc0d5ad

## Related KB

- [flash-loan.md](../flash-loan.md)
- [oracle-manipulation.md](../oracle-manipulation.md)
- [reentrancy.md](../reentrancy.md)
- [access-control.md](../access-control.md)
