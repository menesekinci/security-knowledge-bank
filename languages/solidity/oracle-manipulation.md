# 🔴 Solidity Oracle Manipulation

## Example (Dangerous)
```solidity
// 💀 VULNERABLE — Contract that reads the spot price from a single DEX pair:
function getCollateralValue(address token) public view returns (uint) {
    // getReserves() returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)
    (uint112 reserve0, uint112 reserve1, ) = uniswapV2Pair.getReserves();
    // Instantaneous spot price = reserve of token1 per token0.
    // A single DEX pair — easily skewed with a flash loan in one block!
    uint price = (uint(reserve1) * 1e18) / uint(reserve0);
    return price;
}

// ✅ Safe — Chainlink Data Feed (decentralized, aggregated off-chain price):
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

function getCollateralValue(address token) public view returns (uint) {
    // NOTE: latestRoundData() returns the latest AGGREGATED price reported by the
    // Chainlink Data Feed — it is NOT an on-chain TWAP. It resists flash-loan
    // manipulation because the price is sourced off-chain from many exchanges,
    // not read from a single DEX pool in the same transaction.
    AggregatorV3Interface priceFeed = AggregatorV3Interface(0x...);
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(price > 0, "Bad price");
    require(block.timestamp - updatedAt < 1 hours, "Stale price");
    return uint(price);
}

// ✅ Alternative — a real on-chain TWAP from Uniswap V3 (time-weighted, not spot):
//   OracleLibrary.consult(pool, twapInterval) returns an arithmeticMeanTick
//   averaged over `twapInterval` seconds, which a single-block flash loan
//   cannot move. Use getQuoteAtTick() to convert the tick into a price.
```

## Prevention
- Use a decentralized oracle such as **Chainlink**
- Use **TWAP** (time-weighted average price)
- **Circuit breaker** — halt on abnormal price movements
- Set **minimum/maximum price bounds**

---

**Severity: 🔴 Critical**
