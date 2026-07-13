# LibReferenceOracle never validates Chainlink staleness — broker-priced market orders can trade against a frozen oracle

**Severity (proposed): Medium**
(High if the target program treats broker-key compromise as fully in-scope for fund-loss impact; see Severity discussion.)

**Target:** MUX LiquidityPool / OrderBook contracts
**Affected files:** `libraries/LibReferenceOracle.sol`, `orderbook/OrderBook.sol`, `orderbook/LibOrderBook.sol`, `core/Trade.sol`, `core/Admin.sol`

---

## Summary

`LibReferenceOracle._readChainlink()` reads only `latestAnswer()` from the configured Chainlink aggregator. It never reads `latestTimestamp()` / `latestRoundData().updatedAt`, and no caller anywhere in the reviewed call graph checks `block.timestamp - updatedAt` against a `maxStaleness` bound — even though the library's own declared interface (`IChainlinkV2V3`) exposes that data.

For **market orders**, this Chainlink reference is the *only* on-chain price validation left in the system: the trader-supplied limit-price check in `OrderBook.fillPositionOrder()` is explicitly skipped for market orders, and the broker-supplied `assetPrice`/`collateralPrice` is otherwise trusted as-is. If an asset's `referenceDeviation` is set to `0` (a valid, owner-settable configuration), the Chainlink price isn't even a bound — it **replaces** the broker price outright.

Net effect: if a configured Chainlink feed stalls (deprecated aggregator, oracle node outage, L2 sequencer downtime, etc.), the contracts keep trading against that frozen price indefinitely, with no revert and no on-chain signal that anything is wrong.

## Root Cause

`LibReferenceOracle.sol`:

```solidity
function _readChainlink(address referenceOracle) internal view returns (uint96) {
    int256 ref = IChainlinkV2V3(referenceOracle).latestAnswer();
    require(ref > 0, "P=0"); // oracle Price <= 0
    ref *= 1e10; // decimals 8 => 18
    return uint256(ref).safeUint96();
}
```

No `updatedAt`/staleness check exists here, in `checkPrice`, `checkPriceWithSpread`, or `checkParameters` (which only validates decimals and that the *current* price is `> 0` at set-time — it never re-checks staleness on every read).

```solidity
function _truncatePrice(Asset storage asset, uint96 price, uint96 ref) private returns (uint96) {
    if (asset.referenceDeviation == 0) {
        return ref;   // <-- broker price fully discarded, stale-or-not
    }
    ...
}
```

`Admin.setReferenceOracle` is `onlyOwner` and calls `LibReferenceOracle.checkParameters`, which only enforces `referenceDeviation <= 1e5` — `0` is a legal value, not an edge case that requires a malicious owner.

## Call Path to Market Orders

1. `OrderBook.fillPositionOrder(orderId, collateralPrice, assetPrice, profitAssetPrice)` — `onlyBroker`.
2. Price-limit check is skipped entirely when `order.isMarketOrder()`:
   ```solidity
   // price check
   if (!order.isMarketOrder()) {
       ...
       require(tradingPrice <= order.price, "LMT");
   }
   ```
   (`OrderBook.sol`, price-check block)
3. `LibOrderBook.fillOpenPositionOrder` / `fillClosePositionOrder` pass `assetPrice`/`collateralPrice` straight through to `pool.openPosition` / `pool.closePosition` with no further validation.
4. `Trade.openPosition` / `closePosition` (`onlyOrderBook`) call `LibReferenceOracle.checkPriceWithSpread` / `checkPrice` — the staleness-blind function above — as the sole remaining sanity check on the broker's price.

So for a market order, the trust chain collapses to: **broker price, bounded (or replaced) by a Chainlink read that is never checked for freshness.**

## Impact

- If the configured feed stalls while the pool keeps operating, a broker (compromised key, malfunctioning off-chain service, or simple misconfiguration) can push `assetPrice` values that are bounded against a stale reference rather than the real market price, causing positions to open/close at incorrect prices and mispriced PnL extraction from the pool.
- For any asset configured with `referenceDeviation == 0`, this is not a bound at all: the pool will silently keep trading at the exact frozen Chainlink price for as long as the feed is stalled, regardless of what the broker submits.
- This is a defense-in-depth failure, not a fully permissionless exploit: it requires the broker role (or a compromised broker) to submit a trade during the staleness window. Broker roles are whitelisted via `Admin1.addBroker`, `onlyMaintainer`.

## Severity Discussion

We are proposing **Medium**, because:
- Exploitation requires a trusted-but-compromisable role (broker key), not an arbitrary external actor — this is the standard "trusted role compromise" scenario, which most programs price lower than a fully permissionless bug.
- However, the *entire point* of the Chainlink reference bound is to be the safety net for exactly this scenario (broker key compromise / broker bug). Because that safety net silently degrades to "protect against nothing" during a stale-feed window — and disappears entirely at `referenceDeviation == 0` — the control provides materially less protection than the codebase's own comments and design intent claim.
- We'd support escalation to **High** if: (a) any Chainlink feed used by the deployment has a documented history of stalls/deprecation, or (b) the program's threat model explicitly includes "privileged role compromised, and a stated on-chain safety control must still hold."

## Proof of Concept

Attached: a standalone Foundry project (`REPORT.md`'s sibling folder) containing:
- `src/LibReferenceOracle.sol`, `src/Types.sol` — copied verbatim from the audited code.
- `src/mocks/MockChainlink.sol` — a fake aggregator implementing `IChainlinkV2V3` with a settable stale `updatedAt`.
- `src/harness/OracleHarness.sol` — thin external wrapper so the internal library can be called from tests, using the real `LiquidityPoolStorage`/`Asset` layout.
- `test/ReferenceOracleStaleness.t.sol` — three tests:
  1. `test_staleChainlinkPriceIsAcceptedWithoutRevert` — a 10-day-old Chainlink answer is accepted with zero reverts and used to bound the broker's trade price.
  2. `test_zeroDeviationMakesStaleChainlinkPriceTheOnlyPrice` — with `referenceDeviation = 0`, a 30-day-old Chainlink answer becomes the trade price outright, independent of the broker-submitted price.
  3. `test_freshPriceWithinBandIsUnaffected` — control case, confirming the harness reproduces production behavior faithfully and the bug is specifically about staleness.

Run with:
```bash
forge install foundry-rs/forge-std
forge test -vvv --match-path test/ReferenceOracleStaleness.t.sol
```

*(Written and reviewed against the supplied source; not yet forge-compiled in this environment due to no network egress for `forge install`. Please run locally before submission and paste the console output into the report.)*

## Recommended Fix

In `_readChainlink`, switch to `latestRoundData()` and enforce a `maxStaleness` window configurable per-asset (or globally) via `Admin.setReferenceOracle`/`checkParameters`:

```solidity
function _readChainlink(address referenceOracle, uint256 maxStaleness) internal view returns (uint96) {
    (, int256 ref, , uint256 updatedAt, ) = IChainlinkV2V3(referenceOracle).latestRoundData();
    require(ref > 0, "P=0");
    require(block.timestamp - updatedAt <= maxStaleness, "STALE");
    ref *= 1e10;
    return uint256(ref).safeUint96();
}
```

Additionally, consider disallowing `referenceDeviation == 0` as a silent "trust Chainlink fully" mode, or at minimum requiring it be paired with an explicit, documented staleness bound, since at that setting the staleness check above becomes the *only* protection on asset pricing.

## Affected Code References

- `LibReferenceOracle.sol` — `_readChainlink` (no staleness check), `_truncatePrice` (full override at `referenceDeviation == 0`), `checkParameters` (no staleness param).
- `OrderBook.sol` — `fillPositionOrder`, price-limit check skipped for `isMarketOrder()`.
- `LibOrderBook.sol` — `fillOpenPositionOrder`, `fillClosePositionOrder`.
- `Trade.sol` — `openPosition`, `closePosition`, calls into `LibReferenceOracle`.
- `Admin.sol` — `setReferenceOracle`, allows `referenceDeviation = 0`.
