Lively Tiger Dragon

medium

# Chainlink datafeed may be stale and incorrect


## Summary

There are two issues related to the chainlink datafeed:

1. The current datafeed uses 3 day for staleness check, but the update period for EUR/USD on arbitrum is 1 hour.
2. It does not consider the builtin circuit breaker.

## Vulnerability Detail

### 1. Staleness check

First let's talk about the staleness check issue.

This protocol is deployed on both Ethereum and Arbitrum, and the datafeed is used for EUR/USD and IB01/USD. According to the readme, the current staleness check is set to 3 days because IB01/USD *will only be updated during defined market hours (weekends and holidays excluded), so we assume the price is only stale if more than three days have passed*.

However, this is not how chainlink works. Even though the market price is only updated during weekdays, the price is still updated every X seconds **on-chain**, regardless if the market price is updated or not.

We can take EUR/USD on Arbitrum for an example: https://data.chain.link/feeds/arbitrum/mainnet/eur-usd. If we hover on "Trigger parameters", we can see it says "*A new answer is written when the offchain data moves more than the deviation threshold or 3600 seconds have passed since the last answer was written onchain*".

Just to be sure, we can read the `getRoundData()` function for its aggregator https://arbiscan.io/address/0xA14d53bC1F1c0F31B4aA3BD109344E5009051a84#readContract. Pass 18446744073709580880 and 18446744073709580881 as `_roundId` and we can see the update timestamp is 1716631204 (GMT, Saturday, May 25, 2024 10:00:04 AM) and 1716634806 (GMT, Saturday, May 25, 2024 11:00:06 AM). Notice the time difference is 1 hour and it is on a weekend.

Now we have proved that the aggregator is updated every hour on Arbitrum for EUR/USD, having a hardcoded 3 days staleness check is simply too long.

### 2. Circuit breaker

Then let's talk about the circuit breaker issue. This is of less impact, but I'd like to bring it up as well.

The EUR/USD aggregator contains a circuit breaker of minAnswer == 0.1, maxAnswer == 100 for EUR/USD on ethereum mainnet. We can check it up by the [aggregator](https://etherscan.io/address/0x02F878A94a1AE1B15705aCD65b5519A46fe3517e#readContract) address in EUR/USD [price feed](https://etherscan.io/address/0xb49f677943BC038e9857d61E7d053CaA2C1734C1#readContract). The minAnswer is 1e7, maxAnswer is 1e10, with 8 decimals.

This means if EUR/USD falls below 0.1 or rises above 100, the price feed would take 0.1 or 100 as the answer, which is unexpected.

The current price is 1.0824, and reaching such limit is unlikely to happen, but it would be nice to have a check for it.

```solidity
    function _getDataInBase18()
        private
        view
        returns (uint80 roundId, uint256 answer)
    {
        uint8 decimals = aggregator.decimals();
        (uint80 _roundId, int256 _answer, , uint256 updatedAt, ) = aggregator
            .latestRoundData();
        require(_answer > 0, "DF: feed is deprecated");
        require(
            // solhint-disable-next-line not-rely-on-time
            block.timestamp - updatedAt <= _HEALTHY_DIFF,
            "DF: feed is unhealthy"
        );
        roundId = _roundId;
        answer = uint256(_answer).convertToBase18(decimals);
    }
```

## Impact

1. Staleness check is too large for EUR/USD pair on arbitrum.
2. There is no handling logic if the prices reaches below minAnswer or above maxAnswer.

Both would cause the incorrect calculation of minimum deposit amount for depositVault.

## Code Snippet

- https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/feeds/DataFeed.sol#L64-L80

## Tool used

Manual review

## Recommendation

1. Do not hardcode 3 days as staleness check. Make it a configurable parameter, and set it to 3 hours for EUR/USD on Arbitrum.
2. Introduce a minAnswer and maxAnswer circuit breaker check.
