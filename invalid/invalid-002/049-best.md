Acrobatic Eggplant Shell

medium

# Risk of Incorrect Asset Pricing by Datafeed in Case of Underlying Aggregator Reaching minAnswer.

## Summary
Chainlink aggregators have a built-in circuit breaker to prevent the price of an asset from deviating outside a predefined price range. This circuit breaker may cause the oracle to persistently return the `minPrice` instead of the actual asset price in the event of a significant price drop, as witnessed during the [LUNA](https://rekt.news/venus-blizz-rekt/) crash.
## Vulnerability Detail
`DataFeed.sol` uses AggregatorV3Interface as underlying aggregator for pulling data feed of [EUR/USD](https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/DepositVault.sol#L45).

```solidity
AggregatorV3Interface {
  function decimals() external view returns (uint8);

  function description() external view returns (string memory);

  function version() external view returns (uint256);

  function getRoundData(uint80 _roundId)
    external
    view
    returns (
      uint80 roundId,
      int256 answer,
      uint256 startedAt,
      uint256 updatedAt,
      uint80 answeredInRound
    );

  function latestRoundData()
    external
    view
    returns (
      uint80 roundId,
      int256 answer,
      uint256 startedAt,
      uint256 updatedAt,
      uint80 answeredInRound
    );
}
```
latestRoundData extracts the linked aggregator and requests round data from it. If an asset's price falls below the minPrice, the protocol continues to value the token at the minPrice rather than its real value.This discrepancy could have the protocol end up minting drastically larger amount of mTBILLs.
>[!NOTE]
>This happens due to Datafeed only checking for [negative amounts](https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/feeds/DataFeed.sol#L72) and not for min/maxPrice.

>[!TIP]
> Similar finding: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/18
## Impact
In the event of an asset crash (like LUNA), the protocol can be manipulated to handle calls at an inflated price.


## Code Snippet
https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/feeds/DataFeed.sol#L72
https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/DepositVault.sol#L106
## Tool used

Manual Review

## Recommendation
It can be easily mitigated by introducing a check for minPrice and maxPrice