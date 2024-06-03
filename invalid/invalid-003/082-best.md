Helpful Crimson Frog

medium

# No check if Arbitrum L2 sequencer is down in Chainlink feeds

## Summary
No check if Arbitrum L2 sequencer is down in Chainlink feeds

## Vulnerability Detail
When user calls `DepositVault::deposit` to deposit funds and the check `if (!isFreeFromMinDeposit[user])` passes, `DepositVault::_validateAmountUsdIn` is executed to ensure that `amountUsdIn` is greater than or equal to `minAmountToDepositInUsd()`
```solidity
function deposit(address tokenIn, uint256 amountUsdIn)
        external
        onlyGreenlisted(msg.sender)
        whenNotPaused
    {
        address user = msg.sender;

        _requireTokenExists(tokenIn);

        lastRequestId.increment();
        uint256 requestId = lastRequestId.current();

        if (!isFreeFromMinDeposit[user]) {
            _validateAmountUsdIn(user, amountUsdIn);
        }
        require(amountUsdIn > 0, "DV: invalid amount");

        totalDeposited[user] += amountUsdIn;
        _tokenTransferFromUser(tokenIn, amountUsdIn);

        emit Deposit(requestId, user, tokenIn, amountUsdIn);
    }
```
```solidity
function _validateAmountUsdIn(address user, uint256 amountUsdIn)
        internal
        view
    {
        if (totalDeposited[user] != 0) return;
        require(
            amountUsdIn >= minAmountToDepositInUsd(), 
            "DV: usd amount < min"
        );
    }
```
Therefore if user deposit funds for first time, `_validateAmountUsdIn` calls `DataFeed::getDataInBase18()` to get data for eurUsdPrice from Chainlink oracles to check amountUsdIn's sufficiency
```solidity
function minAmountToDepositInUsd() public view returns (uint256) {
        return
            (minAmountToDepositInEuro * eurUsdDataFeed.getDataInBase18()) /
            10**18;
    }
``` 
```solidity
function getDataInBase18() external view returns (uint256 answer) {
        (, answer) = _getDataInBase18();
    }
```
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
From the contest README we can see that the contracts are expected do be deployed at Arbutrum. Using Chainlink in L2 chains such as Arbitrum requires to check if the sequencer is down to avoid prices from looking like they are fresh although they are not. Due to sequencer check missing, the bug could be leveraged by malicious actors to take advantage of the sequencer downtime.

## Impact
loss of funds due to `DepositVault::_validateAmountUsdIn` could be easily passed for first time deposit at cheaper price

## Code Snippet
https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/feeds/DataFeed.sol#L64C5-L81C2

## Tool used

Manual Review

## Recommendation
It is recommended to follow the code example of Chainlink: https://docs.chain.link/data-feeds/l2-sequencer-feeds#example-code