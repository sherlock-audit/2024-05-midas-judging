Lively Tiger Dragon

medium

# Rounding direction for the amount of stablecoin user deposit is incorrect


## Summary

The rounding direction for the amount of stablecoin user deposit is incorrect. This would cause the deposit amount to be slightly larger than what the user actually deposited, which is a loss for the protocol.

## Vulnerability Detail

During the deposit process, the user specifies the `amountUsdIn` (in 18 decimals) that he would like to deposit. This amount of mTBILL is minted to the user in the future.

User should transfer the equivalent amount of stablecoin to the receiver. The issue here is when calculating the amount of stablecoin to be transferred, the rounding direction should be up instead of down.

Take USDC as an example. If a user passes `amountUsdIn` as `1e12-1`, the actual amount of USDC that would be sent is `(1e12-1) / 1e12` which would be 0, which means users can get `1e12-1` mTBILL tokens for free.

Notice that though this is a very small amount of money (1e-6 USD), if the number of deposits is large enough, this would become large. Also, from the protocol's perspective, this dust amount of money should be charged to the users, or else it may accumulate in the protocol and reach a non-dust value.

https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/DepositVault.sol#L91C1-L112C6
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
>       _tokenTransferFromUser(tokenIn, amountUsdIn);

        emit Deposit(requestId, user, tokenIn, amountUsdIn);
    }
```

https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/abstract/ManageableVault.sol#L151C1-L157C6
```solidity
    function _tokenTransferFromUser(address token, uint256 amount) internal {
        IERC20(token).safeTransferFrom(
            msg.sender,
            tokensReceiver,
>           amount.convertFromBase18(_tokenDecimals(token))
        );
    }
```


https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/libraries/DecimalsCorrectionLibrary.sol#L18C1-L54C6
```solidity
    function convert(
        uint256 originalAmount,
        uint256 originalDecimals,
        uint256 decidedDecimals
    ) internal pure returns (uint256) {
        if (originalAmount == 0) return 0;
        if (originalDecimals == decidedDecimals) return originalAmount;

        uint256 adjustedAmount;

        if (originalDecimals > decidedDecimals) {
>           adjustedAmount =
>               originalAmount /
>               (10**(originalDecimals - decidedDecimals));
        } else {
            adjustedAmount =
                originalAmount *
                (10**(decidedDecimals - originalDecimals));
        }

        return adjustedAmount;
    }

    /**
     * @dev converts `originalAmount` with decimals 18 into
     * amount with `decidedDecimals`
     * @param originalAmount amount to convert
     * @param decidedDecimals decimals for the output amount
     * @return amount converted amount with `decidedDecimals`
     */
    function convertFromBase18(uint256 originalAmount, uint256 decidedDecimals)
        internal
        pure
        returns (uint256)
    {
        return convert(originalAmount, 18, decidedDecimals);
    }
```

## Impact

The protocol would lose dust amount of mTBILL for each deposit, which may accumulate to be a non-dust value.

## Code Snippet

- https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/DepositVault.sol#L91C1-L112C6
- https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/abstract/ManageableVault.sol#L151C1-L157C6
- https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/libraries/DecimalsCorrectionLibrary.sol#L18C1-L54C6

## Tool used

Manual review

## Recommendation

Round up the user transfer for stablecoin instead of rounding down.