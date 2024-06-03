Brave Sand Robin

medium

# Medium2- `_validateAmountUsdIn()` has inconsistent decimals in require statemet

### by [CarlosAlegreUr](https://github.com/CarlosAlegreUr)

## Summary

Due to decimal inconsistencies, the `minAmountToDepositInUsd()` function will likely always return a value that is higher than the `amountUsdIn` parameter. This will cause the check to always pass, even in scenarios where it should not.

## Vulnerability Detail

The `require` statement on `_validateAmountUsdIn()` called by the `deposit()` function at `DepositVault.sol` compares 2 values, one adjusted for decimals and one not adjusted for decimals. The comparison goes like:

```solidity
  require(
            amountUsdIn >= minAmountToDepositInUsd(), 
            "DV: usd amount < min"
        );
```

`amountUsdIn` as per the **natSpec**, is in 10^18 decimals, but `minAmountToDepositInUsd()` returns a value without decimals. This will cause the check to, practiaclly, always pass, as the value of `amountUsdIn` is a number multplied by 10^18.

_Example:_ 

The min limit can be in `1,000,000$` and `minAmountToDepositInUsd()` will return `1*10^6==1,000,000` but the user will deposit with decimals lets say 3$ => `3$=>3*10^18`, which is higher than the min limit. And the check would be `3*10^18 >= 1*10^6` and pass, when clearly 3$ should not be deemed as >= than a million.

## Impact

The `amountUsdIn >= minAmountToDepositInUsd()` check on `_validateAmountUsdIn()` will always pass, thus undermining the codes functionality of adding a minimum deposit amount check for some people.

## Code Snippet

[Here](https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/DepositVault.sol#L161) is the check with the decmials inconsistency.

[Here](https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/DepositVault.sol#L139) you an see how `minAmountToDepositInUsd()`, returns an adjusted 10^18 value.

You can also see in the testbase that the `minAmountToDepositInEuro` amount has no deimals [here](https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/test/DepositVault.test.ts#L291). The value **100_000** is passed as the expected value, which is a value without decimals. See [here](https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/test/common/deposit-vault.helpers.ts#L36) that the **100_000** arg passed it's just [converted to a string](https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/test/common/deposit-vault.helpers.ts#L32) and then fed into the tx. Also the `expect` statement to pass the test compares the return value of `minAmountToDepositInUsd()` with one without decimals [here](https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/test/DepositVault.test.ts#L292).

Yet according to the docs [here](https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/DepositVault.sol#L89), the amount you should pass to `deposit()` is in 10^18 decimals. Actually in other parts of the `deposit()` it is also treated as a 10^18 decimal value. Because it is passed to the `_tokenTransferFromUser()` function directly [here](https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/DepositVault.sol#L109) and this function later treats it with a `convertFromBase18()` function, [here](https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/abstract/ManageableVault.sol#L155).

## Tool used

Manual Review

## Recommendation

Either adjust the `minAmountToDepositInUsd()` function to return a value with decimals or adjust the `amountUsdIn` parameter to be without decimals. This will ensure that the check is done correctly and the intended functionality is achieved.

I strongly recommend making the `minAmountToDepositInUsd()` function return a value with decimals, as `amountUsdIn` is a function input and making the inputs be already in decimals is nowadays the common way of sending inputs accross the industry.
