Lively Tiger Dragon

medium

# `mTBILL` blacklisted users can successfully deposit in `DepositVault` despite not being able to receive mTBILL at all.


## Summary

The blacklist feature in `mTBILL` token forbids a user to transfer or receive the token. However, the user is still free to deposit in the `DepositVault`, though he is not able to receive `mTBILL`.

## Vulnerability Detail

The deposit workflow is user deposits stablecoin (e.g. USDC) to the `DepositVault`, and the `M_TBILL_MINT_OPERATOR_ROLE` role would mint `mTBILL` tokens to the user.

However, the `deposit()` function in `DepositVault` only checks if the `msg.sender` is greenlisted, but does not check if the user is blacklisted from `mTBILL`.

If a user is blacklisted from `mTBILL`, it would be not possible to mint `mTBILL` to the user, causing loss of funds.

https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/DepositVault.sol#L91-L112

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

https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/mTBILL.sol

```solidity
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    )
        internal
        virtual
        override(ERC20PausableUpgradeable)
        onlyNotBlacklisted(from)
        onlyNotBlacklisted(to)
    {
        ERC20PausableUpgradeable._beforeTokenTransfer(from, to, amount);
    }
```

## Impact

User would lose funds if he is blacklisted from `mTBILL` but still tries to deposit in `DepositVault`.

## Code Snippet

- https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/DepositVault.sol#L91-L112
- https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/mTBILL.sol#L90-L102

## Tool used

Manual review

## Recommendation

Also check if the user is blacklisted from `mTBILL` during the deposit phase.
