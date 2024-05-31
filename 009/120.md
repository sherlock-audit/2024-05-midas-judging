Lively Tiger Dragon

medium

# `getPaymentTokens()` function has no access control which contradicts with code comments


## Summary

`getPaymentTokens()` function has no access control yet the natspec comments says it can be only called from permissioned actor.

## Vulnerability Detail

`getPaymentTokens()` function has no access control yet the natspec comments says it can be only called from permissioned actor.

```solidity
    /**
     * @notice returns array of stablecoins supported by the vault
     * can be called only from permissioned actor.
     * @return paymentTokens array of payment tokens
     */
    function getPaymentTokens() external view returns (address[] memory) {
        return _paymentTokens.values();
    }
```

## Impact

Code implementation differs with code comment.

## Code Snippet

- https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/abstract/ManageableVault.sol#L120-L127

## Tool used

Manual review

## Recommendation

Add access control.
