Lively Tiger Dragon

medium

# `M_TBILL_BURN_OPERATOR_ROLE` cannot burn `mTBILL` tokens from users who are blacklisted.


## Summary

`M_TBILL_BURN_OPERATOR_ROLE` cannot burn `mTBILL` tokens from users who are blacklisted.

## Vulnerability Detail

The `burn()` function of `mTBILL` is called by the `M_TBILL_BURN_OPERATOR_ROLE` role, it should be able to burn tokens from any user. Quote the protocol team: *burning is our way to seize assets if necessary.*

However, since `_beforeTokenTransfer` is also called during the internal `_burn()` function, users that are blacklisted would not be able to be burned.

https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/mTBILL.sol#L90-L102
```solidity
    function burn(address from, uint256 amount)
        external
        onlyRole(M_TBILL_BURN_OPERATOR_ROLE, msg.sender)
    {
        _burn(from, amount);
    }

    ...

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

https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/v4.9.0/contracts/token/ERC20/ERC20Upgradeable.sol#L282-L298
```solidity
    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");

>       _beforeTokenTransfer(account, address(0), amount);

        uint256 accountBalance = _balances[account];
        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");
        unchecked {
            _balances[account] = accountBalance - amount;
            // Overflow not possible: amount <= accountBalance <= totalSupply.
            _totalSupply -= amount;
        }

        emit Transfer(account, address(0), amount);

        _afterTokenTransfer(account, address(0), amount);
    }
```

## Impact

`M_TBILL_BURN_OPERATOR_ROLE` cannot burn `mTBILL` tokens from users who are blacklisted.

## Code Snippet

- https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/mTBILL.sol#L90-L102
- https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/v4.9.0/contracts/token/ERC20/ERC20Upgradeable.sol#L282-L298

## Tool used

Manual review

## Recommendation

Add a manual check if `to` address is 0, skip the blacklist check for `from` address.
