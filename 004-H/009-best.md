Sweet White Ferret

high

# Malicious users can bypass the blacklist.

## Summary
The protocol sets the blacklist through roles, and users can bypass the blacklist through the [renounceRole function](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/f6febd79e2a3a17e26969dd0d450c6ebd64bf459/contracts/access/AccessControlUpgradeable.sol#L186-L190).

## Vulnerability Detail
[mTBILL does not allow blacklisted users to transfer funds.](https://github.com/sherlock-audit/2024-05-midas/blob/a4a3cc23bb891913ce44665a4cdea9f5c1190f6c/midas-contracts/contracts/mTBILL.sol#L90-L102)
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

But it is implemented in the form of giving [BLACKLISTED_ROLE.](https://github.com/sherlock-audit/2024-05-midas/blob/a4a3cc23bb891913ce44665a4cdea9f5c1190f6c/midas-contracts/contracts/access/Blacklistable.sol#L38-L42)
```solidity
    function _onlyNotBlacklisted(address account)
        private
        view
        onlyNotRole(BLACKLISTED_ROLE, account)
    {}
```

The AccessControlUpgradeable contract has a [renounceRole function](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/f6febd79e2a3a17e26969dd0d450c6ebd64bf459/contracts/access/AccessControlUpgradeable.sol#L186-L190), through which users can give up their BLACKLISTED_ROLE, thereby bypassing the blacklist.
```solidity
    function renounceRole(bytes32 role, address account) public virtual override {
        require(account == _msgSender(), "AccessControl: can only renounce roles for self");

        _revokeRole(role, account);
    }
```

## Impact
Malicious users can bypass the blacklist.

## Code Snippet
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

## Tool used

Manual Review

## Recommendation
It is recommended not to use roles to implement blacklists.