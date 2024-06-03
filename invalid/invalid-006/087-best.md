Gentle Paisley Jaguar

medium

# Front-running attack on `initialize` functions

## Summary
Front-running attack on `initialize` functions

## Vulnerability Detail
The declaration of function `initialize(address _ac, address _mTBILL, address _eurUsdDataFeed, uint256 _minAmountToDepositInEuro, address _usdReceiver)` is used in almost all scope contracts. It is required a call to the initialize function after deploying it to initialize admin roles. There is no require checking within the initialize function. There are functions that can be front-run, allowing an attacker to malicously initialize the contracts.
```solidity
function initialize(
        address _ac,
        address _mTBILL,
        address _eurUsdDataFeed,
        uint256 _minAmountToDepositInEuro,
        address _usdReceiver
    ) external initializer {
        require(_eurUsdDataFeed != address(0), "zero address");

        __ManageableVault_init(_ac, _mTBILL, _usdReceiver);
        minAmountToDepositInEuro = _minAmountToDepositInEuro;
        eurUsdDataFeed = IDataFeed(_eurUsdDataFeed);
    }
```

## Impact
Medium; Likelihood is very low, but impact is critical

## Code Snippet
https://github.com/sherlock-audit/2024-05-midas/blob/main/midas-contracts/contracts/DepositVault.sol#L70

## Tool used
Manual Review

## Recommendation
It is recommended to declare a constructor instead of an `initialize` function to set up roles at the time of deployment to mitigate the issue. Otherwise, add a `require` statement to each `initialize` function to verify that the function is called by the contract owner only, and post verification roles should be setup. Otherwise, setting the owner in the contract’s constructor to the `msg.sender` and adding the `onlyOwner` modifier to all initializers would be enough for access control.