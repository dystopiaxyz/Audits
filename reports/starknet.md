

# Missing Pre-Transfer Sender Position Validation and Post-Transfer Recipient Validation

**Severity:** High

---

### Finding Description and Impact

#### Root Cause

When calling the `_execute_transfer` from `transfer` function we have two critical issues:

* **Pre-Validation Missing for Sender:**
    The sender’s position health is checked *after* their collateral is reduced. If the sender’s position was already unhealthy, the transfer could push it into a critically undercollateralized state.

* **Recipient Validation Missing:**
    The recipient’s position is not validated after receiving collateral. This could allow transfers to create invalid recipient positions (e.g., exceeding risk limits, undercollateralization).

#### Impact

* **Undercollateralization Attacks (Critical):**
    Even if an operator is calling the `_transfer` function, improper validation could drain collateral from a nearly unhealthy position, intentionally triggering undercollateralization post-transfer. This creates protocol-wide bad debt.

* **Toxic Recipient Positions (High):**
    Recipient positions might violate health checks (e.g., collateral exceeding tiered risk limits), destabilizing the protocol’s risk model.

* **Operator Trust Assumption (Medium):**
    Even if the operator is trusted, the lack of validation violates the "trust but verify" principle, exposing the protocol to errors or insider attacks.

---

### Recommended Mitigation Steps

1.  **Add Pre-Transfer Sender Health Check**

    Validate the sender’s position health *before* applying the collateral reduction:

    ```cairo
    // Inside _execute_transfer, BEFORE apply_diff:
    let pre_transfer_sender_position = self.positions.get_position_snapshot(position_id);
    self._validate_healthy_or_healthier_position(
        position_id,
        pre_transfer_sender_position,
        position_diff: position_diff_sender, // Simulate effect of transfer
    );
    ```

2.  **Add Post-Transfer Recipient Health Check**

    Validate the recipient’s position health *after* applying the collateral increase:

    ```cairo
    // Inside _execute_transfer, AFTER apply_diff to recipient:
    let post_transfer_recipient_position = self.positions.get_position_snapshot(recipient);
    self._validate_healthy_or_healthier_position(
        recipient,
        post_transfer_recipient_position,
        position_diff: None, // Already applied
    );
    ```

---

### Links to affected code

* [`core.cairo#L419`](https://github.com/code-423n4/2025-03-starknet/blob/512889bd5956243c00fc3291a69c3479008a1c8a/workspace/apps/perpetuals/contracts/src/core/core.cairo#L419)
* [`core.cairo#L959-L988`](https://github.com/code-423n4/2025-03-starknet/blob/512889bd5956243c00fc3291a69c3479008a1c8a/workspace/apps/perpetuals/contracts/src/core/core.cairo#L959-L988)



<br>
<br>
<br>




# Incomplete Funding Tick Validation Leading to Stale Funding Rates

## Severity
Medium

---

## Finding Description and Impact

**Root Cause:**
The function validates that `funding_ticks.len()` equals the number of active synthetic assets (`self.get_num_of_active_synthetic_assets()`). However, the protocol documentation specifies that funding updates must include all active and non-pending assets. If the system has synthetic assets in a state like `INACTIVE` (but not `PENDING`), these assets will not receive funding updates, causing their funding indices to become stale.

**Impact:**

* **Financial Inconsistencies:** Stale funding rates lead to incorrect interest calculations for positions tied to excluded assets. For example:
    * Traders might pay/receive incorrect funding fees.
    * Protocol revenue from funding could be misreported.
* **Targeted Manipulation:** An attacker could intentionally exclude certain assets from `funding_ticks` to "freeze" their funding rates, creating arbitrage opportunities (e.g., holding positions that should accrue fees but don’t).
* **Protocol Invariant Violation:** The core invariant "all non-pending assets must have up-to-date funding indices" is broken, undermining trust in the protocol’s financial logic.

---

## Recommended Mitigation Steps

1.  **Update Validation Logic:**
    Replace the active asset count with a count of all non-pending assets:
    ```cairo
    let non_pending_assets_count = self.get_num_of_non_pending_synthetic_assets();
    assert(
        funding_ticks.len() == non_pending_assets_count,
        INVALID_FUNDING_TICK_LEN
    );
    ```
    Implement `get_num_of_non_pending_synthetic_assets()` to include assets where `status != AssetStatus::PENDING`.

2.  **Enforce Status Checks in Loop:**
    Modify the loop to explicitly validate asset status:
    ```cairo
    assert(
        self._get_synthetic_config(:synthetic_id).status != AssetStatus::PENDING,
        SYNTHETIC_PENDING
    );
    ```
    This ensures only non-pending assets are processed, aligning with documentation.

3.  **Add Asset Existence Check:**
    Ensure all non-pending assets are explicitly included in `funding_ticks`:
    ```cairo
    let expected_asset_ids = self.get_non_pending_synthetic_asset_ids();
    let mut i: usize = 0;
    for funding_tick in funding_ticks {
        assert(*funding_tick.asset_id == expected_asset_ids[i], "MISSING_ASSET");
        i += 1;
    }
    ```

4.  **Documentation Alignment:**
    Clarify in code comments and specs that "non-pending" includes all assets except those explicitly in `PENDING` status.

---

## Example Scenario

* **Asset States:**
    * Asset A: `ACTIVE`
    * Asset B: `INACTIVE` (non-pending)
    * Asset C: `PENDING`
* **Attack:** Submit `funding_ticks` with only Asset A.
* **Result:**
    * Validation passes (active count = 1).
    * Asset B’s funding index becomes stale, violating protocol rules.
    * With the fix, Asset B would be included in `non_pending_assets_count` (total = 2), forcing the attacker to provide valid ticks for both A and B.

---

## Links to affected code

* [spec.md?plain=1#L1247-L1260](https://github.com/starkware-libs/starknet-perpetual/blob/9e48514c6151a9b65ee23b4a6f9bced8c6f2b793/docs/spec.md?plain=1#L1247-L1260)
* [assets.cairo#L297-L300](https://github.com/code-423n4/2025-03-starknet/blob/512889bd5956243c00fc3291a69c3479008a1c8a/workspace/apps/perpetuals/contracts/src/core/components/assets/assets.cairo#L297-L300)