# Core Contracts - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Vote Power Snapshot Issue (Time-of-Check to Time-of-Use) in Governance.sol function castVote()](#H-01)
    - ### [H-02. Incorrect Token Burn Scaling in function burn() in Rtoken.sol](#H-02)
- ## Medium Risk Findings
    - ### [M-01. Incorrect Proposal Status Handling Due to Timelock Cancellation](#M-01)
    - ### [M-02. Proposal Replay Attack in Governance.sol propose function](#M-02)
    - ### [M-03. Lack of Transparency in Emergency Revocation in emergencyRevoke() in RAACReleaseOrchestrator.sol](#M-03)
- ## Low Risk Findings
    - ### [L-01. Indefinite Extension of Delegation in function delegateBoos() in BoostController.sol](#L-01)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: Regnum Aurum Acquisition Corp

### Dates: Feb 3rd, 2025 - Feb 24th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-02-raac)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 2
- Medium: 3
- Low: 1


# High Risk Findings

## <a id='H-01'></a>H-01. Vote Power Snapshot Issue (Time-of-Check to Time-of-Use) in Governance.sol function castVote()            



## Summary

The function `castVote` suffers from a **Time-of-Check to Time-of-Use (TOCTOU)** issue related to the retrieval of voting power. The function calls `_veToken.getVotingPower(msg.sender)` at the time of voting, but this value may change before the vote is finalized, leading to **inconsistent or unfair voting results**.

## Vulnerability Details

```Solidity
function castVote(uint256 proposalId, bool support) external override returns (uint256) {
        ProposalCore storage proposal = _proposals[proposalId];
        if (proposal.startTime == 0) revert ProposalDoesNotExist(proposalId);
        if (block.timestamp < proposal.startTime) {
            revert VotingNotStarted(proposalId, proposal.startTime, block.timestamp);
        }
        if (block.timestamp > proposal.endTime) {
            revert VotingEnded(proposalId, proposal.endTime, block.timestamp);
        }

        ProposalVote storage proposalVote = _proposalVotes[proposalId];
        if (proposalVote.hasVoted[msg.sender]) { 
            revert AlreadyVoted(proposalId, msg.sender, block.timestamp);
        }

    >>  uint256 weight = _veToken.getVotingPower(msg.sender); 
        if (weight == 0) {
            revert NoVotingPower(msg.sender, block.number);
        }

        proposalVote.hasVoted[msg.sender] = true;

        if (support) { 
            proposalVote.forVotes += weight;
        } else {
            proposalVote.againstVotes += weight;
        }

        emit VoteCast(msg.sender, proposalId, support, weight, "");
        return weight;
    }

```

The contract fetches the voter's voting power (`weight = _veToken.getVotingPower(msg.sender)`) at the time of vote submission.

* However, `_veToken.getVotingPower(msg.sender)` is a dynamic value that may fluctuate due to token transfers, staking, delegation, or any governance mechanism affecting voting power.
* This introduces a **Time-of-Check to Time-of-Use (TOCTOU) problem** where:

  * A voter may temporarily **inflate their voting power**, cast a vote, and then transfer or unstake tokens.
  * A malicious entity may **borrow tokens (flash loans)**, cast a vote with high power, and return the borrowed tokens before the proposal ends.
  * Voting power may be **reduced unexpectedly** due to another protocol mechanism, affecting the vote's accuracy.

## Impact

Double Voting: This allows double voting, where one entity can vote multiple times using different accounts.

Vote Manipulation: A user can transfer tokens to another address and vote again, effectively amplifying their voting power.

**Unfair Governance Decisions:** The final vote may not reflect the true state of governance token holders at the time of the vote.

## Tools Used

Manual Review

## Recommendations

**Use Voting Power Snapshots:**

* Instead of checking `_veToken.getVotingPower(msg.sender)` at the time of voting, take a **snapshot of voting power** at the **start of the proposal** or **beginning of the voting period**.

```Solidity
// Old: Fetching current balance dynamically (vulnerable to transfers)
-- uint256 weight = _veToken.getVotingPower(msg.sender);
// New: Fetching voting power at the proposal start time (snapshot mechanism)
++ uint256 weight = _veToken.getVotingPowerAt(msg.sender, proposal.startTime);
```



Add code givenb below to veRAACToken.sol : 

```Solidity

    struct Checkpoint {
        uint256 fromTimestamp;
        uint256 votingPower;
    }

    mapping(address => Checkpoint[]) public checkpoints;

    event VotingPowerUpdated(address indexed user, uint256 newPower);

    function _updateVotingPower(address user, uint256 newPower) internal {
        checkpoints[user].push(Checkpoint(block.timestamp, newPower));
        emit VotingPowerUpdated(user, newPower);
    }

    function getVotingPowerAt(address user, uint256 timestamp) external view returns (uint256) {
        Checkpoint[] storage userCheckpoints = checkpoints[user];
        uint256 length = userCheckpoints.length;

        if (length == 0 || timestamp < userCheckpoints[0].fromTimestamp) {
            return 0;
        }

        for (uint256 i = length; i > 0; i--) {
            if (userCheckpoints[i - 1].fromTimestamp <= timestamp) {
                return userCheckpoints[i - 1].votingPower;
            }
        }

        return 0;
    }

```

This ensures that a voter's power is **fixed** when the proposal starts, preventing manipulation.


## <a id='H-02'></a>H-02. Incorrect Token Burn Scaling in function burn() in Rtoken.sol            



## Summary

The variable `amountScaled` is calculated using `amount.rayMul(index)`, but it is never actually used in the function. This leads to a potential issue where **scaled token balances are not properly reduced** upon burning, which could cause inconsistencies in the accounting system.

## Vulnerability Details

```Solidity
function burn(
        address from,
        address receiverOfUnderlying,
        uint256 amount,
        uint256 index
    ) external override onlyReservePool returns (uint256, uint256, uint256) {
        if (amount == 0) {
            return (0, totalSupply(), 0);
        }

        uint256 userBalance = balanceOf(from);  

        _userState[from].index = index.toUint128();

        if(amount > userBalance){
            amount = userBalance;
        }

   >>   uint256 amountScaled = amount.rayMul(index); // Unused variable

        _userState[from].index = index.toUint128();

   >>   _burn(from, amount.toUint128());  // not used amountScaled
        if (receiverOfUnderlying != address(this)) {
            IERC20(_assetAddress).safeTransfer(receiverOfUnderlying, amount);
        }

        emit Burn(from, receiverOfUnderlying, amount, index);

        return (amount, totalSupply(), amount);
    }
```

**Unused Calculation**

* The function computes `amountScaled = amount.rayMul(index);`, which **converts the amount from underlying tokens to scaled tokens**.
* However, `amountScaled` is **never used** in the actual burn operation. Instead, `_burn(from, amount.toUint128());` burns the **raw** **`amount`**.

**Potential Accounting Issues**

* If the protocol **tracks balances in scaled form**, the incorrect burn method could lead to **inconsistencies in the accounting system**.
* This could create **unexpected balance discrepancies**, especially in **interest-bearing token models** where scaling is critical.

## Impact

* **Incorrect Token Burning**: The function may **not reduce the correct amount of scaled tokens**, leading to **inaccurate supply tracking**.
* **Potential Accounting Inconsistencies**: If scaled tokens are meant to be burned, but raw tokens are burned instead, **it could desynchronize token balances from expected values**.
* **Hidden Logical Error**: Even if this doesn't immediately break functionality, it may cause **long-term imbalances** in the reserve system.

## Tools Used

Manual Review

## Recommendations

Use `amountScaled` in the `_burn()` Function

```Solidity
function burn(
        address from,
        address receiverOfUnderlying,
        uint256 amount,
        uint256 index
    ) external override onlyReservePool returns (uint256, uint256, uint256) {
        if (amount == 0) {
            return (0, totalSupply(), 0);
        }

        uint256 userBalance = balanceOf(from);  

        _userState[from].index = index.toUint128();

        if(amount > userBalance){
            amount = userBalance;
        }

        uint256 amountScaled = amount.rayMul(index); // Unused variable

        _userState[from].index = index.toUint128();

        _burn(from, amount.toUint128()); 
        if (receiverOfUnderlying != address(this)) {
            IERC20(_assetAddress).safeTransfer(receiverOfUnderlying, amount);
        }

        emit Burn(from, receiverOfUnderlying, amount, index);

        return (amount, totalSupply(), amount);
    }
```


    
# Medium Risk Findings

## <a id='M-01'></a>M-01. Incorrect Proposal Status Handling Due to Timelock Cancellation            



## Summary

The function `state()` determines the current state of a governance proposal. However, it **does not check if a proposal has been canceled in the timelock**, leading to a scenario where a canceled proposal may be incorrectly returned as `Succeeded`.

This can cause **governance manipulation**, where proposals that should have failed can appear valid, creating inconsistencies in the governance process.

## Vulnerability Details

This is the state function where we check 

if (\_timelock.isOperationPending(id)) {
return ProposalState.Queued;
}

```Solidity
function state(uint256 proposalId) public view override returns (ProposalState) {
        ProposalCore storage proposal = _proposals[proposalId];
        if (proposal.startTime == 0) revert ProposalDoesNotExist(proposalId);

        if (proposal.canceled) return ProposalState.Canceled;
        if (proposal.executed) return ProposalState.Executed;
        if (block.timestamp < proposal.startTime) return ProposalState.Pending;
        if (block.timestamp < proposal.endTime) return ProposalState.Active;

        // After voting period ends, check quorum and votes
        ProposalVote storage proposalVote = _proposalVotes[proposalId];
        uint256 currentQuorum = proposalVote.forVotes + proposalVote.againstVotes;
        uint256 requiredQuorum = quorum();

        // Check if quorum is met and votes are in favor
        if (currentQuorum < requiredQuorum || proposalVote.forVotes <= proposalVote.againstVotes) {
            return ProposalState.Defeated;
        }

        bytes32 id = _timelock.hashOperationBatch(
            proposal.targets,
            proposal.values,
            proposal.calldatas,
            bytes32(0),
            proposal.descriptionHash
        );

        // If operation is pending in timelock, it's Queued
 >>     if (_timelock.isOperationPending(id)) { //@audit-issue : Cancelled proposals in timelock will be returned as succeeded.
            return ProposalState.Queued;
        }

        // If not pending and voting passed, it's Succeeded
        return ProposalState.Succeeded;
    }
```



* However, this **does not account for cases where the timelock operation was canceled**.
* If `_timelock.isOperationPending(id)` returns `false` (because the proposal was canceled), the function **falls through to return** **`ProposalState.Succeeded`**, even though the proposal should not succeed.
* This creates an inconsistency between the governance contract and the timelock contract.



## Impact

**Governance Manipulation:** A canceled proposal may still appear as `Succeeded`, allowing an attacker or malicious actor to **rerun** a proposal that should have failed.

**State Inconsistency:** The governance contract and the timelock contract will **store different statuses** for the same proposal, which can cause **unexpected behaviors** in governance execution.

**Security Risk:** If automated execution relies on a proposal being `Succeeded`, a canceled proposal might **still get executed** in some cases.

## Tools Used

Manual Review

## Recommendations

### 1. Explicitly Check if the Proposal was Canceled in the Timelock

Modify the function to check `_timelock.isOperationCanceled(id)` before marking a proposal as `Succeeded`

### 2. Implement a Mapping to Track Proposal Status

Instead of only relying on `_timelock.isOperationPending()`, maintain a **mapping to track proposal cancellations**



```Solidity
contract TimeLockController{

  mapping(uint256 => bool) public canceledInTimelock;

    function cancelProposalInTimelock(uint256 proposalId) external onlyTimelock {
        canceledInTimelock[proposalId] = true;
    }
}
```

```Solidity
function state(uint256 proposalId) public view override returns (ProposalState) {
        ProposalCore storage proposal = _proposals[proposalId];
        if (proposal.startTime == 0) revert ProposalDoesNotExist(proposalId);

        if (proposal.canceled) return ProposalState.Canceled;
        if (proposal.executed) return ProposalState.Executed;
        if (block.timestamp < proposal.startTime) return ProposalState.Pending;
        if (block.timestamp < proposal.endTime) return ProposalState.Active;

        // After voting period ends, check quorum and votes
        ProposalVote storage proposalVote = _proposalVotes[proposalId];
        uint256 currentQuorum = proposalVote.forVotes + proposalVote.againstVotes;
        uint256 requiredQuorum = quorum();

        // Check if quorum is met and votes are in favor
        if (currentQuorum < requiredQuorum || proposalVote.forVotes <= proposalVote.againstVotes) {
            return ProposalState.Defeated;
        }

        bytes32 id = _timelock.hashOperationBatch(
            proposal.targets,
            proposal.values,
            proposal.calldatas,
            bytes32(0),
            proposal.descriptionHash
        );

        // If operation is pending in timelock, it's Queued
        if (_timelock.isOperationPending(id)) { 
            return ProposalState.Queued;
        }

  ++    if (_timelock.isOperationCanceled(id) || || canceledInTimelock[proposalId]) {  // Fix: Prevents canceled proposals from being marked as succeeded
  ++        return ProposalState.Defeated;
  ++    }

        // If not pending and voting passed, it's Succeeded
        return ProposalState.Succeeded;
    }
```




## <a id='M-02'></a>M-02. Proposal Replay Attack in Governance.sol propose function            



## Summary

The proposal replay attack vulnerability arises because the contract does not check for duplicate proposals. This allows an attacker to repeatedly submit the same proposal, which could lead to network spam, governance inefficiencies, and potential denial-of-service (DoS) attacks.

## Vulnerability Details

```Solidity
function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description,
        ProposalType proposalType
    ) external override returns (uint256) {
        uint256 proposerVotes = _veToken.getVotingPower(msg.sender); 

        if (proposerVotes < proposalThreshold) {
            revert InsufficientProposerVotes(msg.sender, proposerVotes, proposalThreshold, "Below threshold");
        }
        
        if (targets.length == 0 || targets.length != values.length || targets.length != calldatas.length) {
            revert InvalidProposalLength(targets.length, values.length, calldatas.length);
        }

  >>    uint256 proposalId = _proposalCount++; // proposal replay attacks, keep on spamming with same proposals
        uint256 startTime = block.timestamp + votingDelay;
        uint256 endTime = startTime + votingPeriod;

        _proposals[proposalId] = ProposalCore({
            id: proposalId,
            proposer: msg.sender,
            proposalType: proposalType,
            startTime: startTime,
            endTime: endTime,
            executed: false,
            canceled: false,
            descriptionHash: keccak256(bytes(description)),
            targets: targets,
            values: values,
            calldatas: calldatas
        });

        // Store the proposal data separately
        _proposalData[proposalId] = ProposalData(targets, values, calldatas, description);

        emit ProposalCreated(proposalId, msg.sender, targets, values, calldatas, description, proposalType, startTime, endTime, proposerVotes);

        return proposalId;
    }
```

The contract does not maintain a record of past proposal hashes to prevent duplicate proposals.

* The `proposalId` is incremented sequentially (`uint256 proposalId = _proposalCount++`), meaning identical proposals will always be accepted with different IDs.
* An attacker can continuously submit the same proposal, congesting the governance system and spamming voters with redundant proposals.
* If the contract has limits on active proposals or voting resources, it could prevent legitimate proposals from being processed.

## Impact

* **Governance Spam:** The system could be flooded with identical proposals, overwhelming voters and making governance less effective.
* **Denial-of-Service (DoS):** Attackers could exploit gas or storage limits to prevent the submission of legitimate proposals.
* **Vote Dilution:** If resources for proposal processing are limited, it may prevent other users from submitting meaningful proposals.

## Tools Used

Manual Review

## Recommendations

**Enforce Proposal Uniqueness:** Store a mapping of `keccak256(abi.encode(targets, values, calldatas, description))` to prevent duplicate proposals.

## <a id='M-03'></a>M-03. Lack of Transparency in Emergency Revocation in emergencyRevoke() in RAACReleaseOrchestrator.sol            



## Summary

The `emergencyRevoke` function has **two key issues**:

1. **Tokens are transferred to the contract (`address(this)`) instead of a designated treasury wallet (`TREASURY_WALLET`).** This could lead to inefficient fund management.
2. **The function does not include a** **`reason`** **parameter**, making it harder to track why an emergency revocation was triggered.

## Vulnerability Details

```Solidity
function emergencyRevoke(address beneficiary) external onlyRole(EMERGENCY_ROLE) { //@audit-issue : add string memory reason, whenPaused to prevent frontrunning
        VestingSchedule storage schedule = vestingSchedules[beneficiary];
        if (!schedule.initialized) revert NoVestingSchedule();
        
        uint256 unreleasedAmount = schedule.totalAmount - schedule.releasedAmount;
        delete vestingSchedules[beneficiary]; 
        
        if (unreleasedAmount > 0) {
            raacToken.transfer(address(this), unreleasedAmount); //@audit-issue : transfer to address treasury = TREASURY_WALLET; instead of address(this)
            emit EmergencyWithdraw(beneficiary, unreleasedAmount);
        }
        
        emit VestingScheduleRevoked(beneficiary); // add reason to event
    }
```

The function currently transfers **unreleased vested tokens** to `address(this)`.

If the contract is compromised because some issues, these tokens may **become inaccessible**.

Instead, the funds should be transferred to a designated treasury wallet (`TREASURY_WALLET`)

Emergency revocations often happen due to **fraud, compliance issues, or admin decisions**.

Without a `reason` parameter, **there is no way to track why a revocation occurred**, leading to **poor transparency and accountability**.

Adding a `reason` (string) to the function and event ensures **better documentation and future audits**.

## Impact

**Locked or Mismanaged Funds**: If tokens are sent to `address(this)`, they may be **permanently locked** unless another function allows retrieval.

**Transparency & Accountability Issues**: Without a reason for revocation, it is **difficult to justify emergency actions** to stakeholders, auditors, or governance bodies.

## Tools Used

Manual Review

## Recommendations

Transfer Unreleased Tokens to Treasury (`TREASURY_WALLET`)

Modify the function signature to include a `string memory reason`:

Modify the event to contain "reason".

```Solidity
-- function emergencyRevoke(address beneficiary) external onlyRole(EMERGENCY_ROLE) { 
++ function emergencyRevoke(address beneficiary, string memory reason) external onlyRole(EMERGENCY_ROLE) whenPaused {
        VestingSchedule storage schedule = vestingSchedules[beneficiary];
        if (!schedule.initialized) revert NoVestingSchedule();
        
        uint256 unreleasedAmount = schedule.totalAmount - schedule.releasedAmount;
        delete vestingSchedules[beneficiary];
        
        if (unreleasedAmount > 0) {
--          raacToken.transfer(address(this), unreleasedAmount);
++          raacToken.transfer(TREASURY_WALLET, unreleasedAmount);
            emit EmergencyWithdraw(beneficiary, unreleasedAmount);
        }
        
--      emit VestingScheduleRevoked(beneficiary);
++      emit VestingScheduleRevoked(beneficiary, reason);

    }
```



# Low Risk Findings

## <a id='L-01'></a>L-01. Indefinite Extension of Delegation in function delegateBoos() in BoostController.sol            



## Summary

The `delegateBoost` function allows users to **extend** their delegation indefinitely by repeatedly calling it without any restrictions. This could be used to **lock boosts forever**, preventing natural expiry and potentially **abusing rewards, governance, or other delegation benefits**.

## Vulnerability Details

```Solidity
function delegateBoost( 
        address to, 
        uint256 amount,
        uint256 duration
    ) external override nonReentrant {
        if (paused()) revert EmergencyPaused();
        if (to == address(0)) revert InvalidPool(); 
        if (amount == 0) revert InvalidBoostAmount();
        if (duration < MIN_DELEGATION_DURATION || duration > MAX_DELEGATION_DURATION) 
            revert InvalidDelegationDuration();
        
        uint256 userBalance = IERC20(address(veToken)).balanceOf(msg.sender);
        if (userBalance < amount) revert InsufficientVeBalance();
        
        UserBoost storage delegation = userBoosts[msg.sender][to]; 
   >>   if (delegation.amount > 0) revert BoostAlreadyDelegated(); //Delegation Can Be Extended Indefinitely
        
        delegation.amount = amount;
        delegation.expiry = block.timestamp + duration;
        delegation.delegatedTo = to;
        delegation.lastUpdateTime = block.timestamp;
        
        emit BoostDelegated(msg.sender, to, amount, duration);
    }
```



### Expected Behavior (Without Exploit)

1. User delegates **100 tokens** → Expires in **30 days**.
2. After **30 days**, the boost **naturally expires**.
3. User must **wait** before re-delegating or meet a reset condition.

### Exploit Scenario (Indefinite Extension)

1. User delegates **100 tokens** (expires in **30 days**).
2. **Before expiration** (e.g., on **Day 29**), user calls `delegateBoost()` again with the same parameters.
3. The **expiry resets** for another **30 days**.
4. The user **repeats this indefinitely**, **never allowing the boost to expire**.



### 1. User Delegates Boost Initially

* A user (`msg.sender`) calls `delegateBoost()` to delegate a boost (`amount`) to another address (`to`).
* The function stores this delegation in `userBoosts[msg.sender][to]`, setting:

  * `amount` = delegated boost value
  * `expiry` = `block.timestamp + duration` (boost expiration time)

### 2. Delegation is Meant to Expire After `duration`

* The expected behavior is that once `block.timestamp` reaches `expiry`, the boost should expire naturally.
* After expiration, the user should need to **wait** or meet specific conditions before re-delegating.

### 3. Exploit: User Can Repeatedly Extend Delegation Indefinitely

* The contract **does not** prevent a user from calling `delegateBoost()` **again** just before the previous delegation expires.
* Since the function **overwrites** the existing delegation entry (`userBoosts[msg.sender][to]`), it **resets** the `expiry` time.
* The user can **continuously call** **`delegateBoost()`** **before** **`expiry`**, ensuring the delegation **never expires**.

### 4. Root Cause

* **No check ensures that delegation must expire before re-delegation is allowed.**
* **No cooldown period between consecutive delegations.**
* **No maximum lifetime cap on delegation extensions.**



## Impact

* **Perpetual Boosting:** The user **never loses the boost effect**, potentially exploiting governance, rewards, or voting systems.
* **Unfair Advantage:** If the boost provides **yield farming or governance power**, the user **retains benefits indefinitely**, bypassing natural delegation limits.
* **Storage Bloat & Inefficiency:** Constant overwriting of delegation **wastes gas** and **clogs contract execution** unnecessarily.

## Tools Used

Manual Review

## Recommendations

**Prevent Delegation Extension Before Expiry** 

* `if (delegation.amount > 0 && block.timestamp < delegation.expiry) revert BoostAlreadyDelegated();`

**Introduce a Cooldown Period After Expiry** Indefinite Extension of Delegation

* `if (block.timestamp < delegation.expiry + COOLDOWN_PERIOD) revert CooldownNotElapsed();`

```Solidity
function delegateBoost( // @audit - check if it's reasonable to delegate boost to multiple addresses for same caller
        address to, 
        uint256 amount,
        uint256 duration
    ) external override nonReentrant {
        if (paused()) revert EmergencyPaused();
        if (to == address(0)) revert InvalidPool(); 
        if (amount == 0) revert InvalidBoostAmount();
        if (duration < MIN_DELEGATION_DURATION || duration > MAX_DELEGATION_DURATION) 
            revert InvalidDelegationDuration();
        
        uint256 userBalance = IERC20(address(veToken)).balanceOf(msg.sender);
        if (userBalance < amount) revert InsufficientVeBalance();
        
        UserBoost storage delegation = userBoosts[msg.sender][to]; 
    --  if (delegation.amount > 0 & ) revert BoostAlreadyDelegated(); 
        // Prevent Delegation Extension Before Expiry
    ++  if (delegation.amount > 0 && block.timestamp < delegation.expiry) {
    ++      revert BoostAlreadyDelegated();
    ++  }

        // Introduce a Cooldown Period After Expiry
    ++  if (block.timestamp < delegation.expiry + COOLDOWN_PERIOD) 
    ++      revert CooldownNotElapsed();
           
        
        delegation.amount = amount;
        delegation.expiry = block.timestamp + duration;
        delegation.delegatedTo = to;
        delegation.lastUpdateTime = block.timestamp;
        
        emit BoostDelegated(msg.sender, to, amount, duration);
    }
```








