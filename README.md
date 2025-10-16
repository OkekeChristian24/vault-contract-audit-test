# Found Critical Vulnerabilities

## ISSUE-1:

Reentrancy attack on the deposit() function -
The deposit function updates its userShares and totalShares states for the user before actually executing the token transferFrom function. The logic flow is liable to re-entrancy attack because an attacker can execute a callback into the vault's withdraw or emergencyWithdraw functions and deposit function again when the deposit function is calling the depositToken's transferFrom function.
This attack will result in the attacker withdrawing funds from the vault contract multiple times
with a single deposit action.

### Attack Scenario:

- An attacker deploys a malicious deposit token for the vault smart contract.
- He implements transferFrom function and inside it, calls vault's withdraw or emergencyWithdraw function
  and also the deposit function.
- When the attacker calls the vault's deposit function with 100 tokens, the vault updates the attacker's
  userShares to 100. When the vault's deposit function tries to execute the malicious token's transferFrom function
  to do the actual token transfer, it runs into its withdraw or emergencyWithdraw function.
- The withdraw or emergencyWithdraw will execute because the condition checks it does for the attacker is
  valid. This will result in the attacker getting free 100 tokens without actually depositing any token.
  After the withdraw or emergencyWithdraw function runs, the deposit function (in the malicious token's transferFrom)
  runs next which starts the whole attack again until the vault balance is empty.

### Recommended Fix:

Use solidity modifier to implement a guard against re-entrancy. This guard will
use a state variable of the vault contract to lock and open the deposit function of the vault.
This way, no mid-way execution of the deposit function will be allowed. We can also use the
Openzeppelin's ReentrancyGuard implementation

```solidity
bool internal locked;
modifier reentrant() {
    require(!locked, "ReentrancyGuard: reentrant call");
    locked = true;
    \_;
    locked = false;
}
```

## ISSUE-2:

The vault smart contract does not check the return value of the deposit token's transfer and transferFrom
functions to see if the transfer is successful or not. If the token returns false due to transfer failure,
the contract continues as if the transfer succeeded. This can lead to inconsistent balance amounts.

### Attack Scenario:

- When a user tries to deposit via the deposit function, his userShares (on the vault contract) are already updated
  but the token's transferFrom fails silently, meaning there is no token transferred from the user to the vault.
- But the user can withdraw since his userShares balance on the vault is already updated.

### Recommended Fix:

Check the return value of the token's transfer and transferFrom functions to know if the transfer is successful
or not. Also we can use the OpenZeppelin's SafeERC20 wrappers (SafeERC20.safeTransferFrom or safeTransfer) which revert on failed transfers or non-standard tokens.

```solidity
bool success = depositToken.transferFrom(msg.sender, address(this), amount);
require(success, "Token transferFrom failed");
```

## ISSUE-3:

If depositToken is a deflectionary token i.e. taxed on transfer or charged fee on transfer,
the calculated share will be incorrect because the actual amount the vault contract receives will be
lower than the amount initially sent.

### Attack Scenario:

- If Attacker uses a token with a 10% transfer tax. They call deposit with amount of 1000. Vault calculates the shares thinking 1000 was transferred.
- But the token only sends 900 to the vault due to the 10% fee.
- The attacker is given shares for 1000 and later withdraws based on vault's userShares balance, taking more than their actual contribution.

### Recommended Fix:

Make sure to get the actual amount the vault received by calculating the vault's token
balances before and after the token transfer. This will help to get the real amount of token transferred to
the vault.

```solidity
function deposit(uint256 amount) external {
    require(amount > 0, "Amount must be positive");

    uint256 vaultBalance = depositToken.balanceOf(address(this));
    depositToken.transferFrom(msg.sender, address(this), amount);

    uint256 amountReceived = depositToken.balanceOf(address(this)) - vaultBalance;
    require(amountReceived > 0, "No tokens received");

    uint256 shares;

    if (totalShares == 0) {
        shares = amountReceived;
    } else {
        require(vaultBalance > 0, "Invalid vault state");
        shares = (amountReceived * totalShares) / vaultBalance;
    }

    userShares[msg.sender] += shares;
    totalShares += shares;

    bool success = depositToken.transferFrom(msg.sender, address(this), amount);
    require(success, "Token transferFrom failed");
}

```

## ISSUE-4:

Possible division-by-zero error and attack. When calculating the user's share, there is no check
if the vaultBalance is zero or not. The balance of vault can become zero if it is externally drained of the
deposit token.

### Attack Scenario:

- A malicious admin can drain the vault of its deposit token.
- This can result in the deposit function of the vault contract reverting due to division-by-zero (vaultBalance is zero).
- As a result, other users can not deposit into the vault resulting in contract DoS (Denial-of-Service) attack.

### Recommended Fix:

Do check to revert (or appropriate the totalShares) if the vaultBalance is zero while totalShares is greater than zero.

```solidity
uint256 vaultBalance = depositToken.balanceOf(address(this));
depositToken.safeTransferFrom(msg.sender, address(this), amount);
uint256 amountReceived = depositToken.balanceOf(address(this)) - vaultBalance;

uint256 shares;
if (totalShares == 0) {
    shares = amountReceived;
} else {
    require(vaultBalance > 0, "Invalid vault state"); // avoid div0
    shares = (amountReceived * totalShares) / vaultBalance;
}
```

## ISSUE-5:

The vault contract lacks admin control features. If the contract is undergoing an attack, there is
no way for the contract owner to pause or correct any issue with the contract.

### Attack Scenario:

- If the contracts shares and balances are inconsistent, there is no way for the owner to make corrections.

### Recommended Fix:

Add functionalities to the vault smart contract for the admin/owner to be able to pause
the smart contract or do other activities to mitigate attacks on the contract.

## ISSUE-6:

The vault smart contract has no events emitted for its critical actions. Events are supposed to be
emitted when users deposit and withdraw from the vault. Lack of events will make monitoring the vault smart contract
from off-chain systems, like data indexers like GraphProtocol, very difficult.

### Attack Scenario:

- Due to lack of events for monitoring, attacks on the vault contract will be difficult to detect on time.

### Recommended Fix:

Implement events for deposit, withdraw, and emergencyWithdraw functions. These
events will log the important information about the transaction.

```solidity
event Deposit(address indexed user, uint256 amount, uint256 shares);
event Withdraw(address indexed user, uint256 shares, uint256 amount);
event EmergencyWithdraw(address indexed user, uint256 shares, uint256 amount);
event Compound(address indexed caller, uint256 rewards);
```

## ISSUE-7:

The vault's withdraw, emergencyWithdraw, and compoundRewards functions are not made nonReentrant.
It is not only the deposit function that is vulnerable.

### Attack Scenario:

- A malicious token sent to the contract could in principle trigger reentrant behavior during transfer calls,
  or an attacker could try some callback function calls.

### Recommended Fix: Use OpenZeppelin ReentrancyGuard and mark deposit, withdraw, emergencyWithdraw, and compoundRewards nonReentrant

## ISSUE-8:

Due to precision or rounding values issues (when values are floored), the vault contract shares calculations may become slightly
inconsistent.

### Recommended Fix:

Use higher-precision multipliers during calculations. It can mitigate the precision issues.
