# Soroban Vulnerability Reference

Each entry maps to a contract in `vulnerable/` and its secure mirror in `secure/`.

---

## 1. Missing Authorization (`missing_auth`)

**Contract:** `vulnerable/missing_auth` → `secure/secure_vault`
**Severity:** Critical

### What it is

Soroban's auth model requires every state-mutating function to call
`address.require_auth()` for the address whose resources are being modified.
Without this call the Soroban host places no restriction on who can invoke the
function — any account can submit a valid transaction.

### Vulnerable pattern

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    // ❌ No require_auth — anyone can drain `from`
    let from_balance = env.storage().persistent().get(&DataKey::Balance(from.clone())).unwrap_or(0);
    env.storage().persistent().set(&DataKey::Balance(from), &(from_balance - amount));
}
```

### Secure fix

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth(); // ✅ Only `from` can authorise this transfer
    // ...
}
```

### Impact

Complete fund theft: any attacker can transfer the entire balance of any account.

---

## 2. Unchecked Arithmetic (`unchecked_math`)

**Contract:** `vulnerable/unchecked_math` → `secure/secure_vault`
**Severity:** High

### What it is

Rust's integer types wrap on overflow in `--release` builds unless
`overflow-checks = true` is set in the Cargo profile. Even with that flag,
relying on a panic is not the same as explicitly handling the error. The correct
approach is `checked_mul` / `checked_add` which return `Option` and force the
developer to handle the overflow case.

### Vulnerable pattern

```rust
// ❌ Raw * — overflows silently without overflow-checks = true
let reward = staked * rate * elapsed;
```

### Secure fix

```rust
let reward = staked
    .checked_mul(rate).expect("reward: overflow")
    .checked_mul(elapsed).expect("reward: overflow");
```

### Impact

Reward calculation produces wildly incorrect values, enabling either free reward
extraction or denial of rewards.

---

## 3. Unprotected Admin Functions (`unprotected_admin`)

**Contract:** `vulnerable/unprotected_admin` → `secure/protected_admin`
**Severity:** Critical

### What it is

Admin-only functions (`set_admin`, `upgrade`) that do not verify the caller is
the current admin. Because Soroban does not have implicit access control, any
account can call these functions and take over the contract.

### Vulnerable pattern

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    // ❌ No require_auth on the current admin
    env.storage().persistent().set(&DataKey::Admin, &new_admin);
}
```

### Secure fix

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    let current: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
    current.require_auth(); // ✅ Only the current admin can rotate
    env.storage().persistent().set(&DataKey::Admin, &new_admin);
}
```

### Impact

Full contract takeover: attacker becomes admin and can drain funds, upgrade to
malicious WASM, or brick the contract.

---

## 4. Unsafe Storage Writes (`unsafe_storage`)

**Contract:** `vulnerable/unsafe_storage` → `secure/protected_admin`
**Severity:** High

### What it is

A public function that writes to persistent storage keyed by an `Address`
argument without verifying the caller owns that address. Any account can pass
any address and overwrite that account's data.

### Vulnerable pattern

```rust
pub fn set_profile(env: Env, account: Address, display_name: String, kyc_level: u32) {
    // ❌ No require_auth — anyone can write to any account's slot
    env.storage().persistent().set(&DataKey::Profile(account), &Profile { display_name, kyc_level });
}
```

### Secure fix

```rust
pub fn set_profile(env: Env, account: Address, display_name: String, kyc_level: u32) {
    account.require_auth(); // ✅ Only the account owner can update their profile
    env.storage().persistent().set(&DataKey::Profile(account), &Profile { display_name, kyc_level });
}
```

### Impact

Data integrity violation: KYC levels, display names, or any stored metadata can
be forged or wiped by any attacker.

---

## 5. Self-Transfer Balance Inflation (`self_transfer`)

**Contract:** `vulnerable/self_transfer` → `secure/secure_transfer`
**Severity:** Medium

### What it is

When `transfer(from, to, amount)` is called with `from == to`, both balance
reads resolve to the same persistent storage slot. The function reads the
balance into two separate variables, subtracts from the first write, then
overwrites that slot with the second write — inflating the account balance by
`amount`.

### Vulnerable pattern

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    // ❌ No from != to check — self-transfer corrupts balance
    let from_balance = get_balance(&env, &from);
    let to_balance = get_balance(&env, &to); // same slot when from == to
    set_balance(&env, &from, from_balance.checked_sub(amount).unwrap());
    set_balance(&env, &to, to_balance.checked_add(amount).unwrap()); // overwrites subtraction
}
```

### Secure fix

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    assert!(from != to, "self-transfer not allowed"); // ✅ Guard before any storage access
    from.require_auth();
    // ...
}
```

### Impact

Balance inflation: a user can repeatedly self-transfer to inflate their balance
without limit.

---

## 6. Missing TTL Renewal (`missing_ttl`)

**Contract:** `vulnerable/missing_ttl` → `vulnerable/missing_ttl/src/secure.rs`
**Severity:** Low

### What it is

Soroban persistent storage entries are not permanent by default. Every entry has
a ledger TTL, and once that window passes the entry expires unless the contract
refreshes it with `env.storage().persistent().extend_ttl(...)`.

### Vulnerable pattern

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    // ❌ No extend_ttl — active balances are never renewed
    env.storage().persistent().set(&from_key, &new_from);
    env.storage().persistent().set(&to_key, &new_to);
}
```

### Secure fix

```rust
env.storage().persistent().set(&key, &amount);
env.storage().persistent().extend_ttl(&key, threshold, extend_to); // ✅ renew on write
```

### Impact

Liveness failure: after the network's max TTL window, balances disappear and
the contract starts reading them as missing. Funds can become permanently
inaccessible.

---

## 7. Zero-Address Admin (`zero_admin`)

**Contract:** `vulnerable/zero_admin` → `secure/protected_admin`
**Severity:** High

### What it is

`initialize(admin)` stores the admin without validating that it is a real,
non-default address. Passing the zero/default address permanently bricks all
admin-gated functions because no one can ever satisfy `require_auth` for that
address.

### Vulnerable pattern

```rust
pub fn initialize(env: Env, admin: Address) {
    if env.storage().persistent().has(&DataKey::Admin) {
        panic!("already initialized");
    }
    // ❌ Missing: assert admin != zero/default address
    env.storage().persistent().set(&DataKey::Admin, &admin);
}
```

### Secure fix

```rust
pub fn initialize(env: Env, admin: Address) {
    // ✅ Validate admin is a real account before storing
    admin.require_auth();
    env.storage().persistent().set(&DataKey::Admin, &admin);
}
```

### Impact

Contract bricked: if the zero address is stored as admin, no one can ever call
admin-gated functions again.

---

## 8. Zero-Amount Deposit (`zero_deposit`)

**Contract:** `vulnerable/zero_deposit` → `vulnerable/zero_deposit/src/secure.rs`
**Severity:** Low

### What it is

A vault contract where `deposit` accepts `amount == 0` without error. This
writes a zero-balance entry to persistent storage, wasting ledger space and
confusing accounting logic that assumes stored entries always hold a positive
balance.

### Vulnerable pattern

```rust
pub fn deposit(env: Env, user: Address, amount: i128) {
    user.require_auth();
    // ❌ No positive-amount guard — zero deposits create junk storage entries
    let current: i128 = env.storage().persistent().get(&DataKey::Balance(user.clone())).unwrap_or(0);
    env.storage().persistent().set(&DataKey::Balance(user), &(current + amount));
}
```

### Secure fix

```rust
pub fn deposit(env: Env, user: Address, amount: i128) {
    assert!(amount > 0, "deposit must be positive"); // ✅
    // ...
}
```

### Impact

Ledger bloat and accounting confusion; ghost entries can be exploited by logic
that gates access on the presence of a storage entry.

---

## 9. Zero-Amount Stake (`zero_stake`)

**Contract:** `vulnerable/zero_stake` → `vulnerable/zero_stake/src/secure.rs`
**Severity:** Medium

### What it is

A staking contract where `stake(staker, 0)` succeeds and records a `staked_at`
timestamp. The staker occupies a storage slot and is treated as a valid staker
by any logic that checks `is_staker`, even though they contributed nothing.
Ghost entries can be exploited by future logic that gates access on staker
status (e.g. governance, airdrops).

### Vulnerable pattern

```rust
pub fn stake(env: Env, staker: Address, amount: i128) {
    staker.require_auth();
    // ❌ Missing: assert!(amount > 0, "stake must be positive")
    env.storage().persistent().set(&DataKey::Stake(staker.clone()), &StakeInfo { amount, staked_at });
}
```

### Secure fix

```rust
pub fn stake(env: Env, staker: Address, amount: i128) {
    assert!(amount > 0, "stake must be positive"); // ✅
    // ...
}
```

### Impact

Ghost staker entries; attackers gain staker status (governance votes, airdrop
eligibility) without committing any capital.

---

## 10. Double Claim / Stale Timestamp (`double_claim`)

**Contract:** `vulnerable/double_claim` → `secure/secure_vault`
**Severity:** Critical

### What it is

A staking contract where `claim_rewards` computes the reward based on elapsed
ledgers since `staked_at`, but never resets `staked_at` after paying out. The
same elapsed window can be claimed over and over, draining the reward pool.

### Vulnerable pattern

```rust
pub fn claim_rewards(env: Env, staker: Address) -> u64 {
    staker.require_auth();
    let staked_at = get_staked_at(&env, &staker);
    let elapsed = env.ledger().sequence() - staked_at as u32;
    let reward = get_stake(&env, &staker) * elapsed as u64 * get_rate(&env);
    // ❌ staked_at is never updated — same window claimed repeatedly
    reward
}
```

### Secure fix

```rust
// ✅ Reset the timestamp after every claim
env.storage().persistent().set(&DataKey::StakedAt(staker.clone()), &(env.ledger().sequence() as u64));
```

### Impact

Reward pool drained to zero: a staker can call `claim_rewards` in a tight loop
and extract unlimited rewards from a single stake.

---

## 11. Division by Zero (`div_by_zero`)

**Contract:** `vulnerable/div_by_zero` → inline secure pattern
**Severity:** Medium

### What it is

A staking contract that distributes rewards by dividing `total_reward` by
`total_staked`. When the pool is empty (`total_staked == 0`) the division
panics, giving any caller a reliable denial-of-service vector.

### Vulnerable pattern

```rust
pub fn distribute(env: Env) -> u64 {
    let total_staked: u64 = env.storage().persistent().get(&DataKey::TotalStaked).unwrap_or(0);
    let total_reward: u64 = 1_000_000;
    // ❌ Panics when total_staked == 0
    total_reward / total_staked
}
```

### Secure fix

```rust
if total_staked == 0 {
    return 0; // ✅ Guard before division
}
let per_unit = total_reward / total_staked;
```

### Impact

Denial of service: any caller can trigger a panic by invoking `distribute`
before anyone has staked.

---

## 12. Missing Events (`missing_events`)

**Contract:** `vulnerable/missing_events` → `secure/secure_vault`
**Severity:** Low

### What it is

State-mutating functions (`mint`, `burn`) that never call
`env.events().publish()`. Off-chain indexers and users cannot track these state
changes, leading to inconsistent views of the contract state and broken
monitoring.

### Vulnerable pattern

```rust
pub fn mint(env: Env, to: Address, amount: i128) {
    // ❌ No event emitted — off-chain indexers are blind to this mutation
    let key = DataKey::Balance(to);
    let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    env.storage().persistent().set(&key, &(current + amount));
}
```

### Secure fix

```rust
pub fn mint(env: Env, to: Address, amount: i128) {
    // ... balance update ...
    env.events().publish((symbol_short!("mint"),), (to, amount)); // ✅
}
```

### Impact

Silent state changes break off-chain monitoring, auditing, and user-facing
balance displays.


---

## 13. Leaky Events (`leaky_events`)

**Contract:** `vulnerable/leaky_events` → `vulnerable/leaky_events/src/secure.rs`
**Severity:** Low

### What it is

A token contract that publishes post-transfer balances for both sender and
recipient in every transfer event. Anyone monitoring the ledger can reconstruct
every account's full transaction history and current balance from the event
stream alone — no storage access required.

### Vulnerable pattern

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    // ... balance update ...
    // ❌ Emits exact post-transfer balances — leaks financial state of both parties
    env.events().publish(
        (symbol_short!("transfer"),),
        (from, to, new_from_balance, new_to_balance),
    );
}
```

### Secure fix

```rust
// ✅ Emit only the transfer amount — balances stay private
env.events().publish((symbol_short!("transfer"),), (from, to, amount));
```

### Impact

Privacy violation: full balance history of every account is publicly
reconstructable from the event stream.

---

## 14. Unprotected Delete (`unprotected_delete`)

**Contract:** `vulnerable/unprotected_delete` → `secure/protected_admin`
**Severity:** High

### What it is

A data registry contract where any caller can delete any account's persistent
storage entry via `delete_entry()` without owning that address. An attacker can
wipe any account's data with no authorization.

### Vulnerable pattern

```rust
pub fn delete_entry(env: Env, account: Address) {
    // ❌ No account.require_auth() — anyone can delete anyone's entry
    env.storage().persistent().remove(&DataKey::Entry(account));
}
```

### Secure fix

```rust
pub fn delete_entry(env: Env, account: Address) {
    account.require_auth(); // ✅ Only the account owner can delete their entry
    env.storage().persistent().remove(&DataKey::Entry(account));
}
```

### Impact

Data destruction: an attacker can wipe KYC records, profile data, or any
registry entry for any account.

---

## 15. Unprotected Burn (`unprotected_burn`)

**Contract:** `vulnerable/unprotected_burn` → `secure/secure_burn`
**Severity:** High

### What it is

A token contract where `burn()` destroys tokens from any account without
requiring authorization from that account. Any caller can burn any account's
tokens, deflating supply and wiping balances.

### Vulnerable pattern

```rust
pub fn burn(env: Env, account: Address, amount: i128) {
    // ❌ No account.require_auth() — anyone can burn anyone's tokens
    let balance: i128 = env.storage().persistent().get(&DataKey::Balance(account.clone())).unwrap_or(0);
    env.storage().persistent().set(&DataKey::Balance(account), &(balance - amount));
}
```

### Secure fix

```rust
pub fn burn(env: Env, account: Address, amount: i128) {
    account.require_auth(); // ✅ Only the token holder can burn their own tokens
    // ...
}
```

### Impact

Targeted balance destruction: an attacker can zero out any account's token
balance at will.

---

## 16. Unprotected Fee Withdrawal (`unprotected_fee_withdraw`)

**Contract:** `vulnerable/unprotected_fee_withdraw` → `secure/protected_fee_withdraw`
**Severity:** Critical

### What it is

A DEX-style contract that accumulates fees from swaps and exposes an unguarded
`withdraw_fees()` function. Any account can drain the contract's accumulated
fee balance to an arbitrary address.

### Vulnerable pattern

```rust
pub fn withdraw_fees(env: Env, recipient: Address) {
    // ❌ No admin.require_auth() — anyone can drain accumulated fees
    let fees: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
    env.storage().persistent().set(&DataKey::Fees, &0i128);
    env.events().publish((symbol_short!("withdraw"),), (recipient, fees));
}
```

### Secure fix

```rust
pub fn withdraw_fees(env: Env, recipient: Address) {
    let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
    admin.require_auth(); // ✅ Only admin can withdraw fees
    // ...
}
```

### Impact

Complete fee theft: any attacker can drain all accumulated protocol fees to an
address they control.

---

## 17. Reentrancy (`reentrancy`)

**Contract:** `vulnerable/reentrancy` → `vulnerable/reentrancy/src/secure.rs`
**Severity:** High

### What it is

A vault that notifies an external contract before reducing the user's balance.
An attacker-controlled notifier can call back into `withdraw()` while the
original user's balance is still intact, withdrawing more than they deposited.

### Vulnerable pattern

```rust
pub fn withdraw(env: Env, user: Address, amount: i128, notify_id: Address) {
    user.require_auth();
    let balance = get_balance(&env, &user);
    // ❌ External call BEFORE state update — reentrancy window
    NotifyContractClient::new(&env, &notify_id).on_withdraw(&user, &amount);
    // Balance update happens after the callback — too late
    env.storage().persistent().set(&DataKey::Balance(user), &(balance - amount));
}
```

### Secure fix

```rust
pub fn withdraw(env: Env, user: Address, amount: i128, notify_id: Address) {
    user.require_auth();
    let balance = get_balance(&env, &user);
    // ✅ Update state BEFORE external call
    env.storage().persistent().set(&DataKey::Balance(user.clone()), &(balance - amount));
    NotifyContractClient::new(&env, &notify_id).on_withdraw(&user, &amount);
}
```

### Impact

Double-spend: an attacker can withdraw more than their deposited balance by
re-entering `withdraw` during the callback.

---

## 18. Re-initialization Attack (`reinit_attack`)

**Contract:** `vulnerable/reinit_attack` → `secure/protected_admin`
**Severity:** Critical

### What it is

A vault contract whose `initialize()` sets the admin and treasury balance but
performs no re-init guard. Any caller can invoke `initialize()` again after
deployment, replacing the admin with an attacker-controlled address and
effectively taking over the contract.

### Vulnerable pattern

```rust
pub fn initialize(env: Env, admin: Address) {
    // ❌ No check whether already initialized — can be called repeatedly
    env.storage().persistent().set(&DataKey::Admin, &admin);
}
```

### Secure fix

```rust
pub fn initialize(env: Env, admin: Address) {
    if env.storage().persistent().has(&DataKey::Admin) {
        panic!("already initialized"); // ✅ One-time init guard
    }
    env.storage().persistent().set(&DataKey::Admin, &admin);
}
```

### Impact

Full contract takeover: an attacker calls `initialize` after deployment to
install themselves as admin.

---

## 19. String Admin (`string_admin`)

**Contract:** `vulnerable/string_admin` → `secure/protected_admin`
**Severity:** Critical

### What it is

A contract that stores the admin as a `String` and authenticates callers with a
plain `==` comparison. String comparison provides no cryptographic guarantee —
any caller who knows (or guesses) the stored string value can pass the check
without holding the corresponding private key.

### Vulnerable pattern

```rust
pub fn set_config(env: Env, caller: String, value: u32) {
    let admin: String = env.storage().persistent().get(&DataKey::Admin).unwrap();
    // ❌ String equality — no cryptographic proof of key ownership
    assert!(caller == admin, "not admin");
    env.storage().persistent().set(&DataKey::Config, &value);
}
```

### Secure fix

```rust
pub fn set_config(env: Env, admin: Address, value: u32) {
    let stored: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
    assert!(admin == stored, "not admin");
    admin.require_auth(); // ✅ Cryptographic proof via Stellar signature
    env.storage().persistent().set(&DataKey::Config, &value);
}
```

### Impact

Admin bypass: anyone who can observe or guess the admin string can call
privileged functions without holding the private key.

---

## 20. Integer Underflow on Transfer (`underflow_transfer`)

**Contract:** `vulnerable/underflow_transfer` → `secure/secure_vault`
**Severity:** High

### What it is

A token contract where `transfer()` subtracts balances with raw `-` on `i128`.
If `amount > from_balance` the subtraction underflows, wrapping to a large
positive number and crediting the sender with a massive balance.

### Vulnerable pattern

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    let from_balance: i128 = env.storage().persistent().get(&DataKey::Balance(from.clone())).unwrap_or(0);
    // ❌ Raw subtraction — wraps to large positive on underflow
    env.storage().persistent().set(&DataKey::Balance(from), &(from_balance - amount));
}
```

### Secure fix

```rust
let new_balance = from_balance.checked_sub(amount).expect("insufficient funds"); // ✅
```

### Impact

Balance inflation: a user with zero balance can transfer a large amount and end
up with a near-maximum `i128` balance.

---

## 21. Storage Key Collision (`key_collision`)

**Contract:** `vulnerable/key_collision` → `vulnerable/key_collision/src/secure.rs`
**Severity:** Medium

### What it is

Using flat `symbol_short!` strings for all storage keys means any two keys that
share the same string value occupy the same storage slot. A user whose chosen
tag equals `"admin"` silently overwrites the global admin slot, and vice-versa.

### Vulnerable pattern

```rust
pub fn set_admin(env: Env, admin: Address) {
    // ❌ Plain symbol — collides with any user key also named "admin"
    env.storage().persistent().set(&symbol_short!("admin"), &admin);
}

pub fn set_user_tag(env: Env, user: Address, tag: Symbol) {
    // ❌ If tag == symbol_short!("admin"), this overwrites the admin slot
    env.storage().persistent().set(&tag, &user);
}
```

### Secure fix

```rust
#[contracttype]
pub enum DataKey {
    Admin,
    UserTag(Address), // ✅ Enum variants are namespaced — no collision possible
}
```

### Impact

Storage corruption: a crafted user tag can overwrite the admin address or any
other global config slot, leading to privilege escalation or data loss.

---

## 22. Negative Transfer Amount (`negative_transfer`)

**Contract:** `vulnerable/negative_transfer` → `secure/secure_transfer`
**Severity:** High

### What it is

A token contract where `transfer()` accepts negative `amount` values. A
negative amount reverses the transfer direction — the sender receives tokens
from the recipient instead of sending them, bypassing the recipient's auth.

### Vulnerable pattern

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    // ❌ No positive-amount guard — negative amount steals from `to`
    set_balance(&env, &from, get_balance(&env, &from) - amount);
    set_balance(&env, &to,   get_balance(&env, &to)   + amount);
}
```

### Secure fix

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    assert!(amount > 0, "amount must be positive"); // ✅
    from.require_auth();
    // ...
}
```

### Impact

Unauthorized fund extraction: `from` can call `transfer(from, victim, -N)` to
steal `N` tokens from `victim` using only their own auth.

---

## 23. Timestamp-Based Time Lock (`timestamp_lock`)

**Contract:** `vulnerable/timestamp_lock` → `secure/sequence_lock`
**Severity:** Medium

### What it is

A time-locked vault that uses `env.ledger().timestamp()` to enforce lock
periods. Validators can manipulate timestamps within a drift window (typically
5–15 seconds), allowing premature withdrawal of locked funds. Ledger sequences
are monotonically increasing and cannot be manipulated.

### Vulnerable pattern

```rust
pub fn withdraw(env: Env, user: Address) {
    user.require_auth();
    let unlock_time: u64 = env.storage().persistent().get(&DataKey::UnlockTime(user.clone())).unwrap();
    // ❌ Timestamp can be drifted by validators — lock can be bypassed
    assert!(env.ledger().timestamp() >= unlock_time, "funds still locked");
    // ...
}
```

### Secure fix

```rust
pub fn withdraw(env: Env, user: Address) {
    user.require_auth();
    let unlock_ledger: u32 = env.storage().persistent().get(&DataKey::UnlockLedger(user.clone())).unwrap();
    // ✅ Ledger sequence is strictly monotonic — cannot be manipulated
    assert!(env.ledger().sequence() >= unlock_ledger, "funds still locked");
    // ...
}
```

### Impact

Premature withdrawal: an attacker can unlock funds before the intended lock
period expires by exploiting validator timestamp drift.


---

## 24. No Slippage Protection (`no_slippage`)

**Contract:** `vulnerable/no_slippage` → `vulnerable/no_slippage/src/secure.rs`
**Severity:** High

### What it is

An AMM-style swap contract that accepts no `min_amount_out` parameter. An
attacker can sandwich the victim's transaction: front-run to move the pool
price unfavourably, let the victim's swap execute at the worse rate, then
back-run to pocket the difference.

### Vulnerable pattern

```rust
pub fn swap(env: Env, user: Address, amount_in: i128) -> i128 {
    user.require_auth();
    let reserve_a = get_reserve_a(&env);
    let reserve_b = get_reserve_b(&env);
    // ❌ No min_amount_out — any price impact is silently accepted
    let amount_out = (amount_in * reserve_b) / (reserve_a + amount_in);
    // ...
    amount_out
}
```

### Secure fix

```rust
pub fn swap(env: Env, user: Address, amount_in: i128, min_amount_out: i128) -> i128 {
    // ...
    assert!(amount_out >= min_amount_out, "slippage exceeded"); // ✅
    amount_out
}
```

### Impact

MEV sandwich attack: victim receives far fewer tokens than expected; attacker
extracts the price impact as profit.

---

## 25. Flash Loan Without Repayment Check (`flash_loan_no_check`)

**Contract:** `vulnerable/flash_loan_no_check` → `vulnerable/flash_loan_no_check/src/secure.rs`
**Severity:** Critical

### What it is

A flash loan contract that transfers funds to a borrower and invokes their
callback, but never asserts that the borrowed amount was returned within the
same transaction. This allows a borrower to permanently drain the lending pool
without repaying.

### Vulnerable pattern

```rust
pub fn flash_loan(env: Env, borrower_id: Address, amount: i128) {
    // Transfer funds to borrower
    BorrowerContractClient::new(&env, &borrower_id).on_flash_loan(&amount);
    // ❌ No balance check after callback — repayment is never verified
}
```

### Secure fix

```rust
pub fn flash_loan(env: Env, borrower_id: Address, amount: i128) {
    let balance_before = get_pool_balance(&env);
    BorrowerContractClient::new(&env, &borrower_id).on_flash_loan(&amount);
    // ✅ Assert full repayment after callback
    assert!(get_pool_balance(&env) >= balance_before, "flash loan not repaid");
}
```

### Impact

Complete pool drain: a borrower can take a flash loan and never repay it,
stealing the entire lending pool.

---

## 26. Scanner Impersonation (`scanner_impersonation`)

**Contract:** `vulnerable/scanner_impersonation` → `vulnerable/scanner_impersonation/src/secure.rs`
**Severity:** High

### What it is

A scan result registry where `submit_scan(scanner, ...)` does not call
`scanner.require_auth()`. Any caller can pass an arbitrary `scanner` address
and submit findings attributed to that address, poisoning the registry with
fake results.

### Vulnerable pattern

```rust
pub fn submit_scan(env: Env, scanner: Address, contract_address: Address, findings_hash: String) {
    // ❌ No scanner.require_auth() — anyone can impersonate any scanner
    let result = ScanResult { scanner, findings_hash, ... };
    env.storage().persistent().set(&DataKey::Scan(contract_address), &result);
}
```

### Secure fix

```rust
pub fn submit_scan(env: Env, scanner: Address, contract_address: Address, findings_hash: String) {
    scanner.require_auth(); // ✅ Only the real scanner can submit under their address
    // ...
}
```

### Impact

Registry poisoning: an attacker can submit fake scan results attributed to a
trusted scanner, undermining the integrity of the entire audit trail.

---

## 27. Instant Oracle / Flash-Loan Price Manipulation (`instant_oracle`)

**Contract:** `vulnerable/instant_oracle` → `vulnerable/instant_oracle/src/secure.rs`
**Severity:** High

### What it is

An oracle that allows `set_price` and `get_price` to be called in the same
ledger with no enforced delay. An attacker can borrow funds, call `set_price`
to an arbitrary value, exploit any contract that reads the oracle in the same
transaction, then repay — a classic flash-loan price manipulation.

### Vulnerable pattern

```rust
pub fn get_price(env: Env) -> i128 {
    // ❌ No staleness check — price set in the same ledger is immediately usable
    env.storage().persistent().get(&DataKey::Price).unwrap()
}
```

### Secure fix

```rust
pub fn get_price(env: Env) -> i128 {
    let updated_at: u32 = env.storage().persistent().get(&DataKey::UpdatedAt).unwrap();
    // ✅ Require at least MIN_DELAY ledgers between update and consumption
    assert!(env.ledger().sequence() > updated_at + MIN_DELAY, "price too fresh");
    env.storage().persistent().get(&DataKey::Price).unwrap()
}
```

### Impact

Price manipulation: an attacker can set an arbitrary price and exploit it
within the same transaction, enabling flash-loan attacks on any dependent
protocol.

---

## 28. Dust Griefing (`dust_griefing`)

**Contract:** `vulnerable/dust_griefing` → `secure/dust_griefing`
**Severity:** Low

### What it is

A vault contract where `deposit()` accepts any positive amount, including 1.
An attacker can create thousands of 1-unit deposits across many addresses,
bloating persistent storage and inflating TTL extension costs for everyone.

### Vulnerable pattern

```rust
pub fn deposit(env: Env, user: Address, amount: i128) {
    user.require_auth();
    // ❌ No minimum deposit — dust amounts accepted unconditionally
    let current = get_balance(&env, &user);
    set_balance(&env, &user, current + amount);
}
```

### Secure fix

```rust
pub fn deposit(env: Env, user: Address, amount: i128) {
    assert!(amount >= MIN_DEPOSIT, "deposit below minimum"); // ✅
    // ...
}
```

### Impact

Storage bloat and increased ledger fees for all users; can be used to grief
legitimate users by inflating their TTL renewal costs.

---

## 29. Allowance Not Decremented (`allowance_not_decremented`)

**Contract:** `vulnerable/allowance_not_decremented` → `vulnerable/allowance_not_decremented/src/secure.rs`
**Severity:** Critical

### What it is

A token contract where `transfer_from` checks the spender's allowance but never
reduces it after use. This lets a spender drain the full owner balance with
repeated calls using a single approval.

### Vulnerable pattern

```rust
pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
    spender.require_auth();
    let allowance = get_allowance(&env, &from, &spender);
    assert!(allowance >= amount, "insufficient allowance");
    // ❌ Allowance is never decremented — reusable forever
    let from_balance = get_balance(&env, &from);
    set_balance(&env, &from, from_balance - amount);
    set_balance(&env, &to, get_balance(&env, &to) + amount);
}
```

### Secure fix

```rust
// ✅ Decrement allowance after every successful transfer_from
set_allowance(&env, &from, &spender, allowance - amount);
```

### Impact

Unlimited fund drain: a spender with a single approval can repeatedly call
`transfer_from` to drain the entire owner balance.

---

## 30. Unprotected Emergency Withdraw (`unprotected_emergency_withdraw`)

**Contract:** `vulnerable/unprotected_emergency_withdraw` → `vulnerable/unprotected_emergency_withdraw/src/secure.rs`
**Severity:** Critical

### What it is

A time-locked vault with an `emergency_withdraw` function intended for admin
use only. Because it never calls `admin.require_auth()`, any user can invoke it
to bypass the time-lock and drain funds immediately.

### Vulnerable pattern

```rust
pub fn emergency_withdraw(env: Env, user: Address) {
    // ❌ No admin.require_auth() — any caller can release any user's locked funds
    let balance = get_balance(&env, &user);
    env.storage().persistent().set(&DataKey::Balance(user.clone()), &0i128);
    env.events().publish((symbol_short!("emrg_wdw"),), (user, balance));
}
```

### Secure fix

```rust
pub fn emergency_withdraw(env: Env, user: Address) {
    let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
    admin.require_auth(); // ✅ Only admin can trigger emergency withdrawal
    // ...
}
```

### Impact

Time-lock bypass: any attacker can call `emergency_withdraw` to immediately
release any user's locked funds, defeating the purpose of the time-lock.

---

## 31. Admin Rug-Pull (`admin_rugpull`)

**Contract:** `vulnerable/admin_rugpull` → `vulnerable/admin_rugpull/src/secure.rs`
**Severity:** High

### What it is

An escrow contract where the admin can call `admin_withdraw(user, recipient)`
using only their own auth. The user whose funds are being drained is never
consulted, giving the admin unilateral power to rug-pull any depositor.

### Vulnerable pattern

```rust
pub fn admin_withdraw(env: Env, user: Address, recipient: Address) {
    let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
    admin.require_auth();
    // ❌ Only admin signs — user whose funds are taken has no say
    let balance = get_balance(&env, &user);
    set_balance(&env, &user, 0);
    env.events().publish((symbol_short!("adm_wdw"),), (user, recipient, balance));
}
```

### Secure fix

```rust
pub fn admin_withdraw(env: Env, user: Address, recipient: Address) {
    let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
    admin.require_auth();
    user.require_auth(); // ✅ User must co-sign — admin cannot act unilaterally
    // ...
}
```

### Impact

Rug-pull: the admin can drain any depositor's escrow balance to an arbitrary
address without the depositor's consent.

---

## 32. Sensitive Data in Storage (`sensitive_storage`)

**Contract:** `vulnerable/sensitive_storage` → inline secure pattern
**Severity:** Critical

### What it is

A contract that stores a raw secret key or API credential in Soroban persistent
storage. All ledger state is public on Stellar — any observer can read the
value directly from ledger state without invoking the contract at all.

### Vulnerable pattern

```rust
pub fn initialize(env: Env, admin: Address, secret_key: Bytes) {
    admin.require_auth();
    // ❌ Raw secret written to public ledger state — readable by anyone
    env.storage().persistent().set(&DataKey::SecretKey, &secret_key);
}
```

### Secure fix

```rust
pub fn initialize_secure(env: Env, admin: Address, secret_hash: Bytes) {
    admin.require_auth();
    // ✅ Store only a hash commitment — raw secret never touches the ledger
    env.storage().persistent().set(&DataKey::Commitment, &secret_hash);
}
```

Secrets must never be stored on-chain. Use off-chain key management
infrastructure and store only public commitments (e.g. SHA-256 hashes) on the
ledger.

### Impact

Credential exposure: any observer can read the raw secret from ledger state,
compromising any system that relies on that secret remaining private.

---

## 33. Missing Call Depth Guard (`call_depth`)

**Contract:** `vulnerable/call_depth` → inline secure pattern
**Severity:** Medium

### What it is

Soroban enforces a maximum cross-contract call depth. A contract that
recursively calls itself without tracking depth will panic at the host limit
mid-execution, potentially leaving state partially updated. Attackers can craft
inputs that trigger the depth limit at a critical point in execution.

### Vulnerable pattern

```rust
pub fn process(env: Env, contract_id: Address, depth: u32) {
    // ❌ No depth check — will hit Soroban call depth limit and panic
    if depth > 0 {
        CallDepthContractClient::new(&env, &contract_id)
            .process(&contract_id, &(depth - 1));
    }
    // State update here may never be reached if depth limit is hit above
    env.storage().persistent().set(&DataKey::Processed, &true);
}
```

### Secure fix

```rust
pub const MAX_DEPTH: u32 = 10;

pub fn process_safe(env: Env, contract_id: Address, depth: u32) {
    assert!(depth <= MAX_DEPTH, "call depth exceeds safe threshold"); // ✅
    if depth > 0 {
        CallDepthContractClient::new(&env, &contract_id)
            .process_safe(&contract_id, &(depth - 1));
    }
    env.storage().persistent().set(&DataKey::Processed, &true);
}
```

### Impact

Partial state update / denial of service: an attacker can craft a depth value
that causes a panic mid-execution, leaving the contract in an inconsistent
state or blocking legitimate callers.

---

## General Soroban Security Checklist

| Check | Description |
|---|---|
| `require_auth` on every mutating fn | Every function that reads or writes resources belonging to an address must call `address.require_auth()` |
| Checked arithmetic | Use `checked_add`, `checked_sub`, `checked_mul` for all financial calculations |
| Admin gate on privileged fns | `initialize`, `upgrade`, `set_admin`, `pause` must verify the caller is the stored admin |
| Storage key ownership | Storage keys that include an `Address` must only be written after `address.require_auth()` |
| No re-initialization | Guard `initialize` with a check that the contract hasn't already been set up |
| TTL renewal for persistent entries | Long-lived state should call `persistent().extend_ttl(...)` on active reads/writes to avoid expiry |
| Positive-amount guards | Reject zero or negative amounts in `deposit`, `stake`, `transfer`, and `burn` |
| No raw secrets on-chain | Never store private keys, seeds, or API credentials in persistent storage; store only hash commitments |
| Slippage protection | AMM swaps must accept a `min_amount_out` parameter and assert the output meets it |
| Repayment check in flash loans | Assert pool balance is fully restored after the borrower callback returns |
| Call depth guard | Track recursion depth explicitly and reject calls that would exceed a safe threshold |
| Ledger sequence for time locks | Use `env.ledger().sequence()` instead of `env.ledger().timestamp()` for time-based locks |
| Typed storage keys | Use `#[contracttype]` enum variants instead of flat `symbol_short!` strings to prevent key collisions |
| Allowance decrement | `transfer_from` must decrement the spender's allowance after every successful transfer |
| Event privacy | Emit only the minimum data needed (e.g. transfer amount) — never emit post-transaction balances |
