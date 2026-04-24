//! VULNERABLE: Unchecked Cast from i128 to u64
//!
//! A reward contract that stores staker balances as `i128` but casts them to
//! `u64` with `as u64` when returning the reward amount. This silently
//! truncates the high 64 bits of any value that doesn't fit in a u64, and
//! converts negative i128 values into large positive u64 numbers via two's
//! complement reinterpretation.
//!
//! VULNERABILITY: `balance as u64` — no bounds check, no error on overflow.
//! Severity: High
//!
//! Secure mirror: use `u64::try_from(val).expect("value out of range")` or
//! keep consistent types throughout.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_balance(env: &Env, staker: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(staker.clone()))
        .unwrap_or(0)
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct RewardContract;

#[contractimpl]
impl RewardContract {
    /// Deposit an amount (stored as i128).
    pub fn deposit(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        let current = get_balance(&env, &staker);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(staker), &(current + amount));
    }

    /// VULNERABLE: casts i128 balance to u64 with no bounds check.
    /// - Large i128 values lose their high bits → wrong (smaller) result.
    /// - Negative i128 values become large positive u64 numbers.
    pub fn get_reward(env: Env, staker: Address) -> u64 {
        let balance: i128 = get_balance(&env, &staker);
        // ❌ Truncates silently — negative or large values produce wrong results
        balance as u64
    }

    /// Returns the raw i128 balance for inspection in tests.
    pub fn get_balance_raw(env: Env, staker: Address) -> i128 {
        get_balance(&env, &staker)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, soroban_sdk::Address, RewardContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, RewardContract);
        let client = RewardContractClient::new(&env, &id);
        let staker = Address::generate(&env);
        (env, staker, client)
    }

    /// Small positive value fits in u64 — cast is correct.
    #[test]
    fn test_small_positive_casts_correctly() {
        let (_env, staker, client) = setup();
        client.deposit(&staker, &1000_i128);
        let reward = client.get_reward(&staker);
        assert_eq!(reward, 1000_u64);
    }

    /// Large i128 value (> u64::MAX) truncates to a wrong u64.
    /// Demonstrates the vulnerability: high bits are silently dropped.
    #[test]
    fn test_large_i128_truncates_to_wrong_u64() {
        let (_env, staker, client) = setup();

        // u64::MAX + 1 as i128 — the high bit is set, low 64 bits are all zero
        let large: i128 = (u64::MAX as i128) + 1;
        client.deposit(&staker, &large);

        let raw = client.get_balance_raw(&staker);
        assert_eq!(raw, large);

        // ❌ Cast truncates: (u64::MAX + 1) as u64 == 0
        let reward = client.get_reward(&staker);
        assert_eq!(reward, 0, "truncation: high bits lost, result is wrong");
        assert_ne!(reward as i128, raw, "reward does not match actual balance");
    }

    /// Negative i128 casts to a large positive u64 via two's complement.
    /// Demonstrates the vulnerability: -1i128 as u64 == u64::MAX.
    #[test]
    fn test_negative_i128_becomes_large_positive_u64() {
        let (_env, staker, client) = setup();

        // Deposit a negative balance (e.g. after a buggy withdrawal)
        client.deposit(&staker, &-1_i128);

        let raw = client.get_balance_raw(&staker);
        assert_eq!(raw, -1_i128);

        // ❌ -1i128 as u64 == u64::MAX (18_446_744_073_709_551_615)
        let reward = client.get_reward(&staker);
        assert_eq!(
            reward,
            u64::MAX,
            "negative balance cast to u64::MAX — attacker gets maximum reward"
        );
    }
}
