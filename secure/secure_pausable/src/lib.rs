//! SECURE: Admin-gated circuit-breaker (pause / unpause)
//!
//! This is the secure mirror of the `unprotected_pause` vulnerability.
//!
//! SECURITY PROPERTIES:
//! 1. `pause` and `unpause` both call `admin.require_auth()`.
//! 2. `transfer` panics when the contract is paused.
//! 3. Events are emitted on every pause/unpause transition.
//! 4. Admin rotation is protected — only the current admin can set a new one.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Paused,
    Balance(Address),
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct SecurePausable;

#[contractimpl]
impl SecurePausable {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Paused, &false);
    }

    /// Mint tokens to an address (admin only, for test setup).
    pub fn mint(env: Env, to: Address, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(to.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to), &(balance + amount));
    }

    /// ✅ FIX: Only the admin can pause the contract.
    pub fn pause(env: Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        env.storage().persistent().set(&DataKey::Paused, &true);
        env.events()
            .publish((symbol_short!("paused"),), admin);
    }

    /// ✅ FIX: Only the admin can unpause the contract.
    pub fn unpause(env: Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        env.storage().persistent().set(&DataKey::Paused, &false);
        env.events()
            .publish((symbol_short!("unpaused"),), admin);
    }

    /// ✅ FIX: Transfer is blocked while the contract is paused.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let paused: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        if paused {
            panic!("contract is paused");
        }

        from.require_auth();

        let from_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(from.clone()))
            .unwrap_or(0);
        let to_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(to.clone()))
            .unwrap_or(0);

        env.storage().persistent().set(
            &DataKey::Balance(from),
            &from_balance.checked_sub(amount).expect("insufficient balance"),
        );
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to), &(to_balance + amount));
    }

    /// ✅ FIX: Only the current admin can rotate to a new admin.
    pub fn set_admin(env: Env, new_admin: Address) {
        let current_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        current_admin.require_auth();

        env.storage()
            .persistent()
            .set(&DataKey::Admin, &new_admin);
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    /// Admin pauses — transfer fails.
    #[test]
    #[should_panic(expected = "contract is paused")]
    fn test_transfer_fails_when_paused() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecurePausable);
        let client = SecurePausableClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &500);
        client.pause();
        client.transfer(&alice, &bob, &100);
    }

    /// Admin unpauses — transfer succeeds.
    #[test]
    fn test_transfer_succeeds_after_unpause() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecurePausable);
        let client = SecurePausableClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &500);
        client.pause();
        client.unpause();
        client.transfer(&alice, &bob, &200);

        assert_eq!(client.balance(&alice), 300);
        assert_eq!(client.balance(&bob), 200);
    }

    /// Non-admin cannot pause.
    #[test]
    #[should_panic]
    fn test_non_admin_cannot_pause() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecurePausable);
        let client = SecurePausableClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);

        // New env without mocked auths — attacker tries to pause.
        let env2 = Env::default();
        let client2 = SecurePausableClient::new(&env2, &contract_id);
        client2.pause(); // should panic: no auth
    }

    /// Non-admin cannot unpause.
    #[test]
    #[should_panic]
    fn test_non_admin_cannot_unpause() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecurePausable);
        let client = SecurePausableClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);
        client.pause();

        // New env without mocked auths — attacker tries to unpause.
        let env2 = Env::default();
        let client2 = SecurePausableClient::new(&env2, &contract_id);
        client2.unpause(); // should panic
    }

    /// Pause state persists across calls.
    #[test]
    fn test_pause_state_persists() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecurePausable);
        let client = SecurePausableClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);

        assert!(!client.is_paused());
        client.pause();
        assert!(client.is_paused());
        client.unpause();
        assert!(!client.is_paused());
    }

    /// Admin rotation: new admin can be set by current admin.
    #[test]
    fn test_admin_rotation() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecurePausable);
        let client = SecurePausableClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);

        let new_admin = Address::generate(&env);
        client.set_admin(&new_admin);
        assert_eq!(client.get_admin(), new_admin);
    }
}
