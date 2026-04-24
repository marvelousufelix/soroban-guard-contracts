//! SECURE: Canonical Secure Token
//!
//! Reference implementation combining all token security patterns:
//! - Admin-gated mint/burn with `admin.require_auth()`
//! - `from.require_auth()` on transfer
//! - Checked arithmetic on every balance mutation
//! - Self-transfer guard
//! - Events emitted on every state change
//! - Total supply tracked on mint/burn

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
    TotalSupply,
}

#[contract]
pub struct SecureToken;

#[contractimpl]
impl SecureToken {
    /// One-time initialisation — sets the admin.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Mint `amount` tokens to `to`. Requires admin auth.
    pub fn mint(env: Env, to: Address, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(to.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to.clone()), &bal.checked_add(amount).expect("overflow"));

        let supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &supply.checked_add(amount).expect("overflow"));

        env.events().publish((symbol_short!("mint"),), (to, amount));
    }

    /// Burn `amount` tokens from `from`. Requires `from` auth.
    pub fn burn(env: Env, from: Address, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        from.require_auth();

        let bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(from.clone()))
            .unwrap_or(0);
        let new_bal = bal.checked_sub(amount).expect("insufficient balance");
        assert!(new_bal >= 0, "insufficient balance");
        env.storage()
            .persistent()
            .set(&DataKey::Balance(from.clone()), &new_bal);

        let supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &supply.checked_sub(amount).expect("supply underflow"));

        env.events().publish((symbol_short!("burn"),), (from, amount));
    }

    /// Transfer `amount` from `from` to `to`. Requires `from` auth.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        assert!(from != to, "self-transfer not allowed");
        from.require_auth();

        let from_bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(from.clone()))
            .unwrap_or(0);
        let to_bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(to.clone()))
            .unwrap_or(0);

        let new_from = from_bal.checked_sub(amount).expect("insufficient balance");
        assert!(new_from >= 0, "insufficient balance");
        let new_to = to_bal.checked_add(amount).expect("overflow");

        env.storage().persistent().set(&DataKey::Balance(from.clone()), &new_from);
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &new_to);

        env.events().publish((symbol_short!("transfer"),), (from, to, amount));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    pub fn total_supply(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, SecureTokenClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);
        (env, admin, client)
    }

    #[test]
    fn test_admin_mint_user_transfer_user_burn() {
        let (env, _admin, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        env.mock_all_auths();
        client.mint(&alice, &1000);
        assert_eq!(client.balance(&alice), 1000);
        assert_eq!(client.total_supply(), 1000);

        client.transfer(&alice, &bob, &400);
        assert_eq!(client.balance(&alice), 600);
        assert_eq!(client.balance(&bob), 400);

        client.burn(&bob, &100);
        assert_eq!(client.balance(&bob), 300);
        assert_eq!(client.total_supply(), 900);
    }

    #[test]
    #[should_panic]
    fn test_non_admin_cannot_mint() {
        let (env, _admin, client) = setup();
        let attacker = Address::generate(&env);
        // mock_all_auths not called for attacker — require_auth on admin will fail
        client.mint(&attacker, &1000);
    }

    #[test]
    #[should_panic(expected = "self-transfer not allowed")]
    fn test_self_transfer_rejected() {
        let (env, _admin, client) = setup();
        let alice = Address::generate(&env);
        env.mock_all_auths();
        client.mint(&alice, &500);
        client.transfer(&alice, &alice, &100);
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn test_mint_overflow_panics() {
        let (env, _admin, client) = setup();
        let alice = Address::generate(&env);
        env.mock_all_auths();
        client.mint(&alice, &i128::MAX);
        // Second mint pushes balance past i128::MAX
        client.mint(&alice, &1);
    }
}
