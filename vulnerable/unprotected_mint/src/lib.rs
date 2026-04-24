//! VULNERABLE: Unprotected Mint Function
//!
//! A token contract where `mint()` creates tokens for any address without
//! requiring admin authorization. Any caller can inflate the token supply
//! arbitrarily, minting unlimited tokens to any address.
//!
//! VULNERABILITY: Missing admin `require_auth()` before minting tokens.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
}

// ── Vulnerable contract ───────────────────────────────────────────────────────

#[contract]
pub struct UnprotectedMintToken;

#[contractimpl]
impl UnprotectedMintToken {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: Mints `amount` tokens to `to` without verifying the caller
    /// is the admin. No `admin.require_auth()` call — anyone can inflate supply.
    pub fn mint(env: Env, to: Address, amount: i128) {
        // ❌ Missing: let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        //             admin.require_auth();

        let key = DataKey::Balance(to.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));

        env.events()
            .publish((symbol_short!("mint"),), (to, amount));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }
}

// ── Secure mirror ─────────────────────────────────────────────────────────────

#[contract]
pub struct SecureMintToken;

#[contractimpl]
impl SecureMintToken {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// SECURE: Only the stored admin can mint tokens.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap();
        // ✅ Admin must sign this transaction
        admin.require_auth();

        let key = DataKey::Balance(to.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));

        env.events()
            .publish((symbol_short!("mint"),), (to, amount));
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

    // ── Vulnerable contract tests ─────────────────────────────────────────────

    fn setup_vulnerable() -> (Env, Address, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, UnprotectedMintToken);
        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        UnprotectedMintTokenClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, admin, attacker)
    }

    #[test]
    fn test_admin_mints_tokens_normally() {
        let (env, contract_id, admin, _) = setup_vulnerable();
        let client = UnprotectedMintTokenClient::new(&env, &contract_id);

        client.mint(&admin, &1_000);
        assert_eq!(client.balance(&admin), 1_000);
    }

    /// Demonstrates the vulnerability: attacker mints without auth — succeeds.
    #[test]
    fn test_attacker_mints_without_auth() {
        let (env, contract_id, admin, attacker) = setup_vulnerable();
        let client = UnprotectedMintTokenClient::new(&env, &contract_id);

        // Seed a known admin balance so we can track total supply inflation.
        client.mint(&admin, &1_000);

        // ❌ VULNERABILITY: No auth check — attacker mints freely.
        client.mint(&attacker, &999_999);

        assert_eq!(client.balance(&attacker), 999_999);
    }

    /// Total supply is inflated beyond intended cap by an unauthorized caller.
    #[test]
    fn test_supply_inflated_beyond_cap() {
        let (env, contract_id, admin, attacker) = setup_vulnerable();
        let client = UnprotectedMintTokenClient::new(&env, &contract_id);

        let cap: i128 = 1_000_000;
        client.mint(&admin, &cap);

        // Attacker mints an equal amount — supply is now 2× the intended cap.
        client.mint(&attacker, &cap);

        assert_eq!(client.balance(&admin), cap);
        assert_eq!(client.balance(&attacker), cap);
        // Combined balance exceeds the cap, demonstrating unconstrained inflation.
        assert!(client.balance(&admin) + client.balance(&attacker) > cap);
    }

    // ── Secure contract tests ─────────────────────────────────────────────────

    #[test]
    fn test_secure_admin_can_mint() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SecureMintToken);
        let admin = Address::generate(&env);
        let client = SecureMintTokenClient::new(&env, &contract_id);

        client.initialize(&admin);
        client.mint(&admin, &500);
        assert_eq!(client.balance(&admin), 500);
    }

    #[test]
    #[should_panic]
    fn test_secure_attacker_cannot_mint() {
        let env = Env::default();
        // No mock_all_auths — auth failures will panic.
        let contract_id = env.register_contract(None, SecureMintToken);
        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        let client = SecureMintTokenClient::new(&env, &contract_id);

        client.initialize(&admin);
        // ✅ This panics because attacker is not the admin.
        client.mint(&attacker, &999_999);
    }
}
