//! VULNERABLE: Admin Stored as String Instead of Address
//!
//! The contract stores the admin as a `String` and authenticates by comparing
//! the caller string with `==`. This completely bypasses Soroban's cryptographic
//! auth system — `require_auth` cannot be called on a `String`, and any value
//! that matches the stored string passes the check with no signature verification.
//!
//! VULNERABILITY: String comparison is not authentication. An off-chain system
//! that passes the right string value can impersonate the admin with no key proof.
//!
//! SECURE MIRROR: `secure::SecureConfig` stores admin as `Address` and calls
//! `admin.require_auth()`, enforcing cryptographic signature verification.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env, String};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    Config,
}

#[contract]
pub struct StringAdminContract;

#[contractimpl]
impl StringAdminContract {
    pub fn initialize(env: Env, admin: String) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: authenticates by string equality — no cryptographic proof required.
    /// Any caller that knows (or guesses) the admin string value can pass this check.
    pub fn set_config(env: Env, caller: String, new_value: u32) {
        let admin: String = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        // ❌ String comparison — no cryptographic auth, no signature verification.
        if caller != admin {
            panic!("not admin");
        }
        env.storage().persistent().set(&DataKey::Config, &new_value);
    }

    pub fn get_config(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Config)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{Env, String};

    fn setup() -> (Env, StringAdminContractClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, StringAdminContract);
        let client = StringAdminContractClient::new(&env, &id);
        let admin_str = String::from_str(&env, "admin_key");
        client.initialize(&admin_str);
        (env, client)
    }

    /// Correct string value passes the check — no real auth needed.
    #[test]
    fn test_correct_string_passes() {
        let (env, client) = setup();
        let caller = String::from_str(&env, "admin_key");
        client.set_config(&caller, &42);
        assert_eq!(client.get_config(), 42);
    }

    /// Any party that knows the string can act as admin — no key ownership proven.
    #[test]
    fn test_any_matching_string_passes_no_real_auth() {
        let (env, client) = setup();
        // Attacker just needs to know the string value — no cryptographic proof.
        let attacker_string = String::from_str(&env, "admin_key");
        client.set_config(&attacker_string, &999);
        assert_eq!(client.get_config(), 999);
    }

    /// Wrong string is rejected — but this is the only protection, which is weak.
    #[test]
    #[should_panic]
    fn test_wrong_string_rejected() {
        let (env, client) = setup();
        let wrong = String::from_str(&env, "not_admin");
        client.set_config(&wrong, &1);
    }

    /// Secure version requires a real Address and cryptographic require_auth.
    #[test]
    fn test_secure_version_uses_require_auth() {
        use soroban_sdk::testutils::Address as _;
        use soroban_sdk::Address;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureConfig);
        let client = secure::SecureConfigClient::new(&env, &id);

        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);
        client.set_config(&admin, &77);
        assert_eq!(client.get_config(), 77);
    }
}
