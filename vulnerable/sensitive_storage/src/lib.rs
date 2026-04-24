//! VULNERABLE: Sensitive data stored in persistent storage.
//!
//! A contract that stores a raw secret key in Soroban persistent storage.
//! All ledger state is public on Stellar — any observer can read the value
//! directly from ledger state without invoking the contract.
//!
//! VULNERABILITY: `initialize()` writes raw secret material to persistent
//! storage, exposing it to anyone who can read the ledger.
//!
//! SECURE MIRROR: store only a SHA-256 hash commitment on-chain; keep the
//! raw secret in off-chain key management infrastructure.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    SecretKey,
    Commitment,
}

#[contract]
pub struct SensitiveStorageContract;

#[contractimpl]
impl SensitiveStorageContract {
    /// VULNERABLE: stores the raw secret_key in persistent storage.
    /// Any observer can read DataKey::SecretKey directly from ledger state.
    pub fn initialize(env: Env, admin: Address, secret_key: Bytes) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        // ❌ Raw secret written to public ledger state — readable by anyone
        env.storage()
            .persistent()
            .set(&DataKey::SecretKey, &secret_key);
    }

    /// Any caller can retrieve the secret — no auth required because the
    /// ledger is already public; this just makes the exposure explicit.
    pub fn get_secret(env: Env) -> Bytes {
        env.storage()
            .persistent()
            .get(&DataKey::SecretKey)
            .unwrap()
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap()
    }

    // -------------------------------------------------------------------------
    // Secure mirror — stores only a hash commitment, never the raw secret.
    // -------------------------------------------------------------------------

    /// SECURE: stores a hash commitment instead of the raw secret.
    pub fn initialize_secure(env: Env, admin: Address, secret_hash: Bytes) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        // ✅ Only the hash is stored — the raw secret never touches the ledger
        env.storage()
            .persistent()
            .set(&DataKey::Commitment, &secret_hash);
    }

    pub fn get_commitment(env: Env) -> Bytes {
        env.storage()
            .persistent()
            .get(&DataKey::Commitment)
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

    #[test]
    fn test_secret_readable_after_initialize() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SensitiveStorageContract);
        let client = SensitiveStorageContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let secret = Bytes::from_slice(&env, b"super-secret-api-key-12345");

        client.initialize(&admin, &secret);

        // Secret is readable by anyone — no auth needed
        let stored = client.get_secret();
        assert_eq!(stored, secret);
    }

    #[test]
    fn test_any_address_can_read_secret() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SensitiveStorageContract);
        let client = SensitiveStorageContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let _attacker = Address::generate(&env);
        let secret = Bytes::from_slice(&env, b"private-key-material");

        client.initialize(&admin, &secret);

        // No auth mock needed — get_secret has no access control
        let stolen = client.get_secret();
        assert_eq!(stolen, secret);
    }

    #[test]
    fn test_secure_stores_only_commitment() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SensitiveStorageContract);
        let client = SensitiveStorageContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        // Simulate a SHA-256 hash (32 bytes) — raw secret never sent on-chain
        let hash = Bytes::from_slice(&env, &[0xab_u8; 32]);

        client.initialize_secure(&admin, &hash);

        let stored_commitment = client.get_commitment();
        assert_eq!(stored_commitment, hash);
        // Raw secret is never stored — DataKey::SecretKey is absent
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::SecretKey));
    }
}
