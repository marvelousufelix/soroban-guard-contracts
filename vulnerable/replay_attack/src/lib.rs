//! VULNERABLE: Replay Attack — Missing Nonce / Signature Reuse
//!
//! A contract that verifies an off-chain signature over a payload but never
//! records that the signature was used. The same valid signature can be
//! submitted repeatedly, executing the authorised action multiple times.
//!
//! VULNERABILITY: `execute_signed()` calls `verify_signature()` but stores no
//! nonce, so an attacker can replay the same `(payload, signature)` pair
//! indefinitely.
//!
//! SECURE MIRROR: `secure::SecureSignedExecutor` embeds a nonce inside the
//! signed payload and marks each nonce as used after the first execution,
//! causing any replay to panic.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Bytes, BytesN, Env};

pub mod secure;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Simulated off-chain signature: SHA-256 of the raw payload bytes.
/// In production this would be an ed25519 signature; using a hash keeps the
/// test environment simple while still demonstrating the replay pattern.
pub fn verify_signature(env: &Env, payload: &Bytes, signature: &BytesN<32>) {
    let expected = env.crypto().sha256(payload);
    if expected != *signature {
        panic!("invalid signature");
    }
}

pub(crate) fn execute_payload(env: &Env, payload: &Bytes) {
    env.events()
        .publish((symbol_short!("executed"),), payload.clone());
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// Tracks how many times a payload has been executed (for test assertions).
    ExecCount(Bytes),
    /// Nonce-used flag (only used by the secure contract).
    NonceUsed(BytesN<32>),
}

#[contract]
pub struct VulnerableSignedExecutor;

#[contractimpl]
impl VulnerableSignedExecutor {
    /// VULNERABLE: verifies the signature but never records it was used.
    /// The same `(payload, signature)` pair can be replayed indefinitely.
    pub fn execute_signed(env: Env, payload: Bytes, signature: BytesN<32>) {
        verify_signature(&env, &payload, &signature);

        // ❌ Missing: assert nonce not already used, then mark as used.

        let key = DataKey::ExecCount(payload.clone());
        let count: u32 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(count + 1));

        execute_payload(&env, &payload);
    }

    pub fn exec_count(env: Env, payload: Bytes) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ExecCount(payload))
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Bytes, Env};

    fn make_sig(env: &Env, payload: &Bytes) -> BytesN<32> {
        env.crypto().sha256(payload)
    }

    // --- Vulnerable contract tests ---

    #[test]
    fn test_first_execution_succeeds() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableSignedExecutor);
        let client = VulnerableSignedExecutorClient::new(&env, &id);

        let payload = Bytes::from_slice(&env, b"pay:alice:100");
        let sig = make_sig(&env, &payload);

        client.execute_signed(&payload, &sig);
        assert_eq!(client.exec_count(&payload), 1);
    }

    #[test]
    fn test_replay_succeeds_on_vulnerable_contract() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableSignedExecutor);
        let client = VulnerableSignedExecutorClient::new(&env, &id);

        let payload = Bytes::from_slice(&env, b"pay:alice:100");
        let sig = make_sig(&env, &payload);

        // First execution
        client.execute_signed(&payload, &sig);
        // Replay with the exact same signature — succeeds (demonstrates vulnerability)
        client.execute_signed(&payload, &sig);

        assert_eq!(client.exec_count(&payload), 2);
    }

    // --- Secure contract tests ---

    #[test]
    fn test_secure_first_execution_succeeds() {
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureSignedExecutor);
        let client = secure::SecureSignedExecutorClient::new(&env, &id);

        let payload = Bytes::from_slice(&env, b"pay:alice:100");
        let sig = make_sig(&env, &payload);

        client.execute_signed(&payload, &sig);
        assert_eq!(client.exec_count(&payload), 1);
    }

    #[test]
    #[should_panic(expected = "already used")]
    fn test_secure_replay_is_rejected() {
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureSignedExecutor);
        let client = secure::SecureSignedExecutorClient::new(&env, &id);

        let payload = Bytes::from_slice(&env, b"pay:alice:100");
        let sig = make_sig(&env, &payload);

        client.execute_signed(&payload, &sig);
        // Replay — must panic
        client.execute_signed(&payload, &sig);
    }
}
