//! SECURE: Replay Attack — Nonce Tracking
//!
//! The signature hash is used as the nonce key. After the first successful
//! execution the nonce is marked as used; any replay panics immediately.

#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env};
use super::{DataKey, execute_payload, verify_signature};

#[contract]
pub struct SecureSignedExecutor;

#[contractimpl]
impl SecureSignedExecutor {
    /// SECURE: verifies the signature, asserts the nonce has not been used,
    /// marks it as used, then executes the payload.
    pub fn execute_signed(env: Env, payload: Bytes, signature: BytesN<32>) {
        verify_signature(&env, &payload, &signature);

        // ✅ Reject replays: the signature hash serves as the nonce.
        let nonce_key = DataKey::NonceUsed(signature.clone());
        if env.storage().persistent().get::<_, bool>(&nonce_key).unwrap_or(false) {
            panic!("already used");
        }
        env.storage().persistent().set(&nonce_key, &true);

        let count_key = DataKey::ExecCount(payload.clone());
        let count: u32 = env.storage().persistent().get(&count_key).unwrap_or(0);
        env.storage().persistent().set(&count_key, &(count + 1));

        execute_payload(&env, &payload);
    }

    pub fn exec_count(env: Env, payload: Bytes) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ExecCount(payload))
            .unwrap_or(0)
    }
}
