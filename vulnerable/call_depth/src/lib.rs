//! VULNERABLE: No cross-contract call depth guard.
//!
//! Soroban enforces a maximum cross-contract call depth. A contract that
//! recursively calls itself without tracking depth will panic at the host
//! limit mid-execution, potentially leaving state partially updated.
//!
//! VULNERABILITY: `process()` recurses via a cross-contract client with no
//! depth check. An attacker can craft a depth value that hits the Soroban
//! call depth limit at a critical point, causing a panic.
//!
//! SECURE MIRROR: `process_safe()` rejects calls that would exceed
//! MAX_DEPTH before any state mutation occurs.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

/// Safe recursion threshold — well below Soroban's host limit.
pub const MAX_DEPTH: u32 = 10;

#[contracttype]
pub enum DataKey {
    Processed,
    ProcessedCount,
}

#[contract]
pub struct CallDepthContract;

#[contractimpl]
impl CallDepthContract {
    /// VULNERABLE: recurses via cross-contract call with no depth guard.
    /// Will panic at the Soroban call depth limit mid-execution; any state
    /// updates below the recursive call may never be reached.
    pub fn process(env: Env, contract_id: Address, depth: u32) {
        // ❌ No depth check — will hit Soroban call depth limit and panic
        if depth > 0 {
            CallDepthContractClient::new(&env, &contract_id)
                .process(&contract_id, &(depth - 1));
        }
        // State update here may never be reached if depth limit is hit above
        env.storage()
            .persistent()
            .set(&DataKey::Processed, &true);
        let count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProcessedCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::ProcessedCount, &(count + 1));
    }

    /// SECURE: rejects depth values that would exceed MAX_DEPTH before any
    /// recursive call or state mutation.
    pub fn process_safe(env: Env, contract_id: Address, depth: u32) {
        // ✅ Explicit depth guard — panics with a clear message before recursing
        assert!(depth <= MAX_DEPTH, "call depth exceeds safe threshold");
        if depth > 0 {
            CallDepthContractClient::new(&env, &contract_id)
                .process_safe(&contract_id, &(depth - 1));
        }
        env.storage()
            .persistent()
            .set(&DataKey::Processed, &true);
        let count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProcessedCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::ProcessedCount, &(count + 1));
    }

    pub fn is_processed(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Processed)
            .unwrap_or(false)
    }

    pub fn processed_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ProcessedCount)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Env};

    #[test]
    fn test_shallow_recursion_completes() {
        let env = Env::default();
        let contract_id = env.register_contract(None, CallDepthContract);
        let client = CallDepthContractClient::new(&env, &contract_id);

        // depth=0 — no recursion, just sets state
        client.process(&contract_id, &0);
        assert!(client.is_processed());
    }

    #[test]
    #[should_panic]
    fn test_deep_recursion_hits_call_depth_limit() {
        let env = Env::default();
        let contract_id = env.register_contract(None, CallDepthContract);
        let client = CallDepthContractClient::new(&env, &contract_id);

        // Large depth — will exceed Soroban's cross-contract call depth limit
        client.process(&contract_id, &64);
    }

    #[test]
    fn test_secure_shallow_recursion_completes() {
        let env = Env::default();
        let contract_id = env.register_contract(None, CallDepthContract);
        let client = CallDepthContractClient::new(&env, &contract_id);

        client.process_safe(&contract_id, &5);
        assert!(client.is_processed());
    }

    #[test]
    #[should_panic(expected = "call depth exceeds safe threshold")]
    fn test_secure_rejects_depth_above_max() {
        let env = Env::default();
        let contract_id = env.register_contract(None, CallDepthContract);
        let client = CallDepthContractClient::new(&env, &contract_id);

        client.process_safe(&contract_id, &(MAX_DEPTH + 1));
    }
}
