//! VULNERABLE: Unbounded Vec Growth (DoS Vector)
//!
//! A contract that appends items to a Vec in persistent storage with no size
//! cap. A malicious caller can submit thousands of entries, growing the Vec
//! until reads and writes exceed the Soroban instruction limit, bricking the
//! contract for that key.
//!
//! VULNERABILITY: Unbounded `Vec` growth in persistent storage — no length cap.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, String, Vec, Env};

#[contracttype]
pub enum DataKey {
    List,
}

// ── Vulnerable contract ───────────────────────────────────────────────────────

#[contract]
pub struct UnboundedStorage;

#[contractimpl]
impl UnboundedStorage {
    /// VULNERABLE: Appends `item` to the list with no length cap.
    /// Repeated calls grow the Vec indefinitely, increasing read/write cost
    /// proportionally until the contract becomes unusable.
    pub fn append(env: Env, item: String) {
        let key = DataKey::List;
        let mut list: Vec<String> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env));
        // ❌ No length cap — unbounded growth
        list.push_back(item);
        env.storage().persistent().set(&key, &list);
    }

    pub fn list(env: Env) -> Vec<String> {
        env.storage()
            .persistent()
            .get(&DataKey::List)
            .unwrap_or(Vec::new(&env))
    }

    pub fn len(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get::<DataKey, Vec<String>>(&DataKey::List)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

// ── Secure mirror ─────────────────────────────────────────────────────────────

const MAX_HISTORY: u32 = 50;

#[contract]
pub struct BoundedStorage;

#[contractimpl]
impl BoundedStorage {
    /// SECURE: Enforces MAX_HISTORY cap using a ring-buffer eviction strategy.
    /// When the list is full the oldest entry is dropped before appending.
    pub fn append(env: Env, item: String) {
        let key = DataKey::List;
        let mut list: Vec<String> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(Vec::new(&env));
        // ✅ Evict oldest entry when cap is reached
        if list.len() >= MAX_HISTORY {
            list.remove(0);
        }
        list.push_back(item);
        env.storage().persistent().set(&key, &list);
    }

    pub fn list(env: Env) -> Vec<String> {
        env.storage()
            .persistent()
            .get(&DataKey::List)
            .unwrap_or(Vec::new(&env))
    }

    pub fn len(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get::<DataKey, Vec<String>>(&DataKey::List)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Env, String};

    // ── Vulnerable contract tests ─────────────────────────────────────────────

    #[test]
    fn test_normal_append_works() {
        let env = Env::default();
        let id = env.register_contract(None, UnboundedStorage);
        let client = UnboundedStorageClient::new(&env, &id);

        client.append(&String::from_str(&env, "entry-1"));
        client.append(&String::from_str(&env, "entry-2"));

        assert_eq!(client.len(), 2);
    }

    /// Documents that the Vec grows without bound — each append succeeds but
    /// the stored value grows proportionally, increasing future read/write cost.
    #[test]
    fn test_large_number_of_appends_grows_unbounded() {
        let env = Env::default();
        env.budget().reset_unlimited();
        let id = env.register_contract(None, UnboundedStorage);
        let client = UnboundedStorageClient::new(&env, &id);

        let n: u32 = 200;
        for i in 0..n {
            // Pad to a fixed-width string so each entry has uniform size
            let s = if i < 10 {
                String::from_str(&env, "item-00x")
            } else if i < 100 {
                String::from_str(&env, "item-0xx")
            } else {
                String::from_str(&env, "item-xxx")
            };
            client.append(&s);
        }

        // ❌ Vec has grown to N entries — no cap was enforced
        assert_eq!(client.len(), n);
    }

    // ── Secure contract tests ─────────────────────────────────────────────────

    #[test]
    fn test_secure_enforces_max_history_cap() {
        let env = Env::default();
        env.budget().reset_unlimited();
        let id = env.register_contract(None, BoundedStorage);
        let client = BoundedStorageClient::new(&env, &id);

        // Append more entries than MAX_HISTORY
        for _ in 0..(MAX_HISTORY + 20) {
            client.append(&String::from_str(&env, "item"));
        }

        // ✅ Length is capped at MAX_HISTORY regardless of how many were appended
        assert_eq!(client.len(), MAX_HISTORY);
    }
}
