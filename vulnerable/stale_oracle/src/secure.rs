//! SECURE mirror: enforce a maximum staleness window on the oracle price.
//!
//! `get_collateral_value` panics if the oracle's `last_updated` timestamp is
//! older than `MAX_STALENESS` seconds, preventing the contract from operating
//! on stale data.

use crate::{DataKey, oracle::MockOracleClient};
use soroban_sdk::{contract, contractimpl, Address, Env};

/// Maximum allowed age of an oracle price (in seconds).
const MAX_STALENESS: u64 = 300;

#[contract]
pub struct SecureLending;

#[contractimpl]
impl SecureLending {
    pub fn init(env: Env, oracle_id: Address) {
        if env.storage().persistent().has(&DataKey::OracleId) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::OracleId, &oracle_id);
    }

    pub fn deposit_collateral(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Collateral(user);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&key, &(current + amount));
    }

    /// ✅ Rejects the price if it is older than MAX_STALENESS.
    pub fn get_collateral_value(env: Env, user: Address) -> i128 {
        let oracle_id: Address = env
            .storage()
            .persistent()
            .get(&DataKey::OracleId)
            .unwrap();
        let oracle = MockOracleClient::new(&env, &oracle_id);
        let price = oracle.get_price();
        let last_updated: u64 = oracle.last_updated();

        let now = env.ledger().timestamp();
        assert!(
            now.saturating_sub(last_updated) <= MAX_STALENESS,
            "price too stale"
        );

        let collateral: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user))
            .unwrap_or(0);
        collateral * price
    }
}
