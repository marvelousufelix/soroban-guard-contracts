//! Mock Oracle contract for testing.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum OracleDataKey {
    Admin,
    Price,
    LastUpdated,
}

#[contract]
pub struct MockOracle;

#[contractimpl]
impl MockOracle {
    pub fn init(env: Env, admin: Address) {
        if env.storage().persistent().has(&OracleDataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&OracleDataKey::Admin, &admin);
    }

    pub fn set_price(env: Env, price: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&OracleDataKey::Admin)
            .unwrap();
        admin.require_auth();
        env.storage().persistent().set(&OracleDataKey::Price, &price);
        let now = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&OracleDataKey::LastUpdated, &now);
    }

    pub fn get_price(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&OracleDataKey::Price)
            .unwrap_or(0)
    }

    pub fn last_updated(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&OracleDataKey::LastUpdated)
            .unwrap_or(0)
    }
}
