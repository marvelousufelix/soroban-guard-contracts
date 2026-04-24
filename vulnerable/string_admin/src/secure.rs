use soroban_sdk::{contract, contractimpl, Address, Env};
use super::DataKey;

#[contract]
pub struct SecureConfig;

#[contractimpl]
impl SecureConfig {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// SECURE: admin is stored as Address and require_auth enforces
    /// cryptographic signature verification — string spoofing is impossible.
    pub fn set_config(env: Env, caller: Address, new_value: u32) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        // ✅ Cryptographic auth — caller must prove key ownership.
        if caller != admin {
            panic!("not admin");
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Config, &new_value);
    }

    pub fn get_config(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Config)
            .unwrap_or(0)
    }
}
