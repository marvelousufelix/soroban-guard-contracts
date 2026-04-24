//! VULNERABLE: Stale Oracle Price
//!
//! A lending contract that reads a price from an on-chain oracle and uses it
//! for collateral valuation, but never checks whether the oracle's price was
//! updated recently. A liquidation or borrowing contract relying on stale data
//! can be manipulated by an attacker who exploits an old price.
//!
//! VULNERABILITY: No staleness check on the oracle's `last_updated` timestamp.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod oracle;
pub mod secure;

use oracle::MockOracleClient;

// ── Vulnerable Lending Contract ───────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    OracleId,
    Collateral(Address),
}

#[contract]
pub struct VulnerableLending;

#[contractimpl]
impl VulnerableLending {
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

    /// ❌ No staleness check — price could be arbitrarily old.
    pub fn get_collateral_value(env: Env, user: Address) -> i128 {
        let oracle_id: Address = env
            .storage()
            .persistent()
            .get(&DataKey::OracleId)
            .unwrap();
        let price = MockOracleClient::new(&env, &oracle_id).get_price();
        let collateral: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user))
            .unwrap_or(0);
        collateral * price
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, Env};

    fn setup_oracle(env: &Env) -> (MockOracleClient, Address, Address) {
        let id = env.register_contract(None, oracle::MockOracle);
        let client = MockOracleClient::new(env, &id);
        let admin = Address::generate(env);
        env.mock_all_auths();
        client.init(&admin);
        (client, id, admin)
    }

    fn setup_lending<'a>(env: &'a Env, oracle_id: &Address) -> (Address, VulnerableLendingClient<'a>) {
        let id = env.register_contract(None, VulnerableLending);
        let client = VulnerableLendingClient::new(env, &id);
        env.mock_all_auths();
        client.init(oracle_id);
        (id, client)
    }

    /// Fresh price returns correct collateral value.
    #[test]
    fn test_fresh_price_returns_correct_collateral_value() {
        let env = Env::default();
        let (oracle, oracle_id, _admin) = setup_oracle(&env);
        let (_lending_id, lending) = setup_lending(&env, &oracle_id);

        env.mock_all_auths();
        oracle.set_price(&100);
        let user = Address::generate(&env);
        lending.deposit_collateral(&user, &50);

        let value = lending.get_collateral_value(&user);
        assert_eq!(value, 5000); // 50 * 100
    }

    /// Stale price is accepted without error — demonstrates the vulnerability.
    #[test]
    fn test_stale_price_accepted_without_error() {
        let env = Env::default();
        let (oracle, oracle_id, _admin) = setup_oracle(&env);
        let (_lending_id, lending) = setup_lending(&env, &oracle_id);

        env.mock_all_auths();

        // Set price at ledger timestamp 0.
        oracle.set_price(&100);
        let user = Address::generate(&env);
        lending.deposit_collateral(&user, &50);

        // Advance timestamp far into the future (simulate many ledgers passing).
        env.ledger().set_timestamp(1_000_000);

        // The vulnerable contract still uses the ancient price without complaint.
        let value = lending.get_collateral_value(&user);
        assert_eq!(value, 5000);
    }

    // ---- secure mirror tests --------------------------------------------------

    /// Secure version rejects price older than MAX_STALENESS.
    #[test]
    #[should_panic(expected = "price too stale")]
    fn test_secure_rejects_stale_price() {
        use crate::secure::SecureLendingClient;

        let env = Env::default();
        let (oracle, oracle_id, _admin) = setup_oracle(&env);
        let id = env.register_contract(None, secure::SecureLending);
        let lending = SecureLendingClient::new(&env, &id);

        env.mock_all_auths();
        lending.init(&oracle_id);

        oracle.set_price(&100);
        let user = Address::generate(&env);
        lending.deposit_collateral(&user, &50);

        // Advance timestamp beyond MAX_STALENESS (300 seconds).
        env.ledger().set_timestamp(301);

        lending.get_collateral_value(&user);
    }

    /// Secure version works fine with a fresh price.
    #[test]
    fn test_secure_accepts_fresh_price() {
        use crate::secure::SecureLendingClient;

        let env = Env::default();
        let (oracle, oracle_id, _admin) = setup_oracle(&env);
        let id = env.register_contract(None, secure::SecureLending);
        let lending = SecureLendingClient::new(&env, &id);

        env.mock_all_auths();
        lending.init(&oracle_id);

        oracle.set_price(&100);
        let user = Address::generate(&env);
        lending.deposit_collateral(&user, &50);

        let value = lending.get_collateral_value(&user);
        assert_eq!(value, 5000);
    }
}
