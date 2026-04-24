//! VULNERABLE: Negative Transfer Amount Not Validated
//!
//! A token contract where `transfer()` accepts negative `amount` values.
//! A negative amount reverses the transfer direction — the sender receives
//! tokens from the recipient instead of sending them.
//!
//! VULNERABILITY: Missing `assert!(amount > 0)` guard before balance mutation.
//! SECURE MIRROR: `secure::SecureTokenContract` rejects `amount <= 0`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

pub fn get_balance(env: &Env, account: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(account.clone()))
        .unwrap_or(0)
}

pub fn set_balance(env: &Env, account: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(account.clone()), &amount);
}

#[contract]
pub struct TokenContract;

#[contractimpl]
impl TokenContract {
    pub fn mint(env: Env, to: Address, amount: i128) {
        set_balance(&env, &to, get_balance(&env, &to) + amount);
    }

    /// VULNERABLE: `amount` is never checked to be positive.
    /// Passing a negative value causes `from` to gain tokens and `to` to lose them.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        // ❌ Missing: assert!(amount > 0, "amount must be positive");
        set_balance(&env, &from, get_balance(&env, &from) - amount);
        set_balance(&env, &to, get_balance(&env, &to) + amount);
        env.events()
            .publish((symbol_short!("transfer"),), (from, to, amount));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_positive_transfer_works() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &1000);
        client.transfer(&alice, &bob, &400);

        assert_eq!(client.balance(&alice), 600);
        assert_eq!(client.balance(&bob), 400);
    }

    /// Demonstrates the vulnerability: a negative amount causes the sender
    /// to receive tokens from the recipient instead of sending them.
    #[test]
    fn test_negative_amount_reverses_transfer() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &500);
        client.mint(&bob, &500);

        // Alice "transfers" -200 to bob — she actually receives 200 from bob.
        client.transfer(&alice, &bob, &-200);

        assert_eq!(client.balance(&alice), 700); // gained 200
        assert_eq!(client.balance(&bob), 300);   // lost 200
    }

    #[test]
    fn test_secure_rejects_negative_amount() {
        use crate::secure::SecureTokenContractClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureTokenContract);
        let client = SecureTokenContractClient::new(&env, &id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &500);
        client.mint(&bob, &500);

        let result = client.try_transfer(&alice, &bob, &-200);
        assert!(result.is_err());

        assert_eq!(client.balance(&alice), 500);
        assert_eq!(client.balance(&bob), 500);
    }

    #[test]
    fn test_secure_rejects_zero_amount() {
        use crate::secure::SecureTokenContractClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureTokenContract);
        let client = SecureTokenContractClient::new(&env, &id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &500);

        let result = client.try_transfer(&alice, &bob, &0);
        assert!(result.is_err());
    }
}
