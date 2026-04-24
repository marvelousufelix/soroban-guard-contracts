//! SECURE: M-of-N multisig with ledger-sequence expiry
//!
//! Any of the N signers can propose an action (identified by a 32-byte hash).
//! Each signer approves independently. Once M approvals are recorded the
//! proposal is marked executed. Proposals expire after a configurable number
//! of ledgers, preventing stale approvals from being replayed.
//!
//! SECURITY PROPERTIES:
//! 1. Only initialised signers can propose or approve.
//! 2. Each signer can approve a proposal at most once.
//! 3. Proposals expire after `ttl_ledgers` ledgers (ledger-sequence based).
//! 4. A proposal can only be executed once.
//! 5. Execution requires exactly M approvals.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, Vec};

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Vec<Address> of authorised signers
    Signers,
    /// Approval threshold M
    Threshold,
    /// Ledgers a proposal stays live
    TtlLedgers,
    /// Proposal state keyed by action hash
    Proposal(BytesN<32>),
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct Proposal {
    /// Ledger sequence at which this proposal was created
    pub created_at: u32,
    /// Signers who have approved so far
    pub approvals: Vec<Address>,
    /// Whether execute() has already been called
    pub executed: bool,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct SecureMultisig;

#[contractimpl]
impl SecureMultisig {
    /// One-time initialisation.
    /// `signers` — the N authorised addresses.
    /// `threshold` — M approvals required to execute.
    /// `ttl_ledgers` — how many ledgers a proposal stays open.
    pub fn initialize(env: Env, signers: Vec<Address>, threshold: u32, ttl_ledgers: u32) {
        if env.storage().persistent().has(&DataKey::Signers) {
            panic!("already initialized");
        }
        if threshold == 0 || threshold > signers.len() {
            panic!("invalid threshold");
        }
        env.storage().persistent().set(&DataKey::Signers, &signers);
        env.storage()
            .persistent()
            .set(&DataKey::Threshold, &threshold);
        env.storage()
            .persistent()
            .set(&DataKey::TtlLedgers, &ttl_ledgers);
    }

    /// Any signer can open a new proposal for `action_hash`.
    pub fn propose_action(env: Env, proposer: Address, action_hash: BytesN<32>) {
        proposer.require_auth();
        Self::assert_signer(&env, &proposer);

        if env
            .storage()
            .persistent()
            .has(&DataKey::Proposal(action_hash.clone()))
        {
            panic!("proposal already exists");
        }

        let proposal = Proposal {
            created_at: env.ledger().sequence(),
            approvals: Vec::new(&env),
            executed: false,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(action_hash.clone()), &proposal);

        env.events()
            .publish((symbol_short!("proposed"),), action_hash);
    }

    /// A signer approves an existing, non-expired, non-executed proposal.
    pub fn approve(env: Env, signer: Address, action_hash: BytesN<32>) {
        signer.require_auth();
        Self::assert_signer(&env, &signer);

        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(action_hash.clone()))
            .expect("proposal not found");

        Self::assert_not_expired(&env, &proposal);

        if proposal.executed {
            panic!("already executed");
        }
        if proposal.approvals.contains(&signer) {
            panic!("already approved");
        }

        proposal.approvals.push_back(signer.clone());
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(action_hash.clone()), &proposal);

        env.events()
            .publish((symbol_short!("approved"),), (action_hash, signer));
    }

    /// Execute once M approvals have been collected.
    /// Callable by anyone — the security guarantee comes from the approval count.
    pub fn execute(env: Env, action_hash: BytesN<32>) {
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(action_hash.clone()))
            .expect("proposal not found");

        Self::assert_not_expired(&env, &proposal);

        if proposal.executed {
            panic!("already executed");
        }

        let threshold: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Threshold)
            .expect("not initialized");

        if proposal.approvals.len() < threshold {
            panic!("insufficient approvals");
        }

        proposal.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(action_hash.clone()), &proposal);

        env.events()
            .publish((symbol_short!("executed"),), action_hash);
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    pub fn get_proposal(env: Env, action_hash: BytesN<32>) -> Option<Proposal> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(action_hash))
    }

    pub fn get_signers(env: Env) -> Vec<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::Signers)
            .expect("not initialized")
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn assert_signer(env: &Env, addr: &Address) {
        let signers: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Signers)
            .expect("not initialized");
        if !signers.contains(addr) {
            panic!("not a signer");
        }
    }

    fn assert_not_expired(env: &Env, proposal: &Proposal) {
        let ttl: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::TtlLedgers)
            .expect("not initialized");
        if env.ledger().sequence() > proposal.created_at + ttl {
            panic!("proposal expired");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Vec};

    const TTL: u32 = 100;
    const THRESHOLD: u32 = 2;

    fn setup(env: &Env) -> (SecureMultisigClient, Address, Address, Address) {
        let contract_id = env.register_contract(None, SecureMultisig);
        let client = SecureMultisigClient::new(env, &contract_id);

        let s1 = Address::generate(env);
        let s2 = Address::generate(env);
        let s3 = Address::generate(env);

        let mut signers = Vec::new(env);
        signers.push_back(s1.clone());
        signers.push_back(s2.clone());
        signers.push_back(s3.clone());

        env.mock_all_auths();
        client.initialize(&signers, &THRESHOLD, &TTL);

        (client, s1, s2, s3)
    }

    fn action(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &[1u8; 32])
    }

    /// M approvals triggers execution.
    #[test]
    fn test_m_approvals_executes() {
        let env = Env::default();
        let (client, s1, s2, _s3) = setup(&env);
        let hash = action(&env);

        client.propose_action(&s1, &hash);
        client.approve(&s1, &hash);
        client.approve(&s2, &hash);
        client.execute(&hash); // should succeed

        let proposal = client.get_proposal(&hash).unwrap();
        assert!(proposal.executed);
    }

    /// M-1 approvals does not trigger execution.
    #[test]
    #[should_panic(expected = "insufficient approvals")]
    fn test_m_minus_1_approvals_cannot_execute() {
        let env = Env::default();
        let (client, s1, _s2, _s3) = setup(&env);
        let hash = action(&env);

        client.propose_action(&s1, &hash);
        client.approve(&s1, &hash); // only 1 of 2 required
        client.execute(&hash);
    }

    /// Non-signer cannot approve.
    #[test]
    #[should_panic(expected = "not a signer")]
    fn test_non_signer_cannot_approve() {
        let env = Env::default();
        let (client, s1, _s2, _s3) = setup(&env);
        let hash = action(&env);
        let outsider = Address::generate(&env);

        client.propose_action(&s1, &hash);
        client.approve(&outsider, &hash);
    }

    /// Expired proposal cannot be executed.
    #[test]
    #[should_panic(expected = "proposal expired")]
    fn test_expired_proposal_cannot_execute() {
        let env = Env::default();
        let (client, s1, s2, _s3) = setup(&env);
        let hash = action(&env);

        client.propose_action(&s1, &hash);
        client.approve(&s1, &hash);
        client.approve(&s2, &hash);

        // Advance ledger past TTL
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + TTL + 1);

        client.execute(&hash);
    }

    /// Expired proposal cannot even be approved.
    #[test]
    #[should_panic(expected = "proposal expired")]
    fn test_expired_proposal_cannot_be_approved() {
        let env = Env::default();
        let (client, s1, s2, _s3) = setup(&env);
        let hash = action(&env);

        client.propose_action(&s1, &hash);

        env.ledger()
            .set_sequence_number(env.ledger().sequence() + TTL + 1);

        client.approve(&s2, &hash);
    }

    /// A signer cannot approve the same proposal twice.
    #[test]
    #[should_panic(expected = "already approved")]
    fn test_double_approve_rejected() {
        let env = Env::default();
        let (client, s1, _s2, _s3) = setup(&env);
        let hash = action(&env);

        client.propose_action(&s1, &hash);
        client.approve(&s1, &hash);
        client.approve(&s1, &hash);
    }

    /// Executed proposal cannot be executed again.
    #[test]
    #[should_panic(expected = "already executed")]
    fn test_double_execute_rejected() {
        let env = Env::default();
        let (client, s1, s2, _s3) = setup(&env);
        let hash = action(&env);

        client.propose_action(&s1, &hash);
        client.approve(&s1, &hash);
        client.approve(&s2, &hash);
        client.execute(&hash);
        client.execute(&hash);
    }
}
