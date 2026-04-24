//! On-chain Scan Result Registry
//!
//! Stores scan findings submitted by verified scanners, keyed by the scanned
//! contract address. Supports full history per contract.
//!
//! Auth model:
//! - Only the admin can add/remove scanners.
//! - `submit_scan` requires the caller to pass their own `scanner` address and
//!   have signed the transaction (`scanner.require_auth()`). The address is
//!   then checked against the approved-scanner registry.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Map, String, Vec};

// ── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct ScanResult {
    pub scanner: Address,
    pub timestamp: u64,
    pub findings_hash: String,
    /// e.g. {"critical": 1, "high": 2, "medium": 0, "low": 3}
    pub severity_counts: Map<String, u32>,
}

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    /// true = approved, false / absent = not approved
    Scanner(Address),
    /// Most recent scan result for a contract address
    LatestScan(Address),
    /// Full ordered history of scan results for a contract address
    ScanHistory(Address),
    /// Reputation score for a scanner address (i32, default 0)
    ScannerScore(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct ScanRegistry;

#[contractimpl]
impl ScanRegistry {
    // ── Initialisation ───────────────────────────────────────────────────────

    /// Initialize the registry with an admin address.
    ///
    /// # Panics
    /// Panics if the registry has already been initialized.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    // ── Scanner management (admin only) ──────────────────────────────────────

    /// Add a scanner to the approved list.
    ///
    /// # Arguments
    /// * `scanner` - The address to approve for submitting scans.
    ///
    /// # Panics
    /// Panics if the caller is not the admin.
    ///
    /// # Events
    /// Emits `("scanner", "added", scanner)`.
    pub fn add_scanner(env: Env, scanner: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Scanner(scanner.clone()), &true);
        env.events()
            .publish((symbol_short!("scanner"), symbol_short!("added")), scanner);
    }

    /// Remove a scanner from the approved list.
    ///
    /// # Arguments
    /// * `scanner` - The address to remove from the approved list.
    ///
    /// # Panics
    /// Panics if the caller is not the admin.
    ///
    /// # Events
    /// Emits `("scanner", "removed", scanner)`.
    pub fn remove_scanner(env: Env, scanner: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Scanner(scanner.clone()), &false);
        env.events()
            .publish((symbol_short!("scanner"), symbol_short!("removed")), scanner);
    }

    /// Check whether an address is an approved scanner.
    ///
    /// # Arguments
    /// * `scanner` - The address to check.
    ///
    /// # Returns
    /// `true` if the scanner is approved, `false` otherwise.
    pub fn is_scanner(env: Env, scanner: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Scanner(scanner))
            .unwrap_or(false)
    }

    // ── Scan submission ──────────────────────────────────────────────────────

    /// Submit a scan result for `contract_address`.
    ///
    /// `scanner` must be a verified scanner address and must have signed this
    /// transaction. `findings_hash` is a hex-encoded SHA-256 of the full
    /// findings JSON. `severity_counts` maps severity labels to counts.
    ///
    /// # Events
    /// Emits `("scan", "submitted", (scanner, contract_address, findings_hash))`.
    pub fn submit_scan(
        env: Env,
        scanner: Address,
        contract_address: Address,
        findings_hash: String,
        severity_counts: Map<String, u32>,
    ) {
        // 1. The scanner must have signed this transaction.
        scanner.require_auth();

        // 2. The scanner must be in the approved list.
        let approved: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Scanner(scanner.clone()))
            .unwrap_or(false);
        if !approved {
            panic!("not a verified scanner");
        }

        // Keep a copy for the score key before scanner is moved into ScanResult.
        let score_key = DataKey::ScannerScore(scanner.clone());

        let result = ScanResult {
            scanner: scanner.clone(),
            timestamp: env.ledger().timestamp(),
            findings_hash: findings_hash.clone(),
            severity_counts,
        };

        // Overwrite latest result.
        env.storage()
            .persistent()
            .set(&DataKey::LatestScan(contract_address.clone()), &result);

        // Append to history.
        let history_key = DataKey::ScanHistory(contract_address.clone());
        let mut history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&history_key)
            .unwrap_or(Vec::new(&env));
        history.push_back(result);
        env.storage().persistent().set(&history_key, &history);

        // Increment scanner reputation score.
        let score: i32 = env
            .storage()
            .persistent()
            .get(&score_key)
            .unwrap_or(0i32);
        env.storage()
            .persistent()
            .set(&score_key, &score.saturating_add(1));
    }

    // ── Reputation ───────────────────────────────────────────────────────────

    /// Dispute a scanner's submission (admin only), decrementing their score by 1.
    ///
    /// # Arguments
    /// * `scanner` - The scanner whose score should be decremented.
    ///
    /// # Panics
    /// Panics if the caller is not the admin.
    pub fn dispute_scan(env: Env, scanner: Address) {
        Self::require_admin(&env);
        let score_key = DataKey::ScannerScore(scanner);
        let score: i32 = env
            .storage()
            .persistent()
            .get(&score_key)
            .unwrap_or(0i32);
        env.storage()
            .persistent()
            .set(&score_key, &score.saturating_sub(1));
    }

    /// Return the reputation score for a scanner (defaults to 0).
    ///
    /// # Arguments
    /// * `scanner` - The scanner address to query.
    pub fn get_scanner_score(env: Env, scanner: Address) -> i32 {
        env.storage()
            .persistent()
            .get(&DataKey::ScannerScore(scanner))
            .unwrap_or(0i32)
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    /// Retrieve the latest scan result for a contract address.
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to look up.
    ///
    /// # Returns
    /// The most recent `ScanResult`, or `None` if no scan exists.
    pub fn get_scan(env: Env, contract_address: Address) -> Option<ScanResult> {
        env.storage()
            .persistent()
            .get(&DataKey::LatestScan(contract_address))
    }

    /// Retrieve the full scan history for a contract address.
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to look up.
    ///
    /// # Returns
    /// A vector of all `ScanResult`s submitted for this contract, ordered oldest
    /// to newest.
    pub fn get_history(env: Env, contract_address: Address) -> Vec<ScanResult> {
        env.storage()
            .persistent()
            .get(&DataKey::ScanHistory(contract_address))
            .unwrap_or(Vec::new(&env))
    }

    /// Return the total number of scan results stored for a contract address.
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to look up.
    ///
    /// # Returns
    /// The number of `ScanResult`s in the history (0 if none).
    pub fn get_history_len(env: Env, contract_address: Address) -> u32 {
        let history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&DataKey::ScanHistory(contract_address))
            .unwrap_or(Vec::new(&env));
        history.len()
    }

    /// Retrieve a single page of scan history for a contract address.
    ///
    /// Results are ordered oldest to newest. Pages are zero-indexed.
    /// If `page * page_size` is beyond the end of the history, an empty
    /// vector is returned.
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to look up.
    /// * `page`             - Zero-based page index.
    /// * `page_size`        - Number of results per page. Must be > 0.
    ///
    /// # Panics
    /// Panics if `page_size` is 0.
    pub fn get_history_page(
        env: Env,
        contract_address: Address,
        page: u32,
        page_size: u32,
    ) -> Vec<ScanResult> {
        if page_size == 0 {
            panic!("page_size must be greater than zero");
        }

        let history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&DataKey::ScanHistory(contract_address))
            .unwrap_or(Vec::new(&env));

        let total = history.len();
        let start = page.saturating_mul(page_size);

        if start >= total {
            return Vec::new(&env);
        }

        let end = (start + page_size).min(total);
        let mut page_results: Vec<ScanResult> = Vec::new(&env);
        for i in start..end {
            page_results.push_back(history.get(i).unwrap());
        }
        page_results
    }

    /// Return the admin address of the registry.
    ///
    /// # Returns
    /// The admin `Address`.
    ///
    /// # Panics
    /// Panics if the registry has not been initialized.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{map, testutils::Address as _, testutils::Events, Address, Env, String};

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, ScanRegistry);
        let admin = Address::generate(&env);
        let scanner = Address::generate(&env);
        env.mock_all_auths();
        ScanRegistryClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, admin, scanner)
    }

    #[test]
    fn test_add_scanner_and_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let hash = String::from_str(&env, "abc123");
        let counts: Map<String, u32> = map![
            &env,
            (String::from_str(&env, "critical"), 1u32),
            (String::from_str(&env, "high"), 2u32)
        ];

        client.add_scanner(&scanner);
        assert!(client.is_scanner(&scanner));

        client.submit_scan(&scanner, &target, &hash, &counts);

        let result = client.get_scan(&target).unwrap();
        assert_eq!(result.scanner, scanner);
        assert_eq!(result.findings_hash, hash);
    }

    #[test]
    fn test_get_history_accumulates() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 1u32)];

        client.add_scanner(&scanner);

        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash1"), &counts);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash2"), &counts);

        let history = client.get_history(&target);
        assert_eq!(history.len(), 2);
        assert_eq!(
            history.get(0).unwrap().findings_hash,
            String::from_str(&env, "hash1")
        );
        assert_eq!(
            history.get(1).unwrap().findings_hash,
            String::from_str(&env, "hash2")
        );
    }

    /// Unregistered address cannot submit scans.
    #[test]
    #[should_panic]
    fn test_unverified_scanner_cannot_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        // scanner was never added — should panic.
        client.submit_scan(
            &scanner,
            &target,
            &String::from_str(&env, "badhash"),
            &counts,
        );
    }

    #[test]
    #[should_panic]
    fn test_remove_scanner_blocks_submission() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        client.add_scanner(&scanner);
        client.remove_scanner(&scanner);

        assert!(!client.is_scanner(&scanner));

        // Attempting to submit after removal should panic.
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash"), &counts);
    }

    // ── Reputation tests ─────────────────────────────────────────────────────

    #[test]
    fn test_score_starts_at_zero() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        assert_eq!(client.get_scanner_score(&scanner), 0);
    }

    #[test]
    fn test_score_increments_on_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h1"), &counts);
        assert_eq!(client.get_scanner_score(&scanner), 1);

        client.submit_scan(&scanner, &target, &String::from_str(&env, "h2"), &counts);
        assert_eq!(client.get_scanner_score(&scanner), 2);
    }

    #[test]
    fn test_score_decrements_on_admin_dispute() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h1"), &counts);
        assert_eq!(client.get_scanner_score(&scanner), 1);

        client.dispute_scan(&scanner);
        assert_eq!(client.get_scanner_score(&scanner), 0);
    }

    // ── Pagination tests ──────────────────────────────────────────────────────

    fn submit_n_scans(client: &ScanRegistryClient, scanner: &Address, target: &Address, n: u32, env: &Env) {
        // Pre-defined hash labels — supports up to 8 scans in tests.
        let hashes = ["hash0", "hash1", "hash2", "hash3", "hash4", "hash5", "hash6", "hash7"];
        let counts: Map<String, u32> = map![env, (String::from_str(env, "low"), 0u32)];
        for i in 0..n {
            let hash = String::from_str(env, hashes[i as usize]);
            client.submit_scan(scanner, target, &hash, &counts);
        }
    }

    #[test]
    fn test_pagination_page_zero_works() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 5, &env);

        let page = client.get_history_page(&target, &0, &3);
        assert_eq!(page.len(), 3);
        assert_eq!(page.get(0).unwrap().findings_hash, String::from_str(&env, "hash0"));
        assert_eq!(page.get(2).unwrap().findings_hash, String::from_str(&env, "hash2"));
    }

    #[test]
    fn test_pagination_last_page_partial() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 5, &env);

        // page 1 with page_size 3 → items [3, 4] (2 items)
        let page = client.get_history_page(&target, &1, &3);
        assert_eq!(page.len(), 2);
        assert_eq!(page.get(0).unwrap().findings_hash, String::from_str(&env, "hash3"));
        assert_eq!(page.get(1).unwrap().findings_hash, String::from_str(&env, "hash4"));
    }

    #[test]
    fn test_pagination_out_of_range_returns_empty() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 3, &env);

        // page 5 is well beyond the 3 items
        let page = client.get_history_page(&target, &5, &3);
        assert_eq!(page.len(), 0);
    }

    #[test]
    #[should_panic(expected = "page_size must be greater than zero")]
    fn test_pagination_page_size_zero_panics() {
        let (env, contract_id, _admin, _scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);
        client.get_history_page(&target, &0, &0);
    }

    #[test]
    fn test_get_history_len() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        assert_eq!(client.get_history_len(&target), 0);

        submit_n_scans(&client, &scanner, &target, 4, &env);
        assert_eq!(client.get_history_len(&target), 4);
    }

    #[test]
    #[should_panic]
    fn test_non_admin_cannot_dispute() {
        // Use a fresh env with no mocked auths so require_auth panics.
        let env = Env::default();
        let contract_id = env.register_contract(None, ScanRegistry);
        let admin = Address::generate(&env);
        let scanner = Address::generate(&env);

        env.mock_all_auths();
        ScanRegistryClient::new(&env, &contract_id).initialize(&admin);

        // Clear all mocks — no auth is satisfied from here on.
        env.mock_auths(&[]);

        // admin.require_auth() inside dispute_scan is not satisfied → panic.
        ScanRegistryClient::new(&env, &contract_id).dispute_scan(&scanner);
    }
}
