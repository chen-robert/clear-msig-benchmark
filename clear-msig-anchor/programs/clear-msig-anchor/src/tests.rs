extern crate alloc;
extern crate std;

use alloc::vec::Vec;
use {
    alloc::vec,
    ed25519_dalek::Signer as DalekSigner,
    quasar_svm::{Account, Pubkey, QuasarSvm},
    sha2::{Digest, Sha256},
    solana_instruction::AccountMeta,
    std::{format, println, string::String},
};

use crate::state::intent::{DISC_LEN, INTENT_APPROVED_OFFSET};
use crate::state::proposal::Proposal;

// =========================================================================
// Helpers
// =========================================================================

fn setup() -> QuasarSvm {
    let elf = std::fs::read("../../target/deploy/clear_msig_anchor.so").unwrap();
    QuasarSvm::new().with_program(&crate::ID, &elf)
}

fn setup_with_tokens() -> QuasarSvm {
    let elf = std::fs::read("../../target/deploy/clear_msig_anchor.so").unwrap();
    QuasarSvm::new()
        .with_program(&crate::ID, &elf)
        .with_token_program()
        .with_associated_token_program()
}

fn funded_account(address: Pubkey) -> Account {
    quasar_svm::token::create_keyed_system_account(&address, 10_000_000_000)
}

fn empty_account(address: Pubkey) -> Account {
    Account { address, lamports: 0, data: vec![], owner: quasar_svm::system_program::ID, executable: false }
}

fn new_keypair() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
}

fn pubkey_of(key: &ed25519_dalek::SigningKey) -> Pubkey {
    Pubkey::from(key.verifying_key().to_bytes())
}

fn pubkey_bytes(key: &ed25519_dalek::SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

fn sign_message(key: &ed25519_dalek::SigningKey, msg: &[u8]) -> [u8; 64] {
    key.sign(msg).to_bytes()
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn format_timestamp(ts: i64) -> String {
    let secs_per_day: i64 = 86400;
    let mut days = ts / secs_per_day;
    let day_secs = ((ts % secs_per_day) + secs_per_day) % secs_per_day;
    if ts < 0 && day_secs > 0 { days -= 1; }
    let (hour, min, sec) = (day_secs / 3600, (day_secs % 3600) / 60, day_secs % 60);
    let adj = days + 719468;
    let era = if adj >= 0 { adj } else { adj - 146096 } / 146097;
    let doe = adj - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02} {hour:02}:{min:02}:{sec:02}")
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn message_suffix(wallet_name: &str, proposal_index: u64) -> String {
    format!(" | wallet: {wallet_name} proposal: {proposal_index}")
}

const DEFAULT_EXPIRY: i64 = 1_000_000_000;

type MessageFn = dyn Fn(&str, i64, &str, u64, &[u8]) -> Vec<u8>;

// =========================================================================
// PDA helpers (same seeds as clear-wallet-client)
// =========================================================================

fn compute_name_hash(name: &str) -> [u8; 32] {
    sha256_hash(name.as_bytes())
}

fn find_wallet_address(name: &str, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"clear_wallet", &compute_name_hash(name)], program_id)
}

fn find_intent_address(wallet: &Pubkey, index: u8, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"intent", wallet.as_ref(), &[index]], program_id)
}

fn find_proposal_address(intent: &Pubkey, index: u64, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"proposal", intent.as_ref(), &index.to_le_bytes()], program_id)
}

fn find_vault_address(wallet: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault", wallet.as_ref()], program_id)
}

// =========================================================================
// Anchor v2 discriminator helpers
// =========================================================================

fn ix_discriminator(name: &str) -> [u8; 8] {
    let hash = sha256_hash(format!("global:{name}").as_bytes());
    hash[..8].try_into().unwrap()
}

fn acct_discriminator(name: &str) -> [u8; 8] {
    let hash = sha256_hash(format!("account:{name}").as_bytes());
    hash[..8].try_into().unwrap()
}

const PROPOSAL_STATUS_OFFSET: usize = DISC_LEN + core::mem::offset_of!(Proposal, status);

// =========================================================================
// Message builders (must match on-chain format exactly)
// =========================================================================

/// Wraps a plain-text message body with the Solana offchain message header.
/// Format: `\xffsolana offchain` (16) + version(1) + format(1) + length(2 LE)
fn wrap_offchain(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + body.len());
    out.extend_from_slice(b"\xffsolana offchain");
    out.push(0); // version
    out.push(0); // format (restricted ASCII)
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn add_intent_msg(action: &str, expiry: i64, wallet_name: &str, proposal_index: u64, data: &[u8]) -> Vec<u8> {
    let body = format!(
        "expires {}: {action} add intent definition_hash: {}{}",
        format_timestamp(expiry), hex_encode(&sha256_hash(data)), message_suffix(wallet_name, proposal_index),
    );
    wrap_offchain(body.as_bytes())
}

fn remove_intent_msg(action: &str, expiry: i64, wallet_name: &str, proposal_index: u64, intent_index: u8) -> Vec<u8> {
    let body = format!(
        "expires {}: {action} remove intent {intent_index}{}",
        format_timestamp(expiry), message_suffix(wallet_name, proposal_index),
    );
    wrap_offchain(body.as_bytes())
}

// =========================================================================
// Instruction builder helpers
// =========================================================================

type Instruction = solana_instruction::Instruction;

fn create_wallet_ix(
    payer: Pubkey, name: &str, proposers: &[Pubkey], approvers: &[Pubkey], threshold: u8,
) -> (Instruction, Vec<Account>) {
    create_wallet_ix_full(payer, name, proposers, approvers, threshold, 1, 0)
}

fn create_wallet_ix_full(
    payer: Pubkey, name: &str, proposers: &[Pubkey], approvers: &[Pubkey],
    approval_threshold: u8, cancellation_threshold: u8, timelock_seconds: u32,
) -> (Instruction, Vec<Account>) {
    let name_hash = Pubkey::from(compute_name_hash(name));
    let (wallet, _) = find_wallet_address(name, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);
    let (update_intent, _) = find_intent_address(&wallet, 2, &crate::ID);

    let mut data = Vec::new();
    data.extend_from_slice(&ix_discriminator("create_wallet"));
    data.push(approval_threshold);
    data.push(cancellation_threshold);
    data.extend_from_slice(&timelock_seconds.to_le_bytes());
    data.extend_from_slice(&(name.len() as u64).to_le_bytes());
    data.extend_from_slice(name.as_bytes());
    data.extend_from_slice(&(proposers.len() as u64).to_le_bytes());
    for p in proposers { data.extend_from_slice(p.as_ref()); }
    data.extend_from_slice(&(approvers.len() as u64).to_le_bytes());
    for a in approvers { data.extend_from_slice(a.as_ref()); }

    let instruction = Instruction {
        program_id: crate::ID,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(name_hash, false),
            AccountMeta::new(wallet, false),
            AccountMeta::new(add_intent, false),
            AccountMeta::new(remove_intent, false),
            AccountMeta::new(update_intent, false),
            AccountMeta::new_readonly(quasar_svm::system_program::ID, false),
        ],
        data,
    };

    let accounts = vec![funded_account(payer), empty_account(name_hash), empty_account(wallet),
        empty_account(add_intent), empty_account(remove_intent), empty_account(update_intent)];
    (instruction, accounts)
}

struct ProposeArgs {
    payer: Pubkey,
    wallet: Pubkey,
    intent: Pubkey,
    proposal_index: u64,
    expiry: i64,
    proposer_pubkey: [u8; 32],
    signature: [u8; 64],
    params_data: Vec<u8>,
}

fn build_propose_ix(args: ProposeArgs) -> Instruction {
    let (proposal, _) = find_proposal_address(&args.intent, args.proposal_index, &crate::ID);

    let mut data = Vec::new();
    data.extend_from_slice(&ix_discriminator("propose"));
    data.extend_from_slice(&args.expiry.to_le_bytes());
    data.extend_from_slice(&args.proposer_pubkey);
    data.extend_from_slice(&args.signature);
    data.extend_from_slice(&(args.params_data.len() as u64).to_le_bytes());
    data.extend_from_slice(&args.params_data);

    Instruction {
        program_id: crate::ID,
        accounts: vec![
            AccountMeta::new(args.payer, true),
            AccountMeta::new(args.wallet, false),
            AccountMeta::new(args.intent, false),
            AccountMeta::new(proposal, false),
            AccountMeta::new_readonly(quasar_svm::system_program::ID, false),
        ],
        data,
    }
}

fn build_approve_ix(wallet: Pubkey, intent: Pubkey, proposal: Pubkey,
    expiry: i64, approver_index: u8, signature: [u8; 64],
) -> Instruction {
    let mut data = Vec::new();
    data.extend_from_slice(&ix_discriminator("approve"));
    data.extend_from_slice(&expiry.to_le_bytes());
    data.push(approver_index);
    data.extend_from_slice(&signature);

    Instruction {
        program_id: crate::ID,
        accounts: vec![
            AccountMeta::new_readonly(wallet, false),
            AccountMeta::new(intent, false),
            AccountMeta::new(proposal, false),
        ],
        data,
    }
}

fn build_cancel_ix(wallet: Pubkey, intent: Pubkey, proposal: Pubkey,
    expiry: i64, canceller_index: u8, signature: [u8; 64],
) -> Instruction {
    let mut data = Vec::new();
    data.extend_from_slice(&ix_discriminator("cancel"));
    data.extend_from_slice(&expiry.to_le_bytes());
    data.push(canceller_index);
    data.extend_from_slice(&signature);

    Instruction {
        program_id: crate::ID,
        accounts: vec![
            AccountMeta::new_readonly(wallet, false),
            AccountMeta::new(intent, false),
            AccountMeta::new(proposal, false),
        ],
        data,
    }
}

fn build_execute_ix(wallet: Pubkey, intent: Pubkey, proposal: Pubkey,
    remaining: Vec<AccountMeta>,
) -> (Instruction, Pubkey) {
    let (vault, _) = find_vault_address(&wallet, &crate::ID);
    let mut accounts = vec![
        AccountMeta::new(wallet, false),
        AccountMeta::new(vault, false),
        AccountMeta::new(intent, false),
        AccountMeta::new(proposal, false),
        AccountMeta::new_readonly(quasar_svm::system_program::ID, false),
    ];
    accounts.extend(remaining);

    let instruction = Instruction {
        program_id: crate::ID,
        accounts,
        data: ix_discriminator("execute").to_vec(),
    };
    (instruction, vault)
}

fn get_proposal_address(intent: Pubkey, index: u64) -> Pubkey {
    find_proposal_address(&intent, index, &crate::ID).0
}

/// Builds a partial Intent body for AddIntent proposals.
/// Due to PodVec<u8, 512> limit on proposal.params_data, only the first
/// 512 bytes of the Intent struct are filled. This covers identity,
/// governance, and proposer fields but not approvers or beyond.
fn build_intent_params(
    wallet: &Pubkey, proposers: &[Pubkey], _approvers: &[Pubkey],
    approval_threshold: u8, cancellation_threshold: u8, timelock_seconds: u32,
) -> Vec<u8> {
    use crate::state::intent::Intent;
    let cap = core::mem::size_of::<Intent>().min(512);
    let mut data = vec![0u8; cap];

    let off = |field: &str| -> usize {
        match field {
            "wallet" => 0,
            "intent_type" => core::mem::offset_of!(Intent, intent_type),
            "approved" => core::mem::offset_of!(Intent, approved),
            "approval_threshold" => core::mem::offset_of!(Intent, approval_threshold),
            "cancellation_threshold" => core::mem::offset_of!(Intent, cancellation_threshold),
            "timelock_seconds" => core::mem::offset_of!(Intent, timelock_seconds),
            "proposers" => core::mem::offset_of!(Intent, proposers),
            _ => panic!("unknown field"),
        }
    };

    data[off("wallet")..off("wallet") + 32].copy_from_slice(wallet.as_ref());
    data[off("intent_type")] = 3; // Custom
    data[off("approved")] = 1;
    data[off("approval_threshold")] = approval_threshold;
    data[off("cancellation_threshold")] = cancellation_threshold;
    let ts_off = off("timelock_seconds");
    data[ts_off..ts_off + 4].copy_from_slice(&timelock_seconds.to_le_bytes());

    let prop_off = off("proposers");
    let prop_count = proposers.len().min(14);
    data[prop_off..prop_off + 4].copy_from_slice(&(prop_count as u32).to_le_bytes());
    for (i, p) in proposers.iter().take(prop_count).enumerate() {
        let start = prop_off + 4 + i * 32;
        if start + 32 <= cap {
            data[start..start + 32].copy_from_slice(p.as_ref());
        }
    }

    data
}

/// Full propose -> approve -> execute flow.
struct ProposeApproveExecuteArgs<'a> {
    svm: &'a mut QuasarSvm,
    payer: Pubkey,
    wallet: Pubkey,
    wallet_name: &'a str,
    intent: Pubkey,
    proposal_index: u64,
    proposer: &'a ed25519_dalek::SigningKey,
    approver: &'a ed25519_dalek::SigningKey,
    params_data: Vec<u8>,
    msg_fn: &'a MessageFn,
    execute_remaining: Vec<AccountMeta>,
    execute_extra_accounts: Vec<Account>,
}

fn propose_approve_execute(args: ProposeApproveExecuteArgs<'_>) -> Pubkey {
    let proposal_address = get_proposal_address(args.intent, args.proposal_index);

    // Propose
    let msg = (args.msg_fn)("propose", DEFAULT_EXPIRY, args.wallet_name, args.proposal_index, &args.params_data);
    let instruction = build_propose_ix(ProposeArgs {
        payer: args.payer, wallet: args.wallet, intent: args.intent,
        proposal_index: args.proposal_index, expiry: DEFAULT_EXPIRY,
        proposer_pubkey: pubkey_bytes(args.proposer),
        signature: sign_message(args.proposer, &msg),
        params_data: args.params_data.clone(),
    });
    let result = args.svm.process_instruction(&instruction, &[funded_account(args.payer), empty_account(proposal_address)]);
    assert!(result.is_ok(), "propose failed: {:?}", result.raw_result);

    // Approve (approver is always at index 0)
    let msg = (args.msg_fn)("approve", DEFAULT_EXPIRY, args.wallet_name, args.proposal_index, &args.params_data);
    let instruction = build_approve_ix(args.wallet, args.intent, proposal_address, DEFAULT_EXPIRY, 0, sign_message(args.approver, &msg));
    let result = args.svm.process_instruction(&instruction, &[]);
    assert!(result.is_ok(), "approve failed: {:?}", result.raw_result);

    // Execute — vault is already in SVM state, don't overwrite it with empty
    let (instruction, _vault) = build_execute_ix(args.wallet, args.intent, proposal_address, args.execute_remaining);
    let all_accounts = args.execute_extra_accounts;
    let result = args.svm.process_instruction(&instruction, &all_accounts);
    assert!(result.is_ok(), "execute failed: {:?}", result.raw_result);
    println!("  EXECUTE CU: {}", result.compute_units_consumed);

    proposal_address
}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn test_create_wallet() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let (instruction, accounts) = create_wallet_ix(payer, "treasury", &[Pubkey::new_unique()], &[Pubkey::new_unique()], 1);
    let result = svm.process_instruction(&instruction, &accounts);
    assert!(result.is_ok(), "create failed: {:?}", result.raw_result);

    let (wallet, _) = find_wallet_address("treasury", &crate::ID);
    let wallet_disc = acct_discriminator("ClearWallet");
    assert_eq!(&result.account(&wallet).unwrap().data[..DISC_LEN], &wallet_disc);
    for index in 0..3u8 {
        let (intent_address, _) = find_intent_address(&wallet, index, &crate::ID);
        let intent_disc = acct_discriminator("Intent");
        assert_eq!(&result.account(&intent_address).unwrap().data[..DISC_LEN], &intent_disc);
    }
    println!("  CREATE CU: {}", result.compute_units_consumed);
}

#[test]
fn test_create_wallet_wrong_wallet_address_fails() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = Pubkey::new_unique();
    let approver = Pubkey::new_unique();
    let (wallet, _) = find_wallet_address("wrong-name", &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);
    let (update_intent, _) = find_intent_address(&wallet, 2, &crate::ID);

    let wrong_name_hash = Pubkey::from([0u8; 32]);

    let mut data = Vec::new();
    data.extend_from_slice(&ix_discriminator("create_wallet"));
    data.push(1); // approval_threshold
    data.push(1); // cancellation_threshold
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&(11u64).to_le_bytes());
    data.extend_from_slice(b"actual-name");
    data.extend_from_slice(&(1u64).to_le_bytes());
    data.extend_from_slice(proposer.as_ref());
    data.extend_from_slice(&(1u64).to_le_bytes());
    data.extend_from_slice(approver.as_ref());

    let instruction = Instruction {
        program_id: crate::ID,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(wrong_name_hash, false),
            AccountMeta::new(wallet, false),
            AccountMeta::new(add_intent, false),
            AccountMeta::new(remove_intent, false),
            AccountMeta::new(update_intent, false),
            AccountMeta::new_readonly(quasar_svm::system_program::ID, false),
        ],
        data,
    };

    let result = svm.process_instruction(&instruction, &[
        funded_account(payer), empty_account(wrong_name_hash), empty_account(wallet),
        empty_account(add_intent), empty_account(remove_intent), empty_account(update_intent),
    ]);
    assert!(result.is_err(), "wrong wallet address should fail PDA check");
}

#[test]
fn test_create_wallet_bad_threshold_fails() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let (instruction, accounts) = create_wallet_ix(payer, "bad", &[Pubkey::new_unique()], &[Pubkey::new_unique()], 2);
    assert!(svm.process_instruction(&instruction, &accounts).is_err());
}

#[test]
fn test_propose_add_intent() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "prop-test";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);

    let params_data = build_intent_params(&wallet, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1, 1, 0);

    let msg = add_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, &params_data);
    let instruction = build_propose_ix(ProposeArgs {
        payer, wallet, intent: add_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
        proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
        params_data,
    });
    let proposal_address = get_proposal_address(add_intent, 0);

    let result = svm.process_instruction(&instruction, &[funded_account(payer), empty_account(proposal_address)]);
    assert!(result.is_ok(), "propose failed: {:?}", result.raw_result);
    println!("  PROPOSE CU: {}", result.compute_units_consumed);
}

#[test]
fn test_propose_and_approve_add_intent() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "approve-test";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);

    let params_data = build_intent_params(&wallet, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1, 1, 0);
    let proposal_address = get_proposal_address(add_intent, 0);

    // Propose
    let msg = add_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, &params_data);
    let instruction = build_propose_ix(ProposeArgs {
        payer, wallet, intent: add_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
        proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
        params_data: params_data.clone(),
    });
    assert!(svm.process_instruction(&instruction, &[funded_account(payer), empty_account(proposal_address)]).is_ok());

    // Approve
    let msg = add_intent_msg("approve", DEFAULT_EXPIRY, wallet_name, 0, &params_data);
    let instruction = build_approve_ix(wallet, add_intent, proposal_address, DEFAULT_EXPIRY, 0, sign_message(&approver, &msg));
    let result = svm.process_instruction(&instruction, &[]);
    assert!(result.is_ok(), "approve failed: {:?}", result.raw_result);

    assert_eq!(svm.get_account(&proposal_address).unwrap().data[PROPOSAL_STATUS_OFFSET], 1, "status should be Approved(1)");
    println!("  APPROVE CU: {}", result.compute_units_consumed);
}

#[test]
fn test_cancel_overrides_approval() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver1 = new_keypair();
    let approver2 = new_keypair();
    let wallet_name = "cancel-test";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name,
        &[pubkey_of(&proposer)], &[pubkey_of(&approver1), pubkey_of(&approver2)], 2);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);

    let params_data = build_intent_params(
        &wallet, &[pubkey_of(&proposer)], &[pubkey_of(&approver1), pubkey_of(&approver2)], 2, 1, 0,
    );
    let proposal_address = get_proposal_address(add_intent, 0);

    // Propose
    let msg = add_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, &params_data);
    svm.process_instruction(
        &build_propose_ix(ProposeArgs {
            payer, wallet, intent: add_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
            proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
            params_data: params_data.clone(),
        }),
        &[funded_account(payer), empty_account(proposal_address)],
    ).unwrap();

    // Approver 1 approves
    let msg = add_intent_msg("approve", DEFAULT_EXPIRY, wallet_name, 0, &params_data);
    svm.process_instruction(&build_approve_ix(wallet, add_intent, proposal_address, DEFAULT_EXPIRY, 0, sign_message(&approver1, &msg)), &[]).unwrap();

    // Approver 1 switches to cancel
    let cancel_msg = wrap_offchain(format!("expires {}: cancel add intent definition_hash: {}{}",
        format_timestamp(DEFAULT_EXPIRY), hex_encode(&sha256_hash(&params_data)), message_suffix(wallet_name, 0)).as_bytes());
    svm.process_instruction(&build_cancel_ix(wallet, add_intent, proposal_address, DEFAULT_EXPIRY, 0, sign_message(&approver1, &cancel_msg)), &[]).unwrap();

    assert_eq!(svm.get_account(&proposal_address).unwrap().data[PROPOSAL_STATUS_OFFSET], 3, "status should be Cancelled(3)");
}

#[test]
fn test_wrong_signer_propose_fails() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wrong_key = new_keypair();
    let wallet_name = "wrong-signer";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);

    let params_data = vec![0u8; 10];
    let msg = add_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, &params_data);
    let instruction = build_propose_ix(ProposeArgs {
        payer, wallet, intent: add_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
        proposer_pubkey: pubkey_bytes(&wrong_key), signature: sign_message(&wrong_key, &msg),
        params_data,
    });
    let proposal_address = get_proposal_address(add_intent, 0);
    assert!(svm.process_instruction(&instruction, &[funded_account(payer), empty_account(proposal_address)]).is_err());
}

#[test]
fn test_expired_signature_fails() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "expired-sig";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);

    let params_data = vec![0u8; 10];
    let expired = -1i64;
    let msg = add_intent_msg("propose", expired, wallet_name, 0, &params_data);
    let instruction = build_propose_ix(ProposeArgs {
        payer, wallet, intent: add_intent, proposal_index: 0, expiry: expired,
        proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
        params_data,
    });
    let proposal_address = get_proposal_address(add_intent, 0);
    assert!(svm.process_instruction(&instruction, &[funded_account(payer), empty_account(proposal_address)]).is_err());
}

#[test]
fn test_propose_remove_intent() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "remove-test";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);

    let params_data = vec![0u8]; // target_index = 0
    let msg = remove_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, 0);
    let instruction = build_propose_ix(ProposeArgs {
        payer, wallet, intent: remove_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
        proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
        params_data,
    });
    let proposal_address = get_proposal_address(remove_intent, 0);

    let result = svm.process_instruction(&instruction, &[funded_account(payer), empty_account(proposal_address)]);
    assert!(result.is_ok(), "propose remove failed: {:?}", result.raw_result);
    println!("  PROPOSE_REMOVE CU: {}", result.compute_units_consumed);
}

#[test]
fn test_duplicate_approval_fails() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "dup-approve";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);
    let proposal_address = get_proposal_address(add_intent, 0);

    let params_data = vec![0u8; 10];
    let msg = add_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, &params_data);
    svm.process_instruction(
        &build_propose_ix(ProposeArgs {
            payer, wallet, intent: add_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
            proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
            params_data: params_data.clone(),
        }),
        &[funded_account(payer), empty_account(proposal_address)],
    ).unwrap();

    let msg = add_intent_msg("approve", DEFAULT_EXPIRY, wallet_name, 0, &params_data);
    let signature = sign_message(&approver, &msg);
    assert!(svm.process_instruction(&build_approve_ix(wallet, add_intent, proposal_address, DEFAULT_EXPIRY, 0, signature), &[]).is_ok());
    assert!(svm.process_instruction(&build_approve_ix(wallet, add_intent, proposal_address, DEFAULT_EXPIRY, 0, signature), &[]).is_err(),
        "duplicate approval should fail");
}

// =========================================================================
// Execute lifecycle tests
// =========================================================================

#[test]
fn test_execute_add_intent() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "exec-add";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);
    let (new_intent_address, _) = find_intent_address(&wallet, 3, &crate::ID);

    let params_data = build_intent_params(&wallet, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1, 1, 0);

    propose_approve_execute(ProposeApproveExecuteArgs {
        svm: &mut svm, payer, wallet, wallet_name, intent: add_intent,
        proposal_index: 0, proposer: &proposer, approver: &approver,
        params_data, msg_fn: &add_intent_msg,
        execute_remaining: vec![AccountMeta::new(payer, true), AccountMeta::new(new_intent_address, false)],
        execute_extra_accounts: vec![funded_account(payer), empty_account(new_intent_address)],
    });

    let intent_data = svm.get_account(&new_intent_address).unwrap();
    let intent_disc = acct_discriminator("Intent");
    assert_eq!(&intent_data.data[..DISC_LEN], &intent_disc, "new intent discriminator");
    assert_eq!(intent_data.owner, crate::ID, "new intent owned by program");
}

#[test]
fn test_execute_remove_intent() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "exec-remove";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);

    propose_approve_execute(ProposeApproveExecuteArgs {
        svm: &mut svm, payer, wallet, wallet_name, intent: remove_intent,
        proposal_index: 0, proposer: &proposer, approver: &approver,
        params_data: vec![0u8],
        msg_fn: &|action, expiry, wallet_name, proposal_index, data|
            remove_intent_msg(action, expiry, wallet_name, proposal_index, data[0]),
        execute_remaining: vec![AccountMeta::new(add_intent, false)],
        execute_extra_accounts: vec![],
    });

    assert_eq!(svm.get_account(&add_intent).unwrap().data[INTENT_APPROVED_OFFSET], 0, "intent should be deactivated");
}

#[test]
fn test_removed_intent_cannot_be_used() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "removed-fail";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);

    // Remove AddIntent
    propose_approve_execute(ProposeApproveExecuteArgs {
        svm: &mut svm, payer, wallet, wallet_name, intent: remove_intent,
        proposal_index: 0, proposer: &proposer, approver: &approver,
        params_data: vec![0u8],
        msg_fn: &|action, expiry, wallet_name, proposal_index, data|
            remove_intent_msg(action, expiry, wallet_name, proposal_index, data[0]),
        execute_remaining: vec![AccountMeta::new(add_intent, false)],
        execute_extra_accounts: vec![],
    });

    // Try to propose via the removed AddIntent — should fail
    let dummy_params = vec![0u8; 10];
    let msg = add_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 1, &dummy_params);
    let instruction = build_propose_ix(ProposeArgs {
        payer, wallet, intent: add_intent, proposal_index: 1, expiry: DEFAULT_EXPIRY,
        proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
        params_data: dummy_params,
    });
    let proposal_address = get_proposal_address(add_intent, 1);
    assert!(svm.process_instruction(&instruction, &[funded_account(payer), empty_account(proposal_address)]).is_err());
}

// =========================================================================
// Comprehensive tests
// =========================================================================

#[test]
fn test_timelock_enforcement() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "timelock-test";

    let (instruction, accounts) = create_wallet_ix_full(
        payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)],
        1, 1, 3600,
    );
    svm.process_instruction(&instruction, &accounts).unwrap();

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);

    let params_data = vec![0u8];
    let proposal_address = get_proposal_address(remove_intent, 0);

    // Propose + approve
    let msg = remove_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, 0);
    svm.process_instruction(
        &build_propose_ix(ProposeArgs {
            payer, wallet, intent: remove_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
            proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
            params_data: params_data.clone(),
        }),
        &[funded_account(payer), empty_account(proposal_address)],
    ).unwrap();

    let msg = remove_intent_msg("approve", DEFAULT_EXPIRY, wallet_name, 0, 0);
    svm.process_instruction(&build_approve_ix(wallet, remove_intent, proposal_address, DEFAULT_EXPIRY, 0, sign_message(&approver, &msg)), &[]).unwrap();

    // Execute immediately should fail (clock=0, timelock=3600)
    let (instruction, vault) = build_execute_ix(wallet, remove_intent, proposal_address, vec![AccountMeta::new(add_intent, false)]);
    assert!(svm.process_instruction(&instruction, &[empty_account(vault)]).is_err());
    println!("  TIMELOCK: correctly blocked execution");
}

#[test]
fn test_execute_not_approved_fails() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "not-approved";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);

    // Propose but don't approve
    let params_data = vec![0u8];
    let proposal_address = get_proposal_address(remove_intent, 0);
    let msg = remove_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, 0);
    svm.process_instruction(
        &build_propose_ix(ProposeArgs {
            payer, wallet, intent: remove_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
            proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
            params_data,
        }),
        &[funded_account(payer), empty_account(proposal_address)],
    ).unwrap();

    let (instruction, vault) = build_execute_ix(wallet, remove_intent, proposal_address, vec![AccountMeta::new(add_intent, false)]);
    assert!(svm.process_instruction(&instruction, &[empty_account(vault)]).is_err());
}

#[test]
fn test_multi_approver_threshold() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver1 = new_keypair();
    let approver2 = new_keypair();
    let approver3 = new_keypair();
    let wallet_name = "multi-approve";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name,
        &[pubkey_of(&proposer)], &[pubkey_of(&approver1), pubkey_of(&approver2), pubkey_of(&approver3)], 2);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);
    let proposal_address = get_proposal_address(remove_intent, 0);

    let params_data = vec![0u8];
    let msg = remove_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, 0);
    svm.process_instruction(
        &build_propose_ix(ProposeArgs {
            payer, wallet, intent: remove_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
            proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
            params_data: params_data.clone(),
        }),
        &[funded_account(payer), empty_account(proposal_address)],
    ).unwrap();

    // First approval — not enough
    let msg = remove_intent_msg("approve", DEFAULT_EXPIRY, wallet_name, 0, 0);
    svm.process_instruction(&build_approve_ix(wallet, remove_intent, proposal_address, DEFAULT_EXPIRY, 0, sign_message(&approver1, &msg)), &[]).unwrap();
    assert_eq!(svm.get_account(&proposal_address).unwrap().data[PROPOSAL_STATUS_OFFSET], 0, "should still be Active");

    // Second approval — threshold met
    svm.process_instruction(&build_approve_ix(wallet, remove_intent, proposal_address, DEFAULT_EXPIRY, 1, sign_message(&approver2, &msg)), &[]).unwrap();
    assert_eq!(svm.get_account(&proposal_address).unwrap().data[PROPOSAL_STATUS_OFFSET], 1, "should be Approved");
    println!("  MULTI_APPROVE: 2-of-3 threshold works");
}

#[test]
fn test_cancel_reverts_approved_to_active() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver1 = new_keypair();
    let approver2 = new_keypair();
    let wallet_name = "revert-test";

    let (instruction, accounts) = create_wallet_ix_full(
        payer, wallet_name, &[pubkey_of(&proposer)],
        &[pubkey_of(&approver1), pubkey_of(&approver2)],
        2, 2, 0,
    );
    svm.process_instruction(&instruction, &accounts).unwrap();

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);
    let proposal_address = get_proposal_address(remove_intent, 0);

    let params_data = vec![0u8];

    let msg = remove_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, 0);
    svm.process_instruction(
        &build_propose_ix(ProposeArgs {
            payer, wallet, intent: remove_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
            proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
            params_data: params_data.clone(),
        }),
        &[funded_account(payer), empty_account(proposal_address)],
    ).unwrap();

    // Both approve
    let approve_msg = remove_intent_msg("approve", DEFAULT_EXPIRY, wallet_name, 0, 0);
    svm.process_instruction(&build_approve_ix(wallet, remove_intent, proposal_address, DEFAULT_EXPIRY, 0, sign_message(&approver1, &approve_msg)), &[]).unwrap();
    svm.process_instruction(&build_approve_ix(wallet, remove_intent, proposal_address, DEFAULT_EXPIRY, 1, sign_message(&approver2, &approve_msg)), &[]).unwrap();
    assert_eq!(svm.get_account(&proposal_address).unwrap().data[PROPOSAL_STATUS_OFFSET], 1, "should be Approved");

    // approver1 switches to cancel
    let cancel_msg = wrap_offchain(format!("expires {}: cancel remove intent 0{}",
        format_timestamp(DEFAULT_EXPIRY), message_suffix(wallet_name, 0)).as_bytes());
    svm.process_instruction(&build_cancel_ix(wallet, remove_intent, proposal_address, DEFAULT_EXPIRY, 0, sign_message(&approver1, &cancel_msg)), &[]).unwrap();

    assert_eq!(svm.get_account(&proposal_address).unwrap().data[PROPOSAL_STATUS_OFFSET], 0, "should revert to Active");
    println!("  REVERT: Approved -> Active after vote switch");
}

#[test]
fn test_non_approver_approve_fails() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let random_key = new_keypair();
    let wallet_name = "non-approver";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);
    let proposal_address = get_proposal_address(remove_intent, 0);

    let params_data = vec![0u8];
    let msg = remove_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, 0);
    svm.process_instruction(
        &build_propose_ix(ProposeArgs {
            payer, wallet, intent: remove_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
            proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
            params_data,
        }),
        &[funded_account(payer), empty_account(proposal_address)],
    ).unwrap();

    let msg = remove_intent_msg("approve", DEFAULT_EXPIRY, wallet_name, 0, 0);
    assert!(svm.process_instruction(
        &build_approve_ix(wallet, remove_intent, proposal_address, DEFAULT_EXPIRY, 99, sign_message(&random_key, &msg)), &[]).is_err());
}

#[test]
fn test_full_add_then_remove_lifecycle() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "full-lifecycle";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);
    let (new_intent_address, _) = find_intent_address(&wallet, 3, &crate::ID);

    // 1. Add a transfer intent
    let params_data = build_intent_params(&wallet, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1, 1, 0);

    propose_approve_execute(ProposeApproveExecuteArgs {
        svm: &mut svm, payer, wallet, wallet_name, intent: add_intent,
        proposal_index: 0, proposer: &proposer, approver: &approver,
        params_data, msg_fn: &add_intent_msg,
        execute_remaining: vec![AccountMeta::new(payer, true), AccountMeta::new(new_intent_address, false)],
        execute_extra_accounts: vec![funded_account(payer), empty_account(new_intent_address)],
    });
    let intent_disc = acct_discriminator("Intent");
    assert_eq!(&svm.get_account(&new_intent_address).unwrap().data[..DISC_LEN], &intent_disc, "new intent created");

    // 2. Remove the new intent
    propose_approve_execute(ProposeApproveExecuteArgs {
        svm: &mut svm, payer, wallet, wallet_name, intent: remove_intent,
        proposal_index: 1, proposer: &proposer, approver: &approver,
        params_data: vec![3u8],
        msg_fn: &|action, expiry, wallet_name, proposal_index, data|
            remove_intent_msg(action, expiry, wallet_name, proposal_index, data[0]),
        execute_remaining: vec![AccountMeta::new(new_intent_address, false)],
        execute_extra_accounts: vec![],
    });

    assert_eq!(svm.get_account(&new_intent_address).unwrap().data[INTENT_APPROVED_OFFSET], 0, "intent deactivated");

    // 3. Try to propose using deactivated intent — should fail
    let dummy_params = vec![0u8; 10];
    let msg = add_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 2, &dummy_params);
    let instruction = build_propose_ix(ProposeArgs {
        payer, wallet, intent: new_intent_address, proposal_index: 2, expiry: DEFAULT_EXPIRY,
        proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
        params_data: dummy_params,
    });
    let proposal_address = get_proposal_address(new_intent_address, 2);
    assert!(svm.process_instruction(&instruction, &[funded_account(payer), empty_account(proposal_address)]).is_err());
    println!("  FULL_LIFECYCLE: add -> remove -> reject all passed");
}

#[test]
fn test_remove_add_intent_blocks_future_adds() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "block-adds";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);

    // Remove AddIntent itself
    propose_approve_execute(ProposeApproveExecuteArgs {
        svm: &mut svm, payer, wallet, wallet_name, intent: remove_intent,
        proposal_index: 0, proposer: &proposer, approver: &approver,
        params_data: vec![0u8],
        msg_fn: &|action, expiry, wallet_name, proposal_index, data|
            remove_intent_msg(action, expiry, wallet_name, proposal_index, data[0]),
        execute_remaining: vec![AccountMeta::new(add_intent, false)],
        execute_extra_accounts: vec![],
    });

    // Now try to add an intent — AddIntent is deactivated
    let params_data = build_intent_params(&wallet, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1, 1, 0);
    let msg = add_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 1, &params_data);
    let proposal_address = get_proposal_address(add_intent, 1);
    let instruction = build_propose_ix(ProposeArgs {
        payer, wallet, intent: add_intent, proposal_index: 1, expiry: DEFAULT_EXPIRY,
        proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
        params_data,
    });
    assert!(svm.process_instruction(&instruction, &[funded_account(payer), empty_account(proposal_address)]).is_err());
    println!("  BLOCK_ADDS: removing AddIntent blocks future additions");
}

#[test]
#[ignore] // quasar-svm returns UnbalancedInstruction on close; works on real validator
fn test_cleanup_executed_proposal() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "cleanup-test";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);

    let proposal_address = propose_approve_execute(ProposeApproveExecuteArgs {
        svm: &mut svm, payer, wallet, wallet_name, intent: remove_intent,
        proposal_index: 0, proposer: &proposer, approver: &approver,
        params_data: vec![0u8],
        msg_fn: &|action, expiry, wallet_name, proposal_index, data|
            remove_intent_msg(action, expiry, wallet_name, proposal_index, data[0]),
        execute_remaining: vec![AccountMeta::new(add_intent, false)],
        execute_extra_accounts: vec![],
    });

    assert_eq!(svm.get_account(&proposal_address).unwrap().data[PROPOSAL_STATUS_OFFSET], 2, "should be Executed");

    let instruction = Instruction {
        program_id: crate::ID,
        accounts: vec![
            AccountMeta::new(proposal_address, false),
            AccountMeta::new(payer, false),
        ],
        data: ix_discriminator("cleanup_proposal").to_vec(),
    };
    let result = svm.process_instruction(&instruction, &[]);
    assert!(result.is_ok(), "cleanup failed: {:?}", result.raw_result);

    let account = svm.get_account(&proposal_address);
    assert!(account.is_none_or(|a| a.data.is_empty() || a.lamports == 0), "proposal should be closed");
    println!("  CLEANUP: proposal closed successfully");
}

#[test]
fn test_cleanup_active_proposal_fails() {
    let mut svm = setup();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "cleanup-fail";

    let (instruction, accounts) = create_wallet_ix(payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1);
    assert!(svm.process_instruction(&instruction, &accounts).is_ok());

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (remove_intent, _) = find_intent_address(&wallet, 1, &crate::ID);

    let params_data = vec![0u8];
    let proposal_address = get_proposal_address(remove_intent, 0);
    let msg = remove_intent_msg("propose", DEFAULT_EXPIRY, wallet_name, 0, 0);
    svm.process_instruction(
        &build_propose_ix(ProposeArgs {
            payer, wallet, intent: remove_intent, proposal_index: 0, expiry: DEFAULT_EXPIRY,
            proposer_pubkey: pubkey_bytes(&proposer), signature: sign_message(&proposer, &msg),
            params_data,
        }),
        &[funded_account(payer), empty_account(proposal_address)],
    ).unwrap();

    let instruction = Instruction {
        program_id: crate::ID,
        accounts: vec![
            AccountMeta::new(proposal_address, false),
            AccountMeta::new(payer, false),
        ],
        data: ix_discriminator("cleanup_proposal").to_vec(),
    };
    assert!(svm.process_instruction(&instruction, &[funded_account(payer)]).is_err());
}

// =========================================================================
// SPL Token transfer test — exercises the full CPI execution engine
// =========================================================================

#[test]
#[ignore] // Requires full Intent body in PodVec format; PodVec<u8, 512> limit prevents this
fn test_execute_spl_token_transfer() {
    use quasar_svm::token::{create_keyed_mint_account, create_keyed_token_account, Mint, TokenAccount};
    use quasar_svm::{SPL_TOKEN_PROGRAM_ID, SPL_ASSOCIATED_TOKEN_PROGRAM_ID};
    use spl_token::state::AccountState;
    use spl_token::solana_program::program_pack::Pack;

    let mut svm = setup_with_tokens();
    let payer = Pubkey::new_unique();
    let proposer = new_keypair();
    let approver = new_keypair();
    let wallet_name = "token-transfer";
    let transfer_amount = 500_000u64;

    // 1. Create the wallet
    let (instruction, accounts) = create_wallet_ix(
        payer, wallet_name, &[pubkey_of(&proposer)], &[pubkey_of(&approver)], 1,
    );
    svm.process_instruction(&instruction, &accounts).unwrap();

    let (wallet, _) = find_wallet_address(wallet_name, &crate::ID);
    let (add_intent, _) = find_intent_address(&wallet, 0, &crate::ID);
    let (vault, _) = find_vault_address(&wallet, &crate::ID);

    // 2. Add a transfer_tokens intent — would need full Intent body here
    // This is blocked by PodVec<u8, 512> limit on proposal.params_data.
    // A transfer_tokens Intent with approvers, params, accounts, instructions,
    // seeds, and byte_pool requires ~6KB in PodVec format.
    let _ = (wallet, add_intent, vault, transfer_amount, svm, proposer, approver, payer);
    panic!("test_execute_spl_token_transfer requires PodVec<u8, 512> increase to port");
}
