use {
    anchor_bench::{keypair_for_account, BenchContext},
    anyhow::{Context, Result},
    ed25519_dalek::{Signer as DalekSigner, SigningKey},
    sha2::{Digest, Sha256},
    solana_instruction::AccountMeta,
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_signer::Signer,
};

pub const DEFAULT_EXPIRY: i64 = 1_000_000_000;

pub fn program_id() -> Pubkey {
    "msigVi8dMnmLQUuCbakipEMZhzen516QRHxGz7iX5Xv".parse().unwrap()
}

pub fn system_program_id() -> Pubkey {
    "11111111111111111111111111111111".parse().unwrap()
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn wallet_pda(name: &[u8]) -> (Pubkey, [u8; 32]) {
    let name_hash = sha256_bytes(name);
    let (wallet, _) = Pubkey::find_program_address(
        &[b"clear_wallet", &name_hash],
        &program_id(),
    );
    (wallet, name_hash)
}

pub fn intent_pda(wallet: &Pubkey, intent_index: u8) -> Pubkey {
    Pubkey::find_program_address(
        &[b"intent", wallet.as_ref(), &[intent_index]],
        &program_id(),
    )
    .0
}

pub fn proposal_pda(intent: &Pubkey, proposal_index: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[b"proposal", intent.as_ref(), &proposal_index.to_le_bytes()],
        &program_id(),
    )
    .0
}

pub fn vault_pda(wallet: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[b"vault", wallet.as_ref()],
        &program_id(),
    )
    .0
}


/// Derive a deterministic ed25519 keypair from a label.
pub fn ed25519_keypair_from_label(label: &str) -> SigningKey {
    // Hash the label to get 32 bytes for the seed
    let seed = sha256_bytes(label.as_bytes());
    SigningKey::from_bytes(&seed)
}

pub fn ed25519_pubkey(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

pub fn sign_message(key: &SigningKey, msg: &[u8]) -> [u8; 64] {
    key.sign(msg).to_bytes()
}


/// Solana offchain message header (for Ledger compatibility).
fn wrap_offchain(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + body.len());
    out.extend_from_slice(b"\xffsolana offchain");
    out.push(0); // version
    out.push(0); // format = restricted ASCII
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn format_timestamp(ts: i64) -> String {
    let secs_per_day: i64 = 86400;
    let mut days = ts / secs_per_day;
    let day_secs = ((ts % secs_per_day) + secs_per_day) % secs_per_day;
    if ts < 0 && day_secs > 0 {
        days -= 1;
    }
    let hour = day_secs / 3600;
    let min = (day_secs % 3600) / 60;
    let sec = day_secs % 60;

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

fn suffix(wallet_name: &str, proposal_index: u64) -> String {
    format!(" | wallet: {wallet_name} proposal: {proposal_index}")
}

/// Build a "remove intent <N>" message (for RemoveIntent meta-intent).
pub fn remove_intent_msg(
    action: &str,
    expiry: i64,
    wallet_name: &str,
    proposal_index: u64,
    intent_index: u8,
) -> Vec<u8> {
    let body = format!(
        "expires {}: {action} remove intent {intent_index}{}",
        format_timestamp(expiry),
        suffix(wallet_name, proposal_index),
    );
    wrap_offchain(body.as_bytes())
}

/// Build an "add intent definition_hash: <hex>" message (for AddIntent meta-intent).
#[allow(dead_code)]
pub fn add_intent_msg(
    action: &str,
    expiry: i64,
    wallet_name: &str,
    proposal_index: u64,
    data: &[u8],
) -> Vec<u8> {
    let body = format!(
        "expires {}: {action} add intent definition_hash: {}{}",
        format_timestamp(expiry),
        hex_encode(&sha256_bytes(data)),
        suffix(wallet_name, proposal_index),
    );
    wrap_offchain(body.as_bytes())
}


/// Which program variant we're benchmarking.
#[derive(Clone, Copy)]
pub enum ProgramKind {
    AnchorV2,
    Quasar,
}

impl ProgramKind {
    /// Instruction discriminator bytes. Anchor v2 uses sha256("global:name")[..8];
    /// Quasar uses a single explicit u8.
    pub fn discriminator(self, fn_name: &str) -> Vec<u8> {
        match self {
            Self::AnchorV2 => {
                let hash = sha256_bytes(format!("global:{fn_name}").as_bytes());
                hash[..8].to_vec()
            }
            Self::Quasar => {
                // Order matches #[instruction(discriminator = N)] on the Quasar side.
                let n = match fn_name {
                    "create_wallet" => 0u8,
                    "propose" => 1,
                    "approve" => 2,
                    "cancel" => 3,
                    "execute" => 4,
                    "cleanup_proposal" => 5,
                    _ => panic!("unknown instruction: {fn_name}"),
                };
                vec![n]
            }
        }
    }
}


/// Build create_wallet instruction data for the given program kind.
pub fn build_create_wallet_data(
    kind: ProgramKind,
    approval_threshold: u8,
    cancellation_threshold: u8,
    timelock_seconds: u32,
    name: &[u8],
    proposers: &[[u8; 32]],
    approvers: &[[u8; 32]],
) -> Vec<u8> {
    let mut data = kind.discriminator("create_wallet");
    data.push(approval_threshold);
    data.push(cancellation_threshold);
    data.extend_from_slice(&timelock_seconds.to_le_bytes());

    match kind {
        ProgramKind::AnchorV2 => {
            // Wincode slice layout: u64 LE length prefix + raw bytes.
            data.extend_from_slice(&(name.len() as u64).to_le_bytes());
            data.extend_from_slice(name);

            data.extend_from_slice(&(proposers.len() as u64).to_le_bytes());
            for p in proposers {
                data.extend_from_slice(p);
            }

            data.extend_from_slice(&(approvers.len() as u64).to_le_bytes());
            for a in approvers {
                data.extend_from_slice(a);
            }
        }
        ProgramKind::Quasar => {
            // Dynamic layout: DynBytes (u32 len + bytes), DynVec (u32 len + items)
            data.extend_from_slice(&(name.len() as u32).to_le_bytes());
            data.extend_from_slice(name);

            data.extend_from_slice(&(proposers.len() as u32).to_le_bytes());
            for p in proposers {
                data.extend_from_slice(p);
            }

            data.extend_from_slice(&(approvers.len() as u32).to_le_bytes());
            for a in approvers {
                a.iter().for_each(|b| data.push(*b));
            }
        }
    }

    data
}

/// Build propose instruction data.
pub fn build_propose_data(
    kind: ProgramKind,
    proposal_index: u64,
    expiry: i64,
    proposer_pubkey: &[u8; 32],
    signature: &[u8; 64],
    params_data: &[u8],
) -> Vec<u8> {
    let mut data = kind.discriminator("propose");
    // Anchor v2 loads proposal_index from the wallet account; Quasar still takes it as an arg.
    if matches!(kind, ProgramKind::Quasar) {
        data.extend_from_slice(&proposal_index.to_le_bytes());
    }
    data.extend_from_slice(&expiry.to_le_bytes());
    data.extend_from_slice(proposer_pubkey);
    data.extend_from_slice(signature);

    match kind {
        ProgramKind::AnchorV2 => {
            // Wincode slice: u64 LE length prefix + bytes.
            data.extend_from_slice(&(params_data.len() as u64).to_le_bytes());
            data.extend_from_slice(params_data);
        }
        ProgramKind::Quasar => {
            // TailBytes — raw bytes to end of instruction (no length prefix)
            data.extend_from_slice(params_data);
        }
    }

    data
}

/// Build approve instruction data.
pub fn build_approve_data(
    kind: ProgramKind,
    expiry: i64,
    approver_index: u8,
    signature: &[u8; 64],
) -> Vec<u8> {
    let mut data = kind.discriminator("approve");
    data.extend_from_slice(&expiry.to_le_bytes());
    data.push(approver_index);
    data.extend_from_slice(signature);
    data
}

/// Build cancel instruction data.
pub fn build_cancel_data(
    kind: ProgramKind,
    expiry: i64,
    canceller_index: u8,
    signature: &[u8; 64],
) -> Vec<u8> {
    let mut data = kind.discriminator("cancel");
    data.extend_from_slice(&expiry.to_le_bytes());
    data.push(canceller_index);
    data.extend_from_slice(signature);
    data
}

/// Build execute instruction data (no args).
pub fn build_execute_data(kind: ProgramKind) -> Vec<u8> {
    kind.discriminator("execute")
}

/// Build cleanup_proposal instruction data (no args).
pub fn build_cleanup_data(kind: ProgramKind) -> Vec<u8> {
    kind.discriminator("cleanup_proposal")
}


pub fn create_wallet_metas(payer: Pubkey, wallet_name: &[u8]) -> Vec<AccountMeta> {
    let (wallet, name_hash) = wallet_pda(wallet_name);
    let name_hash_pubkey = Pubkey::new_from_array(name_hash);

    vec![
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(name_hash_pubkey, false),
        AccountMeta::new(wallet, false),
        AccountMeta::new(intent_pda(&wallet, 0), false),
        AccountMeta::new(intent_pda(&wallet, 1), false),
        AccountMeta::new(intent_pda(&wallet, 2), false),
        AccountMeta::new_readonly(system_program_id(), false),
    ]
}

pub fn propose_metas(
    payer: Pubkey,
    wallet: Pubkey,
    intent: Pubkey,
    proposal_index: u64,
) -> Vec<AccountMeta> {
    let proposal = proposal_pda(&intent, proposal_index);
    vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(wallet, false),
        AccountMeta::new(intent, false),
        AccountMeta::new(proposal, false),
        AccountMeta::new_readonly(system_program_id(), false),
    ]
}

pub fn approve_metas(wallet: Pubkey, intent: Pubkey, proposal: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(wallet, false),
        AccountMeta::new(intent, false),
        AccountMeta::new(proposal, false),
    ]
}

pub fn cancel_metas(wallet: Pubkey, intent: Pubkey, proposal: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(wallet, false),
        AccountMeta::new(intent, false),
        AccountMeta::new(proposal, false),
    ]
}

pub fn execute_metas(
    wallet: Pubkey,
    intent: Pubkey,
    proposal: Pubkey,
    remaining: Vec<AccountMeta>,
) -> Vec<AccountMeta> {
    let mut metas = vec![
        AccountMeta::new(wallet, false),
        AccountMeta::new(vault_pda(&wallet), false),
        AccountMeta::new(intent, false),
        AccountMeta::new(proposal, false),
        AccountMeta::new_readonly(system_program_id(), false),
    ];
    metas.extend(remaining);
    metas
}

pub fn cleanup_metas(proposal: Pubkey, rent_refund: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(proposal, false),
        AccountMeta::new(rent_refund, false),
    ]
}


pub struct WalletSetup {
    /// On-chain payer (also the rent_refund target). Separate from the
    /// transaction fee payer so close instructions don't double-count lamports.
    pub creator: Keypair,
    pub proposer: SigningKey,
    pub approver: SigningKey,
    pub wallet: Pubkey,
    pub wallet_name: Vec<u8>,
}

impl WalletSetup {
    pub fn default() -> Self {
        let creator = keypair_for_account("bench-creator");
        let proposer = ed25519_keypair_from_label("bench-proposer");
        let approver = ed25519_keypair_from_label("bench-approver");
        let wallet_name = b"bench-wallet".to_vec();
        let (wallet, _) = wallet_pda(&wallet_name);
        Self { creator, proposer, approver, wallet, wallet_name }
    }

    pub fn wallet_name_str(&self) -> &str {
        core::str::from_utf8(&self.wallet_name).unwrap()
    }
}

/// Create a wallet with one proposer and one approver, single-signer threshold.
pub fn setup_wallet(ctx: &mut BenchContext, kind: ProgramKind) -> Result<WalletSetup> {
    let setup = WalletSetup::default();
    ctx.airdrop(&setup.creator.pubkey(), 10_000_000_000)?;

    let proposer_bytes = ed25519_pubkey(&setup.proposer);
    let approver_bytes = ed25519_pubkey(&setup.approver);

    let metas = create_wallet_metas(setup.creator.pubkey(), &setup.wallet_name);
    let data = build_create_wallet_data(
        kind,
        1, // approval_threshold
        1, // cancellation_threshold
        0, // timelock_seconds
        &setup.wallet_name,
        &[proposer_bytes],
        &[approver_bytes],
    );
    ctx.execute_with_signers(data, metas, &[&setup.creator])
        .context("setup_wallet create_wallet failed")?;

    Ok(setup)
}

/// Propose removing intent index `target_intent_index`.
/// Returns (intent_pda, proposal_pda, params_data).
pub fn setup_proposed_remove_intent(
    ctx: &mut BenchContext,
    kind: ProgramKind,
    setup: &WalletSetup,
    target_intent_index: u8,
) -> Result<(Pubkey, Pubkey, Vec<u8>)> {
    // We propose against the RemoveIntent meta-intent (index 1).
    let remove_intent = intent_pda(&setup.wallet, 1);
    let proposal_index: u64 = 0;
    let proposal = proposal_pda(&remove_intent, proposal_index);
    let params_data = vec![target_intent_index];

    let msg = remove_intent_msg(
        "propose",
        DEFAULT_EXPIRY,
        setup.wallet_name_str(),
        proposal_index,
        target_intent_index,
    );
    let signature = sign_message(&setup.proposer, &msg);

    let metas = propose_metas(setup.creator.pubkey(), setup.wallet, remove_intent, proposal_index);
    let data = build_propose_data(
        kind,
        proposal_index,
        DEFAULT_EXPIRY,
        &ed25519_pubkey(&setup.proposer),
        &signature,
        &params_data,
    );
    ctx.execute_with_signers(data, metas, &[&setup.creator])
        .context("setup propose failed")?;

    Ok((remove_intent, proposal, params_data))
}

/// Approve an existing proposal.
pub fn setup_approved(
    ctx: &mut BenchContext,
    kind: ProgramKind,
    setup: &WalletSetup,
    intent: Pubkey,
    proposal: Pubkey,
    target_intent_index: u8,
) -> Result<()> {
    let proposal_index: u64 = 0;
    let msg = remove_intent_msg(
        "approve",
        DEFAULT_EXPIRY,
        setup.wallet_name_str(),
        proposal_index,
        target_intent_index,
    );
    let signature = sign_message(&setup.approver, &msg);
    let metas = approve_metas(setup.wallet, intent, proposal);
    let data = build_approve_data(kind, DEFAULT_EXPIRY, 0, &signature);
    ctx.execute_with_signers(data, metas, &[])
        .context("setup approve failed")?;
    Ok(())
}

/// Execute an approved RemoveIntent proposal (needs the target intent as remaining).
pub fn setup_executed_remove(
    ctx: &mut BenchContext,
    kind: ProgramKind,
    setup: &WalletSetup,
    intent: Pubkey,
    proposal: Pubkey,
    target_intent_index: u8,
) -> Result<()> {
    let target_intent = intent_pda(&setup.wallet, target_intent_index);
    let remaining = vec![AccountMeta::new(target_intent, false)];
    let metas = execute_metas(setup.wallet, intent, proposal, remaining);
    let data = build_execute_data(kind);
    ctx.execute_with_signers(data, metas, &[])
        .context("setup execute failed")?;
    Ok(())
}
