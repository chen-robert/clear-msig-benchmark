use anchor_lang_v2::prelude::*;

use crate::state::{
    intent::{Intent, IntentType},
    wallet::ClearWallet,
};

/// Creates a ClearWallet with three default meta-intents.
///
/// `name_hash` is an UncheckedAccount whose address equals sha256(name).
/// The client derives this off-chain. Verified on-chain.
///
/// Proposer/approver addresses are passed as instruction data (the `addresses`
/// tail field): first `num_proposers * 32` bytes are proposer pubkeys, rest
/// are approver pubkeys. This avoids remaining-account dedup issues when
/// the payer is also a proposer or approver.
#[derive(Accounts)]
pub struct CreateWallet {
    #[account(mut)]
    pub payer: Signer,
    /// Account at address sha256(name) — used as PDA seed reference.
    pub name_hash: UncheckedAccount,
    #[account(
        init,
        payer = payer,
        seeds = [b"clear_wallet", name_hash],
        bump,
        space = ClearWallet::SPACE,
    )]
    pub wallet: Account<ClearWallet>,
    #[account(
        init,
        payer = payer,
        seeds = [b"intent", wallet, &[0u8]],
        bump,
        space = Intent::SPACE,
    )]
    pub add_intent: Account<Intent>,
    #[account(
        init,
        payer = payer,
        seeds = [b"intent", wallet, &[1u8]],
        bump,
        space = Intent::SPACE,
    )]
    pub remove_intent: Account<Intent>,
    #[account(
        init,
        payer = payer,
        seeds = [b"intent", wallet, &[2u8]],
        bump,
        space = Intent::SPACE,
    )]
    pub update_intent: Account<Intent>,
    pub system_program: Program<System>,
}

pub struct CreateWalletArgs<'a> {
    pub name: &'a [u8],
    pub approval_threshold: u8,
    pub cancellation_threshold: u8,
    pub timelock_seconds: u32,
    pub proposers: &'a [[u8; 32]],
    pub approvers: &'a [[u8; 32]],
}

impl CreateWallet {
    pub fn create(
        &mut self,
        args: CreateWalletArgs<'_>,
        bumps: &CreateWalletBumps,
    ) -> Result<()> {
        // Verify name_hash matches sha256(name)
        let computed = sha256(args.name);
        require_keys_eq!(
            *self.name_hash.address(),
            Address::new_from_array(computed),
            ProgramError::InvalidSeeds
        );

        let wallet_addr = *self.wallet.address();

        let proposer_count = args.proposers.len() as u8;
        let approver_count = args.approvers.len() as u8;
        require!(proposer_count as usize <= 16, ProgramError::InvalidArgument);
        require!(approver_count as usize <= 16, ProgramError::InvalidArgument);

        require!(args.approval_threshold > 0, ProgramError::InvalidArgument);
        require!(
            args.approval_threshold <= approver_count,
            ProgramError::InvalidArgument
        );
        require!(
            args.cancellation_threshold > 0,
            ProgramError::InvalidArgument
        );
        require!(
            args.cancellation_threshold <= approver_count,
            ProgramError::InvalidArgument
        );
        require!(args.name.len() <= 64, ProgramError::InvalidArgument);

        // Address is #[repr(transparent)] over [u8; 32], safe to cast
        let proposers: &[Address] = anchor_lang_v2::bytemuck::cast_slice(args.proposers);
        let approvers: &[Address] = anchor_lang_v2::bytemuck::cast_slice(args.approvers);

        self.wallet.bump = bumps.wallet;
        self.wallet.proposal_index = PodU64::from(0u64);
        self.wallet.intent_index = 2u8; // three intents: 0, 1, 2
        self.wallet.name_len = args.name.len() as u8;
        self.wallet.name[..args.name.len()].copy_from_slice(args.name);

        let meta_intents = [
            (
                &mut self.add_intent,
                0u8,
                IntentType::AddIntent,
                bumps.add_intent,
            ),
            (
                &mut self.remove_intent,
                1u8,
                IntentType::RemoveIntent,
                bumps.remove_intent,
            ),
            (
                &mut self.update_intent,
                2u8,
                IntentType::UpdateIntent,
                bumps.update_intent,
            ),
        ];

        for (intent, index, intent_type, bump) in meta_intents {
            intent.wallet = wallet_addr;
            intent.bump = bump;
            intent.intent_index = index;
            intent.intent_type = intent_type;
            intent.approved = 1u8;
            intent.approval_threshold = args.approval_threshold;
            intent.cancellation_threshold = args.cancellation_threshold;
            intent.timelock_seconds = PodU32::from(args.timelock_seconds);
            intent.template_offset = PodU16::ZERO;
            intent.template_len = PodU16::ZERO;
            intent.active_proposal_count = PodU16::ZERO;
            intent.proposers.set_from_slice(proposers);
            intent.approvers.set_from_slice(approvers);
        }

        Ok(())
    }
}
