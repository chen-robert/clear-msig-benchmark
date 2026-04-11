#![no_std]

use anchor_lang_v2::prelude::*;

mod instructions;
use instructions::*;
mod state;
pub use state::*;
pub mod utils;

declare_id!("msigVi8dMnmLQUuCbakipEMZhzen516QRHxGz7iX5Xv");

#[program]
pub mod clear_msig_anchor {
    use super::*;

    pub fn create_wallet(
        ctx: &mut Context<CreateWallet>,
        approval_threshold: u8,
        cancellation_threshold: u8,
        timelock_seconds: u32,
        name: &[u8],
        proposers: &[[u8; 32]],
        approvers: &[[u8; 32]],
    ) -> Result<()> {
        ctx.accounts.create(
            CreateWalletArgs {
                name,
                approval_threshold,
                cancellation_threshold,
                timelock_seconds,
                proposers,
                approvers,
            },
            &ctx.bumps,
        )
    }

    pub fn propose(
        ctx: &mut Context<Propose>,
        proposal_index: u64,
        expiry: i64,
        proposer_pubkey: [u8; 32],
        signature: [u8; 64],
        params_data: &[u8],
    ) -> Result<()> {
        ctx.accounts.propose(
            proposal_index,
            ProposeArgs {
                expiry,
                proposer_pubkey: &proposer_pubkey,
                signature: &signature,
                params_data,
            },
            &ctx.bumps,
        )
    }

    pub fn approve(
        ctx: &mut Context<Approve>,
        expiry: i64,
        approver_index: u8,
        signature: [u8; 64],
    ) -> Result<()> {
        ctx.accounts.approve(ApproveArgs {
            expiry,
            approver_index,
            signature: &signature,
        })
    }

    pub fn cancel(
        ctx: &mut Context<Cancel>,
        expiry: i64,
        canceller_index: u8,
        signature: [u8; 64],
    ) -> Result<()> {
        ctx.accounts.cancel(CancelArgs {
            expiry,
            canceller_index,
            signature: &signature,
        })
    }

    pub fn execute(ctx: &mut Context<Execute>) -> Result<()> {
        instructions::execute::handler(ctx)
    }

    pub fn cleanup_proposal(ctx: &mut Context<CleanupProposal>) -> Result<()> {
        ctx.accounts.cleanup()
    }
}
