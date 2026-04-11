use anchor_lang_v2::prelude::*;

use crate::state::proposal::{Proposal, ProposalStatus};

#[derive(Accounts)]
pub struct CleanupProposal {
    #[account(
        has_one = rent_refund,
        close = rent_refund,
        constraint = proposal.status == ProposalStatus::Executed
            || proposal.status == ProposalStatus::Cancelled
            @ ProgramError::InvalidArgument
    )]
    pub proposal: Account<Proposal>,
    #[account(mut)]
    pub rent_refund: UncheckedAccount,
}

impl CleanupProposal {
    pub fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}
