use anchor_lang_v2::prelude::*;

use crate::{
    state::{
        intent::Intent,
        proposal::{Proposal, ProposalStatus},
        wallet::ClearWallet,
    },
    utils::message::{MessageBuilder, MessageContext},
};

#[derive(Accounts)]
#[instruction(proposal_index: u64)]
pub struct Propose {
    #[account(mut)]
    pub payer: Signer,
    #[account(mut)]
    pub wallet: Account<ClearWallet>,
    #[account(
        mut,
        has_one = wallet,
        constraint = intent.is_approved() @ ProgramError::InvalidArgument,
    )]
    pub intent: Account<Intent>,
    #[account(
        init,
        payer = payer,
        seeds = [b"proposal", intent, &proposal_index.to_le_bytes()],
        bump,
        space = Proposal::SPACE,
    )]
    pub proposal: Account<Proposal>,
    pub system_program: Program<System>,
}

pub struct ProposeArgs<'a> {
    pub expiry: i64,
    pub proposer_pubkey: &'a [u8; 32],
    pub signature: &'a [u8; 64],
    pub params_data: &'a [u8],
}

impl Propose {
    pub fn propose(
        &mut self,
        proposal_index: u64,
        args: ProposeArgs<'_>,
        bumps: &ProposeBumps,
    ) -> Result<()> {
        // Verify the client-provided proposal_index matches the wallet's current index
        require!(
            proposal_index == self.wallet.proposal_index.get(),
            ProgramError::InvalidArgument
        );

        let clock = Clock::get()?;
        require!(args.expiry > clock.unix_timestamp, ProgramError::InvalidArgument);

        let proposer_addr = Address::new_from_array(*args.proposer_pubkey);
        require!(self.intent.is_proposer(&proposer_addr), ProgramError::MissingRequiredSignature);

        if self.intent.intent_type == crate::state::intent::IntentType::Custom {
            self.intent.validate_param_constraints(args.params_data)?;
        }

        let mut msg_buf = MessageBuilder::new();
        msg_buf.build_message_for_intent(
            &MessageContext { expiry: args.expiry, action: "propose", wallet_name: self.wallet.name(), proposal_index },
            &self.intent,
            args.params_data,
        )?;

        brine_ed25519::sig_verify(args.proposer_pubkey, args.signature, msg_buf.as_bytes())
            .map_err(|_| ProgramError::InvalidArgument)?;

        self.proposal.wallet = *self.wallet.address();
        self.proposal.intent = *self.intent.address();
        self.proposal.proposal_index = PodU64::from(proposal_index);
        self.proposal.proposer = proposer_addr;
        self.proposal.status = ProposalStatus::Active;
        self.proposal.proposed_at = PodI64::from(clock.unix_timestamp);
        self.proposal.approved_at = PodI64::ZERO;
        self.proposal.bump = bumps.proposal;
        self.proposal.approval_bitmap = PodU16::ZERO;
        self.proposal.cancellation_bitmap = PodU16::ZERO;
        self.proposal.rent_refund = *self.payer.address();
        self.proposal.params_data.set_from_slice(args.params_data);

        self.intent.active_proposal_count = PodU16::from(self.intent.active_proposal_count.get().checked_add(1).ok_or(ProgramError::InvalidArgument)?);
        self.wallet.proposal_index = PodU64::from(proposal_index.checked_add(1).ok_or(ProgramError::ArithmeticOverflow)?);
        Ok(())
    }
}
