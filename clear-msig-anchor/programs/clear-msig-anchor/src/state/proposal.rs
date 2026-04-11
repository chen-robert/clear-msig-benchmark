use anchor_lang_v2::prelude::*;

use crate::state::intent::DISC_LEN;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProposalStatus {
    Active = 0,
    Approved = 1,
    Executed = 2,
    Cancelled = 3,
}

unsafe impl anchor_lang_v2::bytemuck::Zeroable for ProposalStatus {}
unsafe impl anchor_lang_v2::bytemuck::Pod for ProposalStatus {}

/// Votes are tracked as a bitmap over the intent's approver list.
/// Each bit position corresponds to an approver index in the intent.
#[account]
pub struct Proposal {
    pub wallet: Address,
    pub intent: Address,
    pub proposal_index: PodU64,
    pub proposer: Address,
    pub status: ProposalStatus,
    pub proposed_at: PodI64,
    pub approved_at: PodI64,
    pub bump: u8,
    pub approval_bitmap: PodU16,
    pub cancellation_bitmap: PodU16,
    pub rent_refund: Address,
    pub params_data: PodVec<u8, 512>,
}

impl Proposal {
    pub const SPACE: usize = DISC_LEN + core::mem::size_of::<Self>();

    pub fn approval_count(&self) -> u8 {
        self.approval_bitmap.get().count_ones() as u8
    }

    pub fn cancellation_count(&self) -> u8 {
        self.cancellation_bitmap.get().count_ones() as u8
    }

    pub fn has_approved_by_index(&self, idx: u8) -> bool {
        self.approval_bitmap.get() & (1 << idx) != 0
    }

    pub fn has_cancelled_by_index(&self, idx: u8) -> bool {
        self.cancellation_bitmap.get() & (1 << idx) != 0
    }

    pub fn set_approval(&mut self, idx: u8) {
        let mask: PodU16 = (1u16 << idx).into();
        self.cancellation_bitmap &= !mask;
        self.approval_bitmap |= mask;
    }

    pub fn set_cancellation(&mut self, idx: u8) {
        let mask: PodU16 = (1u16 << idx).into();
        self.approval_bitmap &= !mask;
        self.cancellation_bitmap |= mask;
    }
}
