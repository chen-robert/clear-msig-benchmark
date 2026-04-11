use anchor_lang_v2::prelude::*;

use crate::state::intent::DISC_LEN;

#[account]
pub struct ClearWallet {
    pub bump: u8,
    pub proposal_index: PodU64,
    pub intent_index: u8,
    pub name_len: u8,
    pub name: [u8; 64],
}

impl ClearWallet {
    pub const SPACE: usize = DISC_LEN + core::mem::size_of::<Self>();

    /// Safety: validated as UTF-8 on creation.
    pub fn name(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.name[..self.name_len as usize]) }
    }
}
