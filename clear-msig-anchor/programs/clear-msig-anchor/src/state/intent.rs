use anchor_lang_v2::prelude::*;

use crate::utils::definition::*;

/// Anchor v2 account discriminator length (8 bytes).
pub const DISC_LEN: usize = 8;

/// Byte offset of `Intent::approved` within the account data (including disc).
pub const INTENT_APPROVED_OFFSET: usize =
    DISC_LEN + core::mem::offset_of!(Intent, approved);

/// Byte offset of `Intent::active_proposal_count` within the account data (including disc).
pub const INTENT_ACTIVE_PROPOSAL_COUNT_OFFSET: usize =
    DISC_LEN + core::mem::offset_of!(Intent, active_proposal_count);

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IntentType {
    AddIntent = 0,
    RemoveIntent = 1,
    UpdateIntent = 2,
    Custom = 3,
}

unsafe impl anchor_lang_v2::bytemuck::Zeroable for IntentType {}
unsafe impl anchor_lang_v2::bytemuck::Pod for IntentType {}

impl IntentType {
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::AddIntent),
            1 => Ok(Self::RemoveIntent),
            2 => Ok(Self::UpdateIntent),
            3 => Ok(Self::Custom),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

/// The intent account IS the definition. No separate blob — all fields
/// are directly on the account struct.
#[account]
pub struct Intent {
    // --- Intent identity ---
    pub wallet: Address,
    pub bump: u8,
    pub intent_index: u8,
    pub intent_type: IntentType,
    pub approved: u8,

    // --- Governance ---
    pub approval_threshold: u8,
    pub cancellation_threshold: u8,
    pub timelock_seconds: PodU32,
    pub template_offset: PodU16,
    pub template_len: PodU16,
    /// Number of open (Active or Approved) proposals using this intent.
    /// Prevents intent modification while proposals are in flight.
    pub active_proposal_count: PodU16,

    // --- Definition (fixed-capacity, zero-copy) ---
    pub proposers: PodVec<Address, 16>,
    pub approvers: PodVec<Address, 16>,
    pub params: PodVec<ParamEntry, 8>,
    pub accounts: PodVec<AccountEntry, 32>,
    pub instructions: PodVec<InstructionEntry, 12>,
    pub data_segments: PodVec<DataSegmentEntry, 32>,
    pub seeds: PodVec<SeedEntry, 32>,
    /// Byte pool for variable data: param names, seed literals,
    /// instruction literal data, static addresses, template string.
    pub byte_pool: PodVec<u8, 4096>,
}

impl Intent {
    pub const SPACE: usize = DISC_LEN + core::mem::size_of::<Self>();

    pub fn is_approved(&self) -> bool {
        self.approved != 0
    }

    pub fn is_proposer(&self, address: &Address) -> bool {
        self.proposers.iter().any(|a| a == address)
    }

    pub fn is_approver(&self, address: &Address) -> bool {
        self.approvers.iter().any(|a| a == address)
    }

    /// Returns the index of this approver in the approvers list, or None.
    pub fn approver_index(&self, address: &Address) -> Option<u8> {
        self.approvers
            .iter()
            .position(|a| a == address)
            .map(|i| i as u8)
    }

    pub fn template_str(&self) -> Result<&str> {
        let pool = self.byte_pool.as_slice();
        let offset = self.template_offset.get() as usize;
        let len = self.template_len.get() as usize;
        if offset + len > pool.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        core::str::from_utf8(&pool[offset..offset + len])
            .map_err(|_| ProgramError::InvalidInstructionData)
    }

    pub fn pool_slice(&self, offset: u16, len: u16) -> Result<&[u8]> {
        let pool = self.byte_pool.as_slice();
        let start = offset as usize;
        let end = start + len as usize;
        pool.get(start..end).ok_or(ProgramError::InvalidInstructionData)
    }

    pub fn param_name(&self, param: &ParamEntry) -> Result<&str> {
        let bytes = self.pool_slice(param.name_offset.get(), param.name_len.get())?;
        core::str::from_utf8(bytes).map_err(|_| ProgramError::InvalidInstructionData)
    }

    pub fn read_param_bytes<'a>(
        &self,
        params_data: &'a [u8],
        param_index: u8,
    ) -> Result<&'a [u8]> {
        let params = self.params.as_slice();
        let mut offset = 0usize;
        for i in 0..param_index as usize {
            let param = params.get(i).ok_or(ProgramError::InvalidInstructionData)?;
            let pt = param.param_type;
            offset += param_byte_size(pt, params_data, offset)?;
        }
        let param = params
            .get(param_index as usize)
            .ok_or(ProgramError::InvalidInstructionData)?;
        let pt = param.param_type;
        let size = param_byte_size(pt, params_data, offset)?;
        params_data
            .get(offset..offset + size)
            .ok_or(ProgramError::InvalidInstructionData)
    }

    pub fn validate_param_constraints(&self, params_data: &[u8]) -> Result<()> {
        let params = self.params.as_slice();
        let mut offset = 0usize;
        for param in params {
            let pt = param.param_type;
            match pt {
                ParamType::Address => {
                    require!(
                        offset + 32 <= params_data.len(),
                        ProgramError::InvalidInstructionData
                    );
                    offset += 32;
                }
                ParamType::U64 => {
                    require!(
                        offset + 8 <= params_data.len(),
                        ProgramError::InvalidInstructionData
                    );
                    let val = u64::from_le_bytes(
                        params_data[offset..offset + 8]
                            .try_into()
                            .map_err(|_| ProgramError::InvalidInstructionData)?,
                    );
                    if param.constraint_type == ConstraintType::LessThanU64 {
                        require!(
                            val < param.constraint_value.get(),
                            ProgramError::InvalidArgument
                        );
                    } else if param.constraint_type == ConstraintType::GreaterThanU64 {
                        require!(
                            val > param.constraint_value.get(),
                            ProgramError::InvalidArgument
                        );
                    }
                    offset += 8;
                }
                ParamType::I64 => {
                    require!(
                        offset + 8 <= params_data.len(),
                        ProgramError::InvalidInstructionData
                    );
                    offset += 8;
                }
                ParamType::String => {
                    require!(
                        offset < params_data.len(),
                        ProgramError::InvalidInstructionData
                    );
                    let len = params_data[offset] as usize;
                    offset += 1;
                    require!(
                        offset + len <= params_data.len(),
                        ProgramError::InvalidInstructionData
                    );
                    core::str::from_utf8(&params_data[offset..offset + len])
                        .map_err(|_| ProgramError::InvalidInstructionData)?;
                    offset += len;
                }
                ParamType::Bool | ParamType::U8 => {
                    require!(
                        offset < params_data.len(),
                        ProgramError::InvalidInstructionData
                    );
                    offset += 1;
                }
                ParamType::U16 => {
                    require!(
                        offset + 2 <= params_data.len(),
                        ProgramError::InvalidInstructionData
                    );
                    offset += 2;
                }
                ParamType::U32 => {
                    require!(
                        offset + 4 <= params_data.len(),
                        ProgramError::InvalidInstructionData
                    );
                    offset += 4;
                }
                ParamType::U128 => {
                    require!(
                        offset + 16 <= params_data.len(),
                        ProgramError::InvalidInstructionData
                    );
                    offset += 16;
                }
            }
        }
        Ok(())
    }
}
