use anchor_lang_v2::prelude::*;

use crate::{
    state::{
        intent::{Intent, IntentType},
        proposal::{Proposal, ProposalStatus},
        wallet::ClearWallet,
    },
    utils::definition::*,
};

const PARAMS_DATA_MAX: usize = 512;

#[derive(Accounts)]
pub struct Execute {
    #[account(mut)]
    pub wallet: Account<ClearWallet>,
    #[account(
        mut,
        seeds = [b"vault", wallet],
        bump,
    )]
    pub vault: UncheckedAccount,
    #[account(
        mut,
        has_one = wallet,
    )]
    pub intent: Account<Intent>,
    #[account(
        mut,
        has_one = wallet,
        has_one = intent,
        constraint = proposal.status == ProposalStatus::Approved @ ProgramError::InvalidArgument
    )]
    pub proposal: Account<Proposal>,
    pub system_program: Program<System>,
}

pub fn handler(ctx: &mut Context<Execute>) -> Result<()> {
    Execute::execute(ctx)
}

impl Execute {
    pub fn execute(ctx: &mut Context<Execute>) -> Result<()> {
        let clock = Clock::get()?;
        let approved_at = ctx.accounts.proposal.approved_at.get();
        let timelock = ctx.accounts.intent.timelock_seconds.get() as i64;
        let unlock_at = approved_at
            .checked_add(timelock)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        require!(
            clock.unix_timestamp >= unlock_at,
            ProgramError::InvalidArgument
        );

        let remaining = ctx.remaining_accounts;

        match ctx.accounts.intent.intent_type {
            IntentType::AddIntent => Self::execute_add_intent(ctx, remaining)?,
            IntentType::RemoveIntent => Self::execute_remove_intent(ctx, remaining)?,
            IntentType::UpdateIntent => Self::execute_update_intent(ctx, remaining)?,
            IntentType::Custom => Self::execute_custom(ctx, remaining)?,
        }

        ctx.accounts.proposal.status = ProposalStatus::Executed;
        let count = ctx.accounts.intent.active_proposal_count.get();
        ctx.accounts.intent.active_proposal_count = PodU16::from(count.saturating_sub(1));

        Ok(())
    }

    /// remaining: [0]=payer(mut,signer), [1]=new_intent(mut)
    fn execute_add_intent(ctx: &mut Context<Execute>, remaining: &[AccountView]) -> Result<()> {
        require!(
            ctx.accounts.wallet.intent_index < u8::MAX,
            ProgramError::InvalidArgument
        );
        let new_index = ctx.accounts.wallet.intent_index + 1;
        let wallet_addr = *ctx.accounts.wallet.address();
        let params_data = ctx.accounts.proposal.params_data.as_slice();

        let (expected_pda, intent_bump) = anchor_lang_v2::find_program_address(
            &[b"intent", wallet_addr.as_ref(), &[new_index]],
            &crate::ID,
        );

        require!(remaining.len() >= 2, ProgramError::NotEnoughAccountKeys);
        let payer = remaining[0];
        let mut new_intent = remaining[1];

        require!(payer.is_signer(), ProgramError::MissingRequiredSignature);
        require_keys_eq!(
            *new_intent.address(),
            expected_pda,
            ProgramError::InvalidSeeds
        );

        let space = core::mem::size_of::<Intent>() + crate::state::intent::DISC_LEN;

        anchor_lang_v2::create_account_signed(
            &payer,
            &new_intent,
            space,
            &crate::ID,
            &[b"intent", wallet_addr.as_ref(), &[new_index], &[intent_bump]],
        )?;

        // Write discriminator + raw intent body
        let data_ptr = new_intent.data_mut_ptr();
        let disc = <Intent as anchor_lang_v2::Discriminator>::DISCRIMINATOR;
        unsafe {
            core::ptr::copy_nonoverlapping(disc.as_ptr(), data_ptr, disc.len());
            let body_len = params_data.len().min(space - disc.len());
            core::ptr::copy_nonoverlapping(
                params_data.as_ptr(),
                data_ptr.add(disc.len()),
                body_len,
            );
        }

        ctx.accounts.wallet.intent_index = new_index;
        Ok(())
    }

    /// remaining: [0]=target_intent(mut)
    fn execute_remove_intent(ctx: &mut Context<Execute>, remaining: &[AccountView]) -> Result<()> {
        let params_data = ctx.accounts.proposal.params_data.as_slice();
        require!(params_data.len() == 1, ProgramError::InvalidInstructionData);
        let target_index = params_data[0];

        require!(!remaining.is_empty(), ProgramError::NotEnoughAccountKeys);
        let mut target =
            validate_target_intent_for_modification(ctx, remaining[0], target_index)?;

        // Clear approved flag — typed write.
        target.approved = 0;

        Ok(())
    }

    /// remaining: [0]=payer(mut,signer), [1]=target_intent(mut)
    /// Rewrite an existing intent's body from proposal params.
    ///
    /// This diverges from Quasar's implementation in one meaningful way:
    /// Quasar reallocs the target account to the new body's length because
    /// its `Vec<'a, T, N>` types serialize to a variable on-chain footprint.
    /// Our port uses fixed-capacity `PodVec<T, N>` so the Intent struct has
    /// a constant `size_of::<Intent>()` and the account is always exactly
    /// `DISC_LEN + size_of::<Intent>()` bytes from init onward. Calling
    /// realloc with a smaller body would shrink the account below the
    /// fixed minimum and brick it for all future typed loads.
    ///
    /// Instead we require the client to send exactly one Intent body, cast
    /// it as a `&Intent`, and write through the typed `Account<Intent>`
    /// handle. One Pod memcpy, no raw pointer writes, no realloc, no
    /// discriminator rewrite (it's already on-chain from init).
    ///
    /// remaining: [0]=target_intent(mut)
    fn execute_update_intent(ctx: &mut Context<Execute>, remaining: &[AccountView]) -> Result<()> {
        // Copy params_data into a stack buffer so we can drop the immutable
        // borrow of ctx before calling validate_target_intent_for_modification
        // (which needs a mutable borrow of ctx).
        let mut params_buf = [0u8; PARAMS_DATA_MAX];
        let params_len = {
            let params_data = ctx.accounts.proposal.params_data.as_slice();
            require!(params_data.len() > 1, ProgramError::InvalidInstructionData);
            require!(
                params_data.len() <= PARAMS_DATA_MAX,
                ProgramError::InvalidInstructionData
            );
            params_buf[..params_data.len()].copy_from_slice(params_data);
            params_data.len()
        };
        let params_data = &params_buf[..params_len];
        let target_index = params_data[0];
        let new_body = &params_data[1..];

        require!(
            new_body.len() == core::mem::size_of::<Intent>(),
            ProgramError::InvalidInstructionData
        );
        let new_intent: &Intent = anchor_lang_v2::bytemuck::from_bytes(new_body);

        require!(!remaining.is_empty(), ProgramError::NotEnoughAccountKeys);
        let mut target = validate_target_intent_for_modification(ctx, remaining[0], target_index)?;
        *target = *new_intent;

        Ok(())
    }

    /// remaining: all accounts referenced by the intent's account definitions,
    /// EXCEPT accounts already declared in the Execute struct (vault,
    /// system_program, wallet, etc.). Those are injected automatically when
    /// a Static or Vault entry's address matches a declared account.
    #[inline(never)]
    fn execute_custom(ctx: &mut Context<Execute>, remaining: &[AccountView]) -> Result<()> {
        let params_data = ctx.accounts.proposal.params_data.as_slice();
        let intent = &ctx.accounts.intent;
        let pool = intent.byte_pool.as_slice();

        // Declared accounts available for injection (quasar rejects
        // remaining accounts that duplicate these).
        let declared: [&AccountView; 3] = [
            ctx.accounts.vault.account(),
            ctx.accounts.system_program.account(),
            ctx.accounts.wallet.account(),
        ];

        // Build account_views by walking intent account entries.
        // Vault entries and Static entries whose address matches a declared
        // account are injected directly; everything else is consumed from
        // remaining_accounts in order.
        let acct_entries = intent.accounts.as_slice();
        let mut account_views: [core::mem::MaybeUninit<AccountView>; 32] =
            unsafe { core::mem::MaybeUninit::uninit().assume_init() };
        let mut account_count = 0usize;
        let mut remaining_idx = 0usize;

        for acct_def in acct_entries {
            require!(account_count < 32, ProgramError::InvalidArgument);
            if acct_def.source_type == AccountSourceType::Vault {
                account_views[account_count].write(*ctx.accounts.vault.account());
            } else if acct_def.source_type == AccountSourceType::Static {
                let po = acct_def.pool_offset.get() as usize;
                let pl = acct_def.pool_len.get() as usize;
                let addr_bytes = pool
                    .get(po..po + pl)
                    .ok_or(ProgramError::InvalidInstructionData)?;
                require!(addr_bytes.len() >= 32, ProgramError::InvalidInstructionData);
                let addr = Address::new_from_array(
                    addr_bytes[..32]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                if let Some(dv) = declared.iter().find(|d| *d.address() == addr) {
                    account_views[account_count].write(**dv);
                } else {
                    require!(
                        remaining_idx < remaining.len(),
                        ProgramError::NotEnoughAccountKeys
                    );
                    account_views[account_count].write(remaining[remaining_idx]);
                    remaining_idx += 1;
                }
            } else {
                require!(
                    remaining_idx < remaining.len(),
                    ProgramError::NotEnoughAccountKeys
                );
                account_views[account_count].write(remaining[remaining_idx]);
                remaining_idx += 1;
            }
            account_count += 1;
        }

        // Validate remaining accounts match intent definitions
        validate_remaining_accounts(
            &account_views,
            account_count,
            intent,
            params_data,
            ctx.accounts.vault.address(),
        )?;

        let vault_bump = ctx.bumps.vault;
        let wallet_addr = *ctx.accounts.wallet.address();
        let bump_ref = [vault_bump];
        let vault_seeds = solana_instruction_view::seeds!(b"vault", wallet_addr.as_ref(), &bump_ref);
        let signer = solana_instruction_view::cpi::Signer::from(&vault_seeds);
        execute_cpi_loop(
            &signer,
            intent,
            params_data,
            &account_views,
            account_count,
        )
    }
}

/// CPI execution loop in its own stack frame (DynCpiCall is large).
#[inline(never)]
fn execute_cpi_loop(
    vault_signer: &solana_instruction_view::cpi::Signer<'_, '_>,
    intent: &Intent,
    params_data: &[u8],
    account_views: &[core::mem::MaybeUninit<AccountView>; 32],
    account_count: usize,
) -> Result<()> {
    use solana_instruction_view::InstructionView;

    let ix_entries = intent.instructions.as_slice();
    let seg_entries = intent.data_segments.as_slice();
    let acct_entries = intent.accounts.as_slice();
    let pool = intent.byte_pool.as_slice();

    for ix_entry in ix_entries {
        let prog_idx = ix_entry.program_account_index as usize;
        require!(prog_idx < account_count, ProgramError::NotEnoughAccountKeys);
        let program = unsafe { account_views[prog_idx].assume_init_ref() };

        let mut cpi_ix_accounts: [core::mem::MaybeUninit<solana_instruction_view::InstructionAccount>; 32] =
            unsafe { core::mem::MaybeUninit::uninit().assume_init() };
        let mut cpi_accts: [core::mem::MaybeUninit<solana_instruction_view::cpi::CpiAccount>; 32] =
            unsafe { core::mem::MaybeUninit::uninit().assume_init() };

        // Push accounts
        let acct_idx_offset = ix_entry.account_indexes_offset.get() as usize;
        let acct_idx_len = ix_entry.account_indexes_len.get() as usize;
        let acct_indexes = &pool[acct_idx_offset..acct_idx_offset + acct_idx_len];

        require!(
            acct_indexes.len() <= 16,
            ProgramError::InvalidInstructionData
        );

        for (i, &idx) in acct_indexes.iter().enumerate() {
            let idx = idx as usize;
            require!(idx < account_count, ProgramError::NotEnoughAccountKeys);
            let view = unsafe { account_views[idx].assume_init_ref() };
            let acct_def = &acct_entries[idx];
            cpi_ix_accounts[i].write(solana_instruction_view::InstructionAccount::new(
                view.address(),
                acct_def.is_writable,
                acct_def.is_signer,
            ));
            cpi_accts[i].write(solana_instruction_view::cpi::CpiAccount::from(view));
        }

        // Build instruction data from segments directly into the CPI buffer
        let mut ix_data = [0u8; 1024];
        let mut ix_len = 0usize;
        let seg_start = ix_entry.segments_start.get() as usize;
        let seg_count = ix_entry.segments_count.get() as usize;

        for seg in &seg_entries[seg_start..seg_start + seg_count] {
            let seg_pool = &pool[seg.pool_offset.get() as usize
                ..(seg.pool_offset.get() + seg.pool_len.get()) as usize];
            match seg.segment_type {
                SegmentType::Literal => {
                    require!(
                        ix_len + seg_pool.len() <= 1024,
                        ProgramError::InvalidInstructionData
                    );
                    ix_data[ix_len..ix_len + seg_pool.len()].copy_from_slice(seg_pool);
                    ix_len += seg_pool.len();
                }
                SegmentType::Param => {
                    require!(seg_pool.len() >= 2, ProgramError::InvalidInstructionData);
                    let param_idx = seg_pool[0];
                    let encoding = DataEncoding::from_u8(seg_pool[1])
                        .ok_or(ProgramError::InvalidInstructionData)?;
                    let val = intent.read_param_bytes(params_data, param_idx)?;
                    let size = encoding.byte_size();
                    require!(val.len() >= size, ProgramError::InvalidInstructionData);
                    require!(ix_len + size <= 1024, ProgramError::InvalidInstructionData);
                    ix_data[ix_len..ix_len + size].copy_from_slice(&val[..size]);
                    ix_len += size;
                }
            }
        }

        let instruction = InstructionView {
            program_id: program.address(),
            accounts: unsafe {
                core::slice::from_raw_parts(cpi_ix_accounts[0].as_ptr(), acct_indexes.len())
            },
            data: &ix_data[..ix_len],
        };
        let signers = [vault_signer.clone()];
        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                core::slice::from_raw_parts(cpi_accts[0].as_ptr(), acct_indexes.len()),
                &signers,
            );
        }
    }

    Ok(())
}

/// Validates that each remaining account matches the address specified by the
/// intent definition's account entries (Static, Param, PdaDerived, HasOne, Vault).
#[inline(never)]
fn validate_remaining_accounts(
    account_views: &[core::mem::MaybeUninit<AccountView>; 32],
    account_count: usize,
    intent: &Intent,
    params_data: &[u8],
    vault_address: &Address,
) -> Result<()> {
    let acct_entries = intent.accounts.as_slice();
    let pool = intent.byte_pool.as_slice();

    require!(
        account_count == acct_entries.len(),
        ProgramError::InvalidArgument
    );

    for (i, acct_def) in acct_entries.iter().enumerate() {
        let current_addr = *unsafe { account_views[i].assume_init_ref() }.address();
        let po = acct_def.pool_offset.get() as usize;
        let pl = acct_def.pool_len.get() as usize;

        match acct_def.source_type {
            AccountSourceType::Static => {
                let pool_data = pool
                    .get(po..po + pl)
                    .ok_or(ProgramError::InvalidInstructionData)?;
                require!(pool_data.len() >= 32, ProgramError::InvalidInstructionData);
                let expected = Address::new_from_array(
                    pool_data[..32]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                require_keys_eq!(current_addr, expected, ProgramError::InvalidArgument);
            }
            AccountSourceType::Param => {
                let pool_data = pool
                    .get(po..po + pl)
                    .ok_or(ProgramError::InvalidInstructionData)?;
                require!(!pool_data.is_empty(), ProgramError::InvalidInstructionData);
                let addr_bytes = intent.read_param_bytes(params_data, pool_data[0])?;
                require!(addr_bytes.len() >= 32, ProgramError::InvalidInstructionData);
                let expected = Address::new_from_array(
                    addr_bytes[..32]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                require_keys_eq!(current_addr, expected, ProgramError::InvalidArgument);
            }
            AccountSourceType::PdaDerived => {
                let pool_data = pool
                    .get(po..po + pl)
                    .ok_or(ProgramError::InvalidInstructionData)?;
                validate_pda_account(
                    &current_addr,
                    pool_data,
                    account_views,
                    account_count,
                    intent,
                    params_data,
                )?;
            }
            AccountSourceType::HasOne => {
                let pool_data = pool
                    .get(po..po + pl)
                    .ok_or(ProgramError::InvalidInstructionData)?;
                require!(pool_data.len() >= 3, ProgramError::InvalidInstructionData);
                let acct_idx = pool_data[0] as usize;
                let byte_offset = u16::from_le_bytes([pool_data[1], pool_data[2]]) as usize;

                require!(acct_idx < account_count, ProgramError::NotEnoughAccountKeys);
                let ref_view = unsafe { account_views[acct_idx].assume_init_ref() };
                let data_len = ref_view.data_len();
                require!(
                    byte_offset + 32 <= data_len,
                    ProgramError::InvalidInstructionData
                );
                let addr_bytes = unsafe {
                    core::slice::from_raw_parts(ref_view.data_ptr().add(byte_offset), 32)
                };
                let expected = Address::new_from_array(
                    addr_bytes
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                require_keys_eq!(current_addr, expected, ProgramError::InvalidArgument);
            }
            AccountSourceType::Vault => {
                require_keys_eq!(
                    current_addr,
                    *vault_address,
                    ProgramError::InvalidArgument
                );
            }
        }
    }

    Ok(())
}

/// PDA account validation in its own stack frame (seed buffers are large).
#[inline(never)]
fn validate_pda_account(
    current_addr: &Address,
    pool_data: &[u8],
    account_views: &[core::mem::MaybeUninit<AccountView>; 32],
    account_count: usize,
    intent: &Intent,
    params_data: &[u8],
) -> Result<()> {
    let pool = intent.byte_pool.as_slice();
    let seed_entries = intent.seeds.as_slice();
    require!(pool_data.len() >= 5, ProgramError::InvalidInstructionData);
    let prog_acct_idx = pool_data[0] as usize;
    let seeds_start = u16::from_le_bytes([pool_data[1], pool_data[2]]) as usize;
    let seeds_count = u16::from_le_bytes([pool_data[3], pool_data[4]]) as usize;

    require!(
        prog_acct_idx < account_count,
        ProgramError::NotEnoughAccountKeys
    );
    let program_addr = *unsafe { account_views[prog_acct_idx].assume_init_ref() }.address();

    require!(seeds_count <= 16, ProgramError::InvalidInstructionData);
    let mut seed_bufs = [[0u8; 32]; 16];
    let mut seed_lens = [0usize; 16];

    for s in 0..seeds_count {
        let se = seed_entries
            .get(seeds_start + s)
            .ok_or(ProgramError::InvalidInstructionData)?;
        let se_start = se.pool_offset.get() as usize;
        let se_len = se.pool_len.get() as usize;
        let se_pool = pool
            .get(se_start..se_start + se_len)
            .ok_or(ProgramError::InvalidInstructionData)?;

        match se.seed_type {
            SeedType::Literal => {
                require!(se_pool.len() <= 32, ProgramError::InvalidInstructionData);
                seed_bufs[s][..se_pool.len()].copy_from_slice(se_pool);
                seed_lens[s] = se_pool.len();
            }
            SeedType::ParamRef => {
                require!(!se_pool.is_empty(), ProgramError::InvalidInstructionData);
                let val = intent.read_param_bytes(params_data, se_pool[0])?;
                require!(val.len() <= 32, ProgramError::InvalidInstructionData);
                seed_bufs[s][..val.len()].copy_from_slice(val);
                seed_lens[s] = val.len();
            }
            SeedType::AccountRef => {
                require!(!se_pool.is_empty(), ProgramError::InvalidInstructionData);
                let acct_idx = se_pool[0] as usize;
                require!(acct_idx < account_count, ProgramError::NotEnoughAccountKeys);
                let addr = *unsafe { account_views[acct_idx].assume_init_ref() }.address();
                seed_bufs[s].copy_from_slice(addr.as_ref());
                seed_lens[s] = 32;
            }
        }
    }

    let mut seed_refs: [&[u8]; 16] = [&[]; 16];
    for s in 0..seeds_count {
        seed_refs[s] = &seed_bufs[s][..seed_lens[s]];
    }

    let (expected, _) = anchor_lang_v2::find_program_address(&seed_refs[..seeds_count], &program_addr);
    require_keys_eq!(*current_addr, expected, ProgramError::InvalidArgument);
    Ok(())
}

/// Validates the target intent for modification: PDA matches, writable,
/// and has no active proposals. Returns the loaded Account<Intent>.
fn validate_target_intent_for_modification(
    ctx: &mut Context<Execute>,
    view: AccountView,
    target_index: u8,
) -> Result<Account<Intent>> {
    let (expected_pda, _) = anchor_lang_v2::find_program_address(
        &[b"intent", ctx.accounts.wallet.address().as_ref(), &[target_index]],
        &crate::ID,
    );
    require_keys_eq!(*view.address(), expected_pda, ProgramError::InvalidSeeds);
    require!(view.is_writable(), ProgramError::Immutable);

    let target: Account<Intent> = Account::load_mut(view, &crate::ID)?;
    require!(
        target.active_proposal_count.get() == 0,
        ProgramError::InvalidArgument
    );
    Ok(target)
}
