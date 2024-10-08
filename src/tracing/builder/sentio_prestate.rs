//! Sentio trace builder

use crate::tracing::{
    types::{CallTraceNode},
};
use alloy_primitives::{keccak256, Address, B256, B512};
use revm::{db::DatabaseRef};
use std::collections::{btree_map, BTreeMap, HashMap};
use std::default::Default;
use std::fmt::Debug;
use alloy_rpc_types_trace::geth::{AccountChangeKind};
use alloy_rpc_types_trace::geth::sentio_prestate::{AccountState, SentioPrestateResult, SentioPrestateTracerConfig, State};
use revm::interpreter::OpCode;
use revm::primitives::ResultAndState;
use crate::tracing::utils::{load_account_code};

#[derive(Clone, Debug)]
pub struct SentioPrestateTraceBuilder {
    /// Recorded trace nodes.
    nodes: Vec<CallTraceNode>,
    prestate_config: SentioPrestateTracerConfig
}

struct AdditionalInfo {
    pub code_address: HashMap<Address, Address>,
    pub code_address_by_slot: HashMap<Address, BTreeMap<B256, Address>>,
    pub mapping_keys: HashMap<Address, BTreeMap<B256, B256>>,
}

impl SentioPrestateTraceBuilder {
    pub fn new(nodes: Vec<CallTraceNode>, prestate_config: SentioPrestateTracerConfig) -> Self {
        Self { nodes, prestate_config }
    }

    pub fn sentio_prestate_traces<DB: DatabaseRef>(
        &self,
        ResultAndState { state, .. }: &ResultAndState,
        db: DB,
    ) -> Result<SentioPrestateResult, DB::Error> {
        let account_diffs = state.iter().map(|(addr, acc)| (*addr, acc));

        let mut ret = if !self.prestate_config.diff_mode {
            let mut pre = State::default();
            for (addr, changed_acc) in account_diffs {
                let db_acc = db.basic_ref(addr)?.unwrap_or_default();
                let code = load_account_code(&db, &db_acc);
                let mut acc_state = AccountState::from_account_info(db_acc.nonce, db_acc.balance, code);
                for (key, slot) in changed_acc.storage.iter() {
                    acc_state.storage.insert((*key).into(), slot.original_value.into());
                }
                pre.insert(addr, acc_state);
            }
            SentioPrestateResult {
                pre,
                post: None,
            }
        } else {
            let mut pre = State::default();
            let mut post = State::default();
            let mut account_change_kinds = HashMap::with_capacity(account_diffs.len());
            for (addr, changed_acc) in account_diffs {
                let db_acc = db.basic_ref(addr)?.unwrap_or_default();

                let pre_code = load_account_code(&db, &db_acc);

                let mut pre_state = AccountState::from_account_info(db_acc.nonce, db_acc.balance, pre_code);
                let mut post_state = AccountState::from_account_info(
                    changed_acc.info.nonce,
                    changed_acc.info.balance,
                    changed_acc.info.code.as_ref().map(|code| code.original_bytes()),
                );

                // handle storage changes
                for (key, slot) in changed_acc.storage.iter().filter(|(_, slot)| slot.is_changed())
                {
                    pre_state.storage.insert((*key).into(), slot.original_value.into());
                    post_state.storage.insert((*key).into(), slot.present_value.into());
                }

                pre.insert(addr, pre_state);
                post.insert(addr, post_state);

                // determine the change type
                let pre_change = if changed_acc.is_created() {
                    AccountChangeKind::Create
                } else {
                    AccountChangeKind::Modify
                };
                let post_change = if changed_acc.is_selfdestructed() {
                    AccountChangeKind::SelfDestruct
                } else {
                    AccountChangeKind::Modify
                };

                account_change_kinds.insert(addr, (pre_change, post_change));
            }

            // ensure we're only keeping changed entries
            pre.retain(|address, pre| {
                if let btree_map::Entry::Occupied(entry) = post.entry(*address) {
                    if entry.get() == pre {
                        // remove unchanged account state from both sets
                        entry.remove();
                        return false;
                    }
                }
                true
            });
            for state in pre.values_mut().chain(post.values_mut()) {
                state.storage.retain(|_, value| *value != B256::ZERO);
            }

            self.diff_traces(&mut pre, &mut post, account_change_kinds);
            SentioPrestateResult {
                pre,
                post: Some(post),
            }
        };
        for node in &self.nodes {
            let caller = node.trace.address;
            for step in &node.trace.steps {
                let Some(stack) = &step.stack else {
                    continue;
                };
                let code_address = step.contract;
                match step.op {
                    OpCode::SLOAD | OpCode::SSTORE => {
                        if let Some(entry) = ret.pre.get_mut(&caller) {
                            let slot = B256::from(stack.last().unwrap().to_be_bytes());
                            entry.code_address = Some(code_address);
                            entry.code_address_by_slot.insert(slot, code_address);
                        }
                    }
                    OpCode::KECCAK256 => {
                        if let Some(entry) = ret.pre.get_mut(&caller) {
                            let memory = &step.memory.clone().unwrap();
                            let offset = stack.last().unwrap().to::<usize>();
                            let raw_key = &memory.as_bytes()[offset..offset + 64];
                            let hash_of_key = keccak256(raw_key);
                            entry.mapping_keys.insert(B512::from_slice(raw_key), hash_of_key);

                            let base_slot = &raw_key[32..];
                            entry.code_address_by_slot.insert(B256::from_slice(base_slot), code_address);
                            entry.code_address_by_slot.insert(hash_of_key, code_address);
                        }
                    }
                    _ => { }
                }
            }
        }
        if let Some(post) = &mut ret.post {
            for (address, state) in &ret.pre {
                let Some(post_state) = post.get_mut(address) else {
                    post.insert(*address, AccountState {
                        mapping_keys: state.mapping_keys.clone(),
                        ..AccountState::default()
                    });
                    continue;
                };
                post_state.mapping_keys = state.mapping_keys.clone();
            }
        }
        Ok(ret)
    }

    /// Returns the difference between the pre and post state of the transaction depending on the
    /// kind of changes of that account (pre,post)
    fn diff_traces(
        &self,
        pre: &mut BTreeMap<Address, AccountState>,
        post: &mut BTreeMap<Address, AccountState>,
        change_type: HashMap<Address, (AccountChangeKind, AccountChangeKind)>,
    ) {
        post.retain(|addr, post_state| {
            // Don't keep destroyed accounts in the post state
            if change_type.get(addr).map(|ty| ty.1.is_selfdestruct()).unwrap_or(false) {
                return false;
            }
            if let Some(pre_state) = pre.get(addr) {
                // remove any unchanged account info
                post_state.remove_matching_account_info(pre_state);
            }

            true
        });

        // Don't keep created accounts in the pre state
        pre.retain(|addr, _pre_state| {
            // only keep accounts that are not created
            change_type.get(addr).map(|ty| !ty.0.is_created()).unwrap_or(true)
        });
    }
}
