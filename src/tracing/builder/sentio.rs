//! Sentio trace builder

use crate::tracing::types::{CallTraceNode, RecordedMemory};
use crate::tracing::types::{CallTraceStep, TraceMemberOrder};
use crate::tracing::utils::maybe_revert_reason;
use crate::tracing::{EvalCtx, Expr, OpCode};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rpc_types_trace::geth::sentio::{
    FunctionInfo, SentioReceipt, SentioTrace, SentioTracerConfig, StorageKey,
};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct SentioTraceBuilder {
    /// Recorded trace nodes.
    nodes: Vec<CallTraceNode>,

    // address => (pc => function)
    function_map: HashMap<Address, HashMap<usize, InternalFunctionInfo>>,
    // address => (pc => bool)
    call_map: HashMap<Address, HashSet<usize>>,

    tracer_config: SentioTracerConfig,

    extra_capture_rules: Vec<Expr>,

    origin: Address,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InternalSentioTrace {
    pub trace: SentioTrace,
    pub exit_pc: Option<usize>,
    pub function: Option<InternalFunctionInfo>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InternalFunctionInfo {
    pub function_info: FunctionInfo,
    pub address: Address,
}

impl SentioTraceBuilder {
    pub fn new(
        nodes: Vec<CallTraceNode>,
        origin: Option<Address>,
        config: SentioTracerConfig,
    ) -> Self {
        let tracer_config = config.clone();
        let mut function_map: HashMap<Address, HashMap<usize, InternalFunctionInfo>> =
            HashMap::new();
        for (address, function_infos) in config.functions.into_iter() {
            let function_by_pc = function_infos
                .into_iter()
                .map(|function_info| {
                    (function_info.pc, InternalFunctionInfo { function_info, address })
                })
                .collect();
            function_map.insert(address, function_by_pc);
        }
        let mut call_map: HashMap<Address, HashSet<usize>> = HashMap::new();
        for (address, pcs) in config.calls.into_iter() {
            let pc_set = pcs.into_iter().collect();
            call_map.insert(address, pc_set);
        }
        let extra_capture_rules =
            config.extra_capture_rules.iter().map(|e| Expr::new(e).unwrap()).collect::<Vec<Expr>>();
        let origin = origin.unwrap_or(nodes[0].trace.caller);
        Self { nodes, function_map, call_map, extra_capture_rules, origin, tracer_config }
    }

    pub fn sentio_traces(
        &self,
        gas_used: u64,
        gas_refunded: u64,
        receipt: Option<SentioReceipt>,
    ) -> SentioTrace {
        SentioTrace {
            receipt,
            gas_used: U256::from(gas_used),
            refund: Some(U256::from(gas_refunded)),
            tracer_config: if self.tracer_config.debug {
                Some(self.tracer_config.clone())
            } else {
                None
            },
            ..self.transform_call(&self.nodes[0], 0, 0).trace
        }
    }

    fn get_function_info(&self, address: &Address, pc: &usize) -> Option<&InternalFunctionInfo> {
        if let Some(functions) = self.function_map.get(address) {
            return functions.get(pc);
        }
        None
    }

    fn is_call(&self, address: &Address, pc: &usize) -> bool {
        if let Some(calls) = self.call_map.get(address) {
            return calls.contains(pc);
        }
        false
    }

    fn transform_call(
        &self,
        node: &CallTraceNode,
        inst_start_idx: usize,
        call_pc: usize,
    ) -> InternalSentioTrace {
        let trace = &node.trace;
        let root = InternalSentioTrace {
            trace: SentioTrace {
                typ: trace.kind.to_string(),
                pc: call_pc,
                start_index: inst_start_idx,
                gas: U256::from(trace.gas_limit),
                gas_used: U256::from(trace.gas_used),
                from: Some(trace.caller.to_string().to_lowercase()),
                to: Some(trace.address.to_string().to_lowercase()),
                code_address: Some(trace.address.to_string().to_lowercase()),
                input: Some(trace.data.clone()),
                value: Some(trace.value),
                output: Some(trace.output.clone()),
                error: if trace.success {
                    None
                } else if trace.is_revert() {
                    Some("execution reverted".to_string())
                } else {
                    Some(format!("{:?}", trace.status))
                },
                revert_reason: if trace.is_revert() {
                    maybe_revert_reason(trace.output.as_ref())
                } else {
                    None
                },
                ..Default::default()
            },
            exit_pc: None,
            function: None,
        };

        let mut last_step: Option<&CallTraceStep> = None;
        let mut last_pc: usize = call_pc;
        let mut next_inst_idx = inst_start_idx;

        let mut frames: Vec<InternalSentioTrace> = vec![root];

        let mut entry_pc = HashSet::<usize>::new();
        if !trace.kind.is_any_create()
            && !trace.maybe_precompile.unwrap_or(false)
            && trace.data.len() >= 4
        {
            let sig_hash = trace.data.slice(0..4);
            if let Some(functions) = self.function_map.get(&trace.address) {
                for (pc, function) in functions {
                    if function.function_info.signature_hash == sig_hash {
                        entry_pc.insert(*pc);
                    }
                }
            }
        }
        let mut entry_found = false;
        let code_address = node.trace.address;
        let mut prev_sload_frame: Option<SentioTrace> = None;

        for i in &node.ordering {
            match i {
                TraceMemberOrder::Call(child_idx) => {
                    let child_trace = self.transform_call(
                        &self.nodes[node.children[*child_idx]],
                        next_inst_idx,
                        last_pc,
                    );
                    next_inst_idx = child_trace.trace.end_index.clone();
                    frames.last_mut().unwrap().trace.traces.push(Box::from(child_trace.trace));
                }
                TraceMemberOrder::Step(step_idx) => {
                    let step = &trace.steps[*step_idx];
                    if let Some(ref sload_frame) = prev_sload_frame {
                        let stack = step.stack.as_ref().unwrap();
                        let value = B256::from(stack.last().unwrap().to_be_bytes());
                        frames.last_mut().unwrap().trace.traces.push(Box::from(SentioTrace {
                            storage_value: Some(value),
                            ..sload_frame.clone()
                        }));
                        prev_sload_frame = None;
                    }

                    last_step = Some(step);
                    last_pc = step.pc;
                    next_inst_idx += 1;

                    if !entry_found && entry_pc.contains(&last_pc) {
                        let Some(root) = frames.first_mut() else {
                            panic!("no root call");
                        };
                        root.trace.pc = last_pc;
                        root.trace.start_index = next_inst_idx - 1;
                        entry_found = true;
                    }

                    let base_frame = || SentioTrace {
                        typ: step.op.to_string(),
                        pc: last_pc,
                        start_index: next_inst_idx - 1,
                        end_index: next_inst_idx,
                        gas: U256::from(step.gas_remaining),
                        gas_used: U256::from(step.gas_cost),
                        ..Default::default()
                    };

                    match step.op {
                        OpCode::JUMPDEST => {
                            if !self.tracer_config.with_internal_calls {
                                continue;
                            }

                            // check internal function exit
                            let mut is_exit = false;
                            for (i, frame) in frames.iter().rev().enumerate() {
                                if frame.function.is_none() {
                                    continue;
                                };
                                if frame.exit_pc == Some(last_pc) {
                                    let frames_to_pop = i + 1;
                                    if frames_to_pop > 1 {
                                        println!("tail call optimization size: {}", frames_to_pop);
                                    }
                                    for _ in 0..frames_to_pop {
                                        let mut frame = frames.pop().unwrap();
                                        let InternalFunctionInfo {
                                            function_info: function,
                                            address,
                                        } = &frame.function.unwrap();
                                        let stack = step.stack.as_ref().unwrap();
                                        let output_enough = function.output_size <= stack.len();
                                        if !output_enough {
                                            println!("stack size not enough, stack: {}, output_size: {}, address: {}, function: {}, pc: {}", stack.len(), function.output_size, address, function.name, last_pc);
                                            if step.is_error() {
                                                println!(
                                                    "stack size not enough has error, err: {}",
                                                    step.as_error().unwrap()
                                                )
                                            }
                                        }
                                        frame.trace = SentioTrace {
                                            end_index: next_inst_idx - 1,
                                            gas_used: frame.trace.gas
                                                - U256::from(step.gas_remaining),
                                            output_stack: output_enough
                                                .then(|| copy_stack(stack, function.output_size)),
                                            output_memory: function.output_memory.then(|| {
                                                step.memory.clone().unwrap().memory_chunks()
                                            }),
                                            ..frame.trace
                                        };
                                        frames
                                            .last_mut()
                                            .unwrap()
                                            .trace
                                            .traces
                                            .push(Box::from(frame.trace));
                                    }
                                    is_exit = true;
                                    break;
                                }
                            }
                            if is_exit {
                                continue;
                            }

                            // check internal function entry
                            if *step_idx == 0 {
                                continue;
                            }
                            let Some(InternalFunctionInfo { function_info: function, address }) =
                                self.get_function_info(&code_address, &step.pc)
                            else {
                                continue;
                            };

                            // ensure callsite
                            let prev_step = &trace.steps[*step_idx - 1];
                            if !prev_step.op.is_jump() {
                                continue;
                            }
                            if !self.is_call(&code_address, &prev_step.pc) {
                                continue;
                            };

                            // get exit pc from stack
                            let stack = step.stack.as_ref().unwrap();
                            let input_enough = function.input_size <= stack.len();
                            if !input_enough {
                                println!("stack size not enough, stack: {}, input_size: {}, address: {}, function: {}, pc: {}", stack.len(), function.input_size, address, function.name, last_pc);
                                if step.is_error() {
                                    println!(
                                        "stack size not enough has error, err: {}",
                                        step.as_error().unwrap()
                                    )
                                }
                            }
                            let Some(exit_pc) = stack.get(stack.len() - function.input_size - 1)
                            else {
                                println!("function entry stack not enough");
                                continue;
                            };
                            if self.tracer_config.debug {
                                println!("function entry, address: {}, function: {}, pc: {}, exit_pc: {}, input_size: {}, stack: {:?}",
                                    address, function.name, last_pc, exit_pc, function.input_size, stack.to_vec());
                            }
                            let frame = InternalSentioTrace {
                                trace: SentioTrace {
                                    typ: OpCode::JUMP.to_string(),
                                    pc: prev_step.pc,
                                    function_pc: Some(last_pc),
                                    start_index: next_inst_idx - 2,
                                    gas: U256::from(step.gas_remaining),
                                    from: Some(code_address.to_string().to_lowercase()),
                                    to: None,
                                    code_address: Some(code_address.to_string().to_lowercase()),
                                    input_stack: input_enough
                                        .then(|| copy_stack(stack, function.input_size)),
                                    input_memory: function
                                        .input_memory
                                        .then(|| step.memory.clone().unwrap().memory_chunks()),
                                    name: self.tracer_config.debug.then(|| function.name.clone()),
                                    ..Default::default()
                                },
                                exit_pc: Some(exit_pc.saturating_to::<usize>()), // exit pc can be wrong due to compiler optimization
                                function: Some(InternalFunctionInfo {
                                    function_info: function.clone(),
                                    address: address.clone(),
                                }),
                            };
                            frames.push(frame);
                        }
                        OpCode::REVERT => {
                            let stack = step.stack.as_ref().unwrap();
                            let memory = step.memory.as_ref().unwrap();
                            let [size, offset] = stack.last_chunk::<2>().unwrap();
                            let frame = SentioTrace {
                                error: frames.first().unwrap().trace.error.clone(),
                                output: Some(copy_memory(
                                    memory,
                                    offset.to::<usize>(),
                                    size.to::<usize>(),
                                )),
                                ..base_frame()
                            };
                            frames.last_mut().unwrap().trace.traces.push(Box::from(frame));
                        }
                        OpCode::SLOAD | OpCode::TLOAD => {
                            if !self.tracer_config.with_storage {
                                continue;
                            }
                            let stack = step.stack.as_ref().unwrap();
                            let slot = B256::from(stack.last().unwrap().to_be_bytes());
                            prev_sload_frame = Some(SentioTrace {
                                storage_address: Some(node.execution_address()),
                                storage_slot: Some(slot),
                                ..base_frame()
                            });
                        }
                        OpCode::SSTORE | OpCode::TSTORE => {
                            if !self.tracer_config.with_storage {
                                continue;
                            }
                            let stack = step.stack.as_ref().unwrap();
                            let slot = B256::from(stack.last().unwrap().to_be_bytes());
                            let value = B256::from(stack[stack.len() - 2].to_be_bytes());
                            let frame = SentioTrace {
                                storage_address: Some(node.execution_address()),
                                storage_slot: Some(slot),
                                storage_value: Some(value),
                                ..base_frame()
                            };
                            frames.last_mut().unwrap().trace.traces.push(Box::from(frame));
                        }
                        OpCode::KECCAK256 => {
                            if !self.tracer_config.with_storage_keys {
                                continue;
                            }
                            let stack = step.stack.as_ref().unwrap();
                            let memory = &step.memory.clone().unwrap();
                            let offset = stack.last().unwrap().to::<usize>();
                            let size = stack[stack.len() - 2].to::<usize>();
                            if size != 64 {
                                continue;
                            }
                            let raw_key = &memory.as_bytes()[offset..offset + size];
                            let key_slot = keccak256(raw_key);
                            let base_slot = B256::from_slice(&raw_key[32..]);
                            let key = B256::from_slice(&raw_key[0..32]);
                            let new_storage_key = StorageKey {
                                address: node.execution_address(),
                                code_address,
                                base_slot,
                                key_slot,
                                key,
                            };
                            let trace = &mut frames.last_mut().unwrap().trace;
                            if let Some(storage_keys) = &trace.storage_keys {
                                let mut new_storage_keys = storage_keys.clone();
                                new_storage_keys.push(new_storage_key);
                                trace.storage_keys = Some(new_storage_keys);
                            } else {
                                trace.storage_keys = Some(vec![new_storage_key]);
                            }
                        }
                        _ => {}
                    }

                    if !self.extra_capture_rules.is_empty() {
                        let mut match_rule_ids = vec![];
                        let ctx = EvalCtx {
                            step,
                            call_node: node,
                            stack: step.stack.as_ref().unwrap(),
                            origin: &self.origin,
                            debug: self.tracer_config.debug,
                        };
                        for (i, rule) in self.extra_capture_rules.iter().enumerate() {
                            match rule.eval(&ctx) {
                                Ok(result) => {
                                    if result == "true" {
                                        match_rule_ids.push(i);
                                    }
                                }
                                Err(err) => {
                                    if self.tracer_config.debug {
                                        println!(
                                            "error evaluating extra capture rule {}: {}",
                                            i, err
                                        );
                                    }
                                    continue;
                                }
                            }
                        }
                        if match_rule_ids.is_empty() {
                            continue;
                        }
                        let frame = SentioTrace {
                            match_rule_ids: Some(match_rule_ids),
                            stack: step.stack.clone(),
                            memory: step.memory.clone().map(|m| m.memory_chunks()),
                            ..base_frame()
                        };
                        frames.last_mut().unwrap().trace.traces.push(Box::from(frame));
                    }
                }
                TraceMemberOrder::Log(log_idx) => {
                    let log = &node.logs[*log_idx];
                    let Some(step) = last_step else {
                        println!("log without step");
                        let frame = InternalSentioTrace {
                            trace: SentioTrace {
                                typ: "LOG".to_string(),
                                address: Some(node.trace.address.to_string().to_lowercase()),
                                topics: Some(Vec::from(log.raw_log.topics())),
                                data: Some(log.raw_log.data.clone()),
                                ..Default::default()
                            },
                            ..Default::default()
                        };
                        frames.last_mut().unwrap().trace.traces.push(Box::from(frame.trace));
                        continue;
                    };
                    let (OpCode::LOG0 | OpCode::LOG1 | OpCode::LOG2 | OpCode::LOG3 | OpCode::LOG4) =
                        step.op
                    else {
                        panic!("log without log op");
                    };
                    let frame = InternalSentioTrace {
                        trace: SentioTrace {
                            typ: step.op.to_string(),
                            pc: last_pc,
                            start_index: next_inst_idx - 1,
                            end_index: next_inst_idx,
                            gas: U256::from(step.gas_remaining),
                            gas_used: U256::from(step.gas_cost),
                            address: Some(node.execution_address().to_string().to_lowercase()),
                            code_address: Some(code_address.to_string().to_lowercase()),
                            topics: Some(Vec::from(log.raw_log.topics())),
                            data: Some(log.raw_log.data.clone()),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    frames.last_mut().unwrap().trace.traces.push(Box::from(frame.trace));
                }
            }
        }
        while frames.len() > 1 {
            let mut frame = frames.pop().unwrap();
            frame.trace = SentioTrace {
                end_index: next_inst_idx,
                gas_used: frame.trace.gas - U256::from(last_step.unwrap().gas_remaining),
                output: Some(trace.output.clone()),
                ..frame.trace
            };
            frames.last_mut().unwrap().trace.traces.push(Box::from(frame.trace));
        }
        if frames.len() != 1 {
            println!("frames size: {}", frames.len());
        }
        let mut ret = frames.remove(0);
        ret.trace.end_index = next_inst_idx;
        ret
    }
}

fn copy_stack(stack: &Vec<U256>, size: usize) -> Vec<U256> {
    let mut input_stack = vec![U256::ZERO; stack.len() - size];
    input_stack.append(&mut stack[stack.len() - size..].to_vec());
    input_stack
}

fn copy_memory(memory: &RecordedMemory, offset: usize, size: usize) -> Bytes {
    if size == 0 {
        return Bytes::new();
    }
    if offset + size > memory.as_bytes().len() {
        println!(
            "memory out of bounds: offset: {}, size: {}, memory size: {}",
            offset,
            size,
            memory.as_bytes().len()
        );
        memory.as_bytes().slice(offset..)
    } else {
        memory.as_bytes().slice(offset..offset + size)
    }
}
