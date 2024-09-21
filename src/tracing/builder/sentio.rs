//! Sentio trace builder

use crate::tracing::{
    types::{CallTraceNode},
};
use alloy_primitives::{Address, U256};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use alloy_rpc_types::trace::geth::sentio::{FunctionInfo, SentioReceipt, SentioTrace, SentioTracerConfig};
use revm::interpreter::OpCode;
use log::warn;
use crate::tracing::types::{CallTraceStep, TraceMemberOrder};
use crate::tracing::utils::maybe_revert_reason;

#[derive(Clone, Debug)]
pub struct SentioTraceBuilder {
    /// Recorded trace nodes.
    nodes: Vec<CallTraceNode>,

    // address => (pc => function)
    function_map: HashMap<Address, HashMap<usize, InternalFunctionInfo>>,
    // address => (pc => bool)
    call_map: HashMap<Address, HashSet<usize>>,

    tracer_config: SentioTracerConfig,
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
    pub fn new(nodes: Vec<CallTraceNode>, config: SentioTracerConfig) -> Self {
        let tracer_config = config.clone();
        let mut function_map: HashMap<Address, HashMap<usize, InternalFunctionInfo>> = HashMap::new();
        for (address, function_infos) in config.functions.into_iter() {
            let function_by_pc = function_infos.into_iter().map(
                |function_info| (function_info.pc, InternalFunctionInfo { function_info, address })).collect();
            function_map.insert(address, function_by_pc);
        }
        let mut call_map: HashMap<Address, HashSet<usize>> = HashMap::new();
        for (address, pcs) in config.calls.into_iter() {
            let pc_set = pcs.into_iter().collect();
            call_map.insert(address, pc_set);
        }
        Self { nodes, function_map, call_map, tracer_config }
    }

    pub fn sentio_traces(&self, gas_used: u64, receipt: Option<SentioReceipt>) -> SentioTrace {
        SentioTrace {
            receipt,
            gas_used: U256::from(gas_used),
            tracer_config: if self.tracer_config.debug { Some(self.tracer_config.clone()) } else {  None },
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

    fn transform_call(&self, node: &CallTraceNode, inst_start_idx: usize, call_pc: usize) -> InternalSentioTrace {
        let trace = &node.trace;
        let root = InternalSentioTrace {
            trace: SentioTrace {
                typ: trace.kind.to_string(),
                pc: call_pc,
                start_index: inst_start_idx,
                gas: U256::from(trace.gas_limit),
                gas_used: U256::from(trace.gas_used),
                from: Some(trace.caller),
                to: Some(trace.address),
                code_address: Some(trace.address),
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
        if !trace.kind.is_any_create() && !trace.maybe_precompile.unwrap_or(false) && trace.data.len() >= 4 {
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

        for i in &node.ordering {
            match i {
                TraceMemberOrder::Call(child_idx) => {
                    let child_trace = self.transform_call(&self.nodes[node.children[*child_idx]], next_inst_idx, last_pc);
                    next_inst_idx = child_trace.trace.end_index.clone();
                    frames.last_mut().unwrap().trace.traces.push(Box::from(child_trace.trace));
                }
                TraceMemberOrder::Step(step_idx) => {
                    let step = &trace.steps[*step_idx];
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

                    if !self.tracer_config.with_internal_calls {
                        continue;
                    }
                    match step.op {
                        OpCode::JUMPDEST => {
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
                                        let InternalFunctionInfo { function_info: function, address } = &frame.function.unwrap();
                                        let stack = step.stack.as_ref().unwrap();
                                        let output_enough = function.output_size <= stack.len();
                                        if !output_enough {
                                            warn!("stack size not enough, stack: {}, output_size: {}, address: {}, function: {}, pc: {}", stack.len(), function.output_size, address, function.name, last_pc);
                                            if step.is_error() {
                                                warn!("stack size not enough has error, err: {}", step.as_error().unwrap())
                                            }
                                        }
                                        frame.trace = SentioTrace {
                                            end_index: next_inst_idx - 1,
                                            gas_used: frame.trace.gas - U256::from(step.gas_remaining),
                                            output_stack: if output_enough { Some(stack[stack.len() - function.output_size..].to_vec()) } else { None },
                                            output_memory: if function.output_memory { Some(step.memory.clone().unwrap().into_bytes()) } else { None },
                                            ..frame.trace
                                        };
                                        frames.last_mut().unwrap().trace.traces.push(Box::from(frame.trace));
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
                            let Some(InternalFunctionInfo { function_info: function, address }) = self.get_function_info(&step.contract, &step.pc) else {
                                continue;
                            };

                            // ensure callsite
                            let prev_step = &trace.steps[*step_idx - 1];
                            if !prev_step.op.is_jump() {
                                continue;
                            }
                            if !self.is_call(&prev_step.contract, &prev_step.pc) {
                                continue;
                            };

                            // get exit pc from stack
                            let stack = step.stack.as_ref().unwrap();
                            let input_enough = function.input_size <= stack.len();
                            if !input_enough {
                                warn!("stack size not enough, stack: {}, input_size: {}, address: {}, function: {}, pc: {}", stack.len(), function.input_size, address, function.name, last_pc);
                                if step.is_error() {
                                    warn!("stack size not enough has error, err: {}", step.as_error().unwrap())
                                }
                            }
                            let Some(exit_pc) = stack.get(stack.len() - function.input_size - 1) else {
                                warn!("function entry stack not enough");
                                continue;
                            };
                            let frame = InternalSentioTrace {
                                trace: SentioTrace {
                                    typ: OpCode::JUMP.to_string(),
                                    pc: prev_step.pc,
                                    function_pc: Some(last_pc),
                                    start_index: next_inst_idx - 2,
                                    gas: U256::from(step.gas_remaining),
                                    from: Some(step.contract),
                                    to: Some(step.contract),
                                    code_address: Some(step.contract),
                                    input_stack: if input_enough { Some(stack[stack.len() - function.input_size..].to_vec()) } else { None },
                                    name: if self.tracer_config.debug { Some(function.name.clone()) } else { None },
                                    input_memory: if function.input_memory { Some(step.memory.clone().unwrap().into_bytes()) } else { None },
                                    ..Default::default()
                                },
                                exit_pc: Some(exit_pc.to::<usize>()),
                                function: Some(InternalFunctionInfo { function_info: function.clone(), address: address.clone() }),
                            };
                            frames.push(frame);
                        }
                        OpCode::REVERT => {
                            let stack = step.stack.as_ref().unwrap();
                            let memory = step.memory.as_ref().unwrap();
                            let [size, offset] = stack.last_chunk::<2>().unwrap();
                            let output = memory.as_bytes().slice(offset.to::<usize>()..(offset + size).to::<usize>());
                            let frame = SentioTrace {
                                typ: OpCode::REVERT.to_string(),
                                pc: last_pc,
                                start_index: next_inst_idx - 1,
                                end_index: next_inst_idx,
                                gas: U256::from(step.gas_remaining),
                                gas_used: U256::from(step.gas_cost),
                                error: frames.first().unwrap().trace.error.clone(),
                                output: Some(output),
                                ..Default::default()
                            };
                            frames.last_mut().unwrap().trace.traces.push(Box::from(frame));
                        }
                        _ => {}
                    }
                }
                TraceMemberOrder::Log(log_idx) => {
                    let log = &node.logs[*log_idx];
                    let Some(step) = last_step else {
                        println!("log without step");
                        let frame = InternalSentioTrace {
                            trace: SentioTrace {
                                typ: "LOG".to_string(),
                                address: Some(node.trace.address),
                                topics: Some(Vec::from(log.raw_log.topics())),
                                data: Some(log.raw_log.data.clone()),
                                ..Default::default()
                            },
                            ..Default::default()
                        };
                        frames.last_mut().unwrap().trace.traces.push(Box::from(frame.trace));
                        continue;
                    };
                    let (OpCode::LOG0 | OpCode::LOG1 | OpCode::LOG2 | OpCode::LOG3 | OpCode::LOG4) = step.op else {
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
                            address: Some(node.trace.address),
                            code_address: Some(step.contract),
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
            warn!("frames size: {}", frames.len());
        }
        let mut ret = frames.remove(0);
        ret.trace.end_index = next_inst_idx;
        ret
    }
}
