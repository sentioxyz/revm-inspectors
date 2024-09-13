//! Geth tests

use crate::utils::inspect;
use alloy_primitives::{hex, Address, Bytes, U256};
use alloy_rpc_types::trace::geth::sentio::{FunctionInfo, SentioTracerConfig};
use revm::{db::{CacheDB, EmptyDB}, primitives::{
    BlockEnv, CfgEnv, CfgEnvWithHandlerCfg, EnvWithHandlerCfg, ExecutionResult, HandlerCfg,
    Output, SpecId, TransactTo, TxEnv,
}, DatabaseCommit};
use revm::primitives::AccountInfo;
use revm_inspectors::tracing::{SentioTraceBuilder, TracingInspector, TracingInspectorConfig};

#[test]
fn test_sentiotracer_logs() {
    /*
    contract LogTracing {
        event Log(address indexed addr, uint256 value);

        fallback() external payable {
            emit Log(msg.sender, msg.value);

            try this.nestedEmitWithFailure() {} catch {}
            try this.nestedEmitWithFailureAfterNestedEmit() {} catch {}
            this.nestedEmitWithSuccess();
        }

        function nestedEmitWithFailure() external {
            emit Log(msg.sender, 0);
            require(false, "nestedEmitWithFailure");
        }

        function nestedEmitWithFailureAfterNestedEmit() external {
            this.doubleNestedEmitWithSuccess();
            require(false, "nestedEmitWithFailureAfterNestedEmit");
        }

        function doubleNestedEmitWithSuccess() external {
            emit Log(msg.sender, 0);
            this.nestedEmitWithSuccess();
        }

        function nestedEmitWithSuccess() external {
            emit Log(msg.sender, 0);
        }
    }
    */
    let code = hex!("608060405234801561001057600080fd5b506103ac806100206000396000f3fe60806040526004361061003f5760003560e01c80630332ed131461014d5780636ae1ad40146101625780638384a00214610177578063de7eb4f31461018c575b60405134815233906000805160206103578339815191529060200160405180910390a2306001600160a01b0316636ae1ad406040518163ffffffff1660e01b8152600401600060405180830381600087803b15801561009d57600080fd5b505af19250505080156100ae575060015b50306001600160a01b0316630332ed136040518163ffffffff1660e01b8152600401600060405180830381600087803b1580156100ea57600080fd5b505af19250505080156100fb575060015b50306001600160a01b0316638384a0026040518163ffffffff1660e01b8152600401600060405180830381600087803b15801561013757600080fd5b505af115801561014b573d6000803e3d6000fd5b005b34801561015957600080fd5b5061014b6101a1565b34801561016e57600080fd5b5061014b610253565b34801561018357600080fd5b5061014b6102b7565b34801561019857600080fd5b5061014b6102dd565b306001600160a01b031663de7eb4f36040518163ffffffff1660e01b8152600401600060405180830381600087803b1580156101dc57600080fd5b505af11580156101f0573d6000803e3d6000fd5b505060405162461bcd60e51b8152602060048201526024808201527f6e6573746564456d6974576974684661696c75726541667465724e6573746564604482015263115b5a5d60e21b6064820152608401915061024a9050565b60405180910390fd5b6040516000815233906000805160206103578339815191529060200160405180910390a260405162461bcd60e51b81526020600482015260156024820152746e6573746564456d6974576974684661696c75726560581b604482015260640161024a565b6040516000815233906000805160206103578339815191529060200160405180910390a2565b6040516000815233906000805160206103578339815191529060200160405180910390a2306001600160a01b0316638384a0026040518163ffffffff1660e01b8152600401600060405180830381600087803b15801561033c57600080fd5b505af1158015610350573d6000803e3d6000fd5b5050505056fef950957d2407bed19dc99b718b46b4ce6090c05589006dfb86fd22c34865b23ea2646970667358221220090a696b9fbd22c7d1cc2a0b6d4a48c32d3ba892480713689a3145b73cfeb02164736f6c63430008130033");
    let deployer = Address::ZERO;

    let mut db = CacheDB::new(EmptyDB::default());

    let cfg = CfgEnvWithHandlerCfg::new(CfgEnv::default(), HandlerCfg::new(SpecId::LONDON));

    let env = EnvWithHandlerCfg::new_with_cfg_env(
        cfg.clone(),
        BlockEnv::default(),
        TxEnv {
            caller: deployer,
            gas_limit: 1000000,
            transact_to: TransactTo::Create,
            data: code.into(),
            ..Default::default()
        },
    );

    let mut insp = TracingInspector::new(TracingInspectorConfig::default_geth());

    // Create contract
    let (res, _) = inspect(&mut db, env, &mut insp).unwrap();
    let addr = match res.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Create(_, addr) => addr.unwrap(),
            _ => panic!("Create failed"),
        },
        _ => panic!("Execution failed"),
    };
    db.commit(res.state);

    let mut insp =
        TracingInspector::new(TracingInspectorConfig::default_geth().set_record_logs(true).set_memory_snapshots(true).set_immediate_bytes(true));

    let env = EnvWithHandlerCfg::new_with_cfg_env(
        cfg,
        BlockEnv::default(),
        TxEnv {
            caller: deployer,
            gas_limit: 1000000,
            transact_to: TransactTo::Call(addr),
            data: Bytes::default(), // call fallback
            ..Default::default()
        },
    );

    let (res, _) = inspect(&mut db, env, &mut insp).unwrap();
    assert!(res.result.is_success());


    let sentio_tracer_config = SentioTracerConfig {
        with_internal_calls: true,
        ..SentioTracerConfig::default()
    };

    let traces = insp.into_traces().into_nodes();
    let builder = SentioTraceBuilder::new(traces, sentio_tracer_config, TracingInspectorConfig::default_geth());
    let sentio_trace = builder.sentio_traces(res.result.gas_used(), None);

    assert_eq!(sentio_trace.traces.len(), 4);
    assert_eq!(sentio_trace.traces[0].typ, "LOG2");
    assert_eq!(sentio_trace.traces[0].topics.clone().unwrap().len(), 2);
    assert_eq!(sentio_trace.traces[1].error, Some("execution reverted".to_string()));
    assert_eq!(sentio_trace.traces[1].revert_reason, Some("nestedEmitWithFailure".to_string()));
    assert_eq!(sentio_trace.traces[1].traces[0].typ, "LOG2");
}

#[test]
fn test_sentiotracer_weth_transfer() {
    let user1 = Address::from(hex!("0000000000000000000000000000000000000123"));
    let user2 = Address::from(hex!("0000000000000000000000000000000000000456"));
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(user1, AccountInfo {
        balance: U256::from(10000000000_i64),
        ..Default::default()
    });
    let cfg = CfgEnvWithHandlerCfg::new(CfgEnv::default(), HandlerCfg::new(SpecId::LONDON));

    // Create contract
    let weth_code = hex!("60606040526040805190810160405280600d81526020017f57726170706564204574686572000000000000000000000000000000000000008152506000908051906020019061004f9291906100c8565b506040805190810160405280600481526020017f57455448000000000000000000000000000000000000000000000000000000008152506001908051906020019061009b9291906100c8565b506012600260006101000a81548160ff021916908360ff16021790555034156100c357600080fd5b61016d565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061010957805160ff1916838001178555610137565b82800160010185558215610137579182015b8281111561013657825182559160200191906001019061011b565b5b5090506101449190610148565b5090565b61016a91905b8082111561016657600081600090555060010161014e565b5090565b90565b610c348061017c6000396000f3006060604052600436106100af576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806306fdde03146100b9578063095ea7b31461014757806318160ddd146101a157806323b872dd146101ca5780632e1a7d4d14610243578063313ce5671461026657806370a082311461029557806395d89b41146102e2578063a9059cbb14610370578063d0e30db0146103ca578063dd62ed3e146103d4575b6100b7610440565b005b34156100c457600080fd5b6100cc6104dd565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561010c5780820151818401526020810190506100f1565b50505050905090810190601f1680156101395780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561015257600080fd5b610187600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061057b565b604051808215151515815260200191505060405180910390f35b34156101ac57600080fd5b6101b461066d565b6040518082815260200191505060405180910390f35b34156101d557600080fd5b610229600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061068c565b604051808215151515815260200191505060405180910390f35b341561024e57600080fd5b61026460048080359060200190919050506109d9565b005b341561027157600080fd5b610279610b05565b604051808260ff1660ff16815260200191505060405180910390f35b34156102a057600080fd5b6102cc600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610b18565b6040518082815260200191505060405180910390f35b34156102ed57600080fd5b6102f5610b30565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561033557808201518184015260208101905061031a565b50505050905090810190601f1680156103625780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561037b57600080fd5b6103b0600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091908035906020019091905050610bce565b604051808215151515815260200191505060405180910390f35b6103d2610440565b005b34156103df57600080fd5b61042a600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610be3565b6040518082815260200191505060405180910390f35b34600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055503373ffffffffffffffffffffffffffffffffffffffff167fe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c346040518082815260200191505060405180910390a2565b60008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156105735780601f1061054857610100808354040283529160200191610573565b820191906000526020600020905b81548152906001019060200180831161055657829003601f168201915b505050505081565b600081600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905092915050565b60003073ffffffffffffffffffffffffffffffffffffffff1631905090565b600081600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101515156106dc57600080fd5b3373ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff16141580156107b457507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205414155b156108cf5781600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015151561084457600080fd5b81600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055505b81600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254039250508190555081600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a3600190509392505050565b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410151515610a2757600080fd5b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f193505050501515610ab457600080fd5b3373ffffffffffffffffffffffffffffffffffffffff167f7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65826040518082815260200191505060405180910390a250565b600260009054906101000a900460ff1681565b60036020528060005260406000206000915090505481565b60018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610bc65780601f10610b9b57610100808354040283529160200191610bc6565b820191906000526020600020905b815481529060010190602001808311610ba957829003601f168201915b505050505081565b6000610bdb33848461068c565b905092915050565b60046020528160005260406000206020528060005260406000206000915091505054815600a165627a7a72305820deb4c2ccab3c2fdca32ab3f46728389c2fe2c165d5fafa07661e4e004f6c344a0029");
    let env = EnvWithHandlerCfg::new_with_cfg_env(
        cfg.clone(),
        BlockEnv::default(),
        TxEnv {
            caller: user1,
            gas_limit: 1000000,
            transact_to: TransactTo::Create,
            data: weth_code.into(),
            ..Default::default()
        },
    );
    let mut insp = TracingInspector::new(TracingInspectorConfig::default_geth().set_record_logs(true).set_memory_snapshots(true));
    let (res, _) = inspect(&mut db, env, &mut insp).unwrap();
    let contract_addr = match res.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Create(_, addr) => addr.unwrap(),
            _ => panic!("Create failed"),
        },
        _ => panic!("Execution failed"),
    };
    db.commit(res.state);

    // build sentio tracer config
    let functions_str = r#"[{"name":"approve","signatureHash":"0x095ea7b3","pc":327,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"approve","signatureHash":"0x095ea7b3","pc":338,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"approve","signatureHash":"0x095ea7b3","pc":391,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"totalSupply","signatureHash":"0x18160ddd","pc":417,"inputSize":0,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"totalSupply","signatureHash":"0x18160ddd","pc":428,"inputSize":0,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"totalSupply","signatureHash":"0x18160ddd","pc":436,"inputSize":0,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transferFrom","signatureHash":"0x23b872dd","pc":458,"inputSize":3,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transferFrom","signatureHash":"0x23b872dd","pc":469,"inputSize":3,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transferFrom","signatureHash":"0x23b872dd","pc":553,"inputSize":3,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"withdraw","signatureHash":"0x2e1a7d4d","pc":579,"inputSize":1,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"withdraw","signatureHash":"0x2e1a7d4d","pc":590,"inputSize":1,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"withdraw","signatureHash":"0x2e1a7d4d","pc":612,"inputSize":1,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"transfer","signatureHash":"0xa9059cbb","pc":880,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transfer","signatureHash":"0xa9059cbb","pc":891,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transfer","signatureHash":"0xa9059cbb","pc":944,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"deposit","signatureHash":"0xd0e30db0","pc":970,"inputSize":0,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"deposit","signatureHash":"0xd0e30db0","pc":978,"inputSize":0,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"deposit","signatureHash":"0xd0e30db0","pc":1088,"inputSize":0,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"approve","signatureHash":"0x095ea7b3","pc":1403,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"totalSupply","signatureHash":"0x18160ddd","pc":1645,"inputSize":0,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"transferFrom","signatureHash":"0x23b872dd","pc":1676,"inputSize":3,"inputMemory":false,"outputSize":1,"outputMemory":false},{"name":"withdraw","signatureHash":"0x2e1a7d4d","pc":2521,"inputSize":1,"inputMemory":false,"outputSize":0,"outputMemory":false},{"name":"transfer","signatureHash":"0xa9059cbb","pc":3022,"inputSize":2,"inputMemory":false,"outputSize":1,"outputMemory":false}]"#;
    let mut tracer_cfg: SentioTracerConfig = Default::default();
    let functions: Vec<FunctionInfo> = serde_json::from_str(functions_str).unwrap();
    tracer_cfg.with_internal_calls = true;
    tracer_cfg.debug = true;
    tracer_cfg.functions.insert(contract_addr, functions);
    tracer_cfg.calls.insert(contract_addr, vec![182, 3034]);

    // deposit some eth
    let env = EnvWithHandlerCfg::new_with_cfg_env(
        cfg.clone(),
        BlockEnv::default(),
        TxEnv {
            caller: user1,
            gas_limit: 1000000,
            transact_to: TransactTo::Call(contract_addr),
            value: U256::from(1000),
            ..Default::default()
        },
    );
    let mut insp = TracingInspector::new(TracingInspectorConfig::default_geth().set_record_logs(true).set_memory_snapshots(true));
    let (res, _) = inspect(&mut db, env, &mut insp).unwrap();
    assert!(res.result.is_success());
    db.commit(res.state);

    let traces = insp.into_traces().into_nodes();
    let builder = SentioTraceBuilder::new(traces, tracer_cfg.clone(), TracingInspectorConfig::default_geth());
    let sentio_trace = builder.sentio_traces(res.result.gas_used(), None);
    assert_eq!(sentio_trace.traces[0].typ, "JUMP");
    assert_eq!(sentio_trace.traces[0].name, Some("deposit".to_string()));
    assert_eq!(sentio_trace.traces[0].traces[0].typ, "LOG2");

    // transfer weth
    let env = EnvWithHandlerCfg::new_with_cfg_env(
        cfg.clone(),
        BlockEnv::default(),
        TxEnv {
            caller: user1,
            gas_limit: 1000000,
            transact_to: TransactTo::Call(contract_addr),
            // transfer("0x0000000000000000000000000000000000000456", 100)
            data: hex::decode("a9059cbb00000000000000000000000000000000000000000000000000000000000004560000000000000000000000000000000000000000000000000000000000000064").unwrap().into(),
            ..Default::default()
        },
    );
    let mut insp = TracingInspector::new(TracingInspectorConfig::default_geth().set_record_logs(true).set_memory_snapshots(true));
    let (res, _) = inspect(&mut db, env, &mut insp).unwrap();
    assert!(res.result.is_success());
    db.commit(res.state);

    let traces = insp.into_traces().into_nodes();
    let builder = SentioTraceBuilder::new(traces, tracer_cfg.clone(), TracingInspectorConfig::default_geth());
    let sentio_trace = builder.sentio_traces(res.result.gas_used(), None);

    assert_eq!(sentio_trace.pc, 880);
    assert_eq!(sentio_trace.start_index, 60);
    assert_eq!(sentio_trace.end_index, 273);
    assert_eq!(sentio_trace.traces[0].typ, "JUMP");
    assert_eq!(sentio_trace.traces[0].name, Some("transferFrom".to_string()));
    assert_eq!(sentio_trace.traces[0].input_stack.as_ref().unwrap().len(), 3);
    assert_eq!(sentio_trace.traces[0].output_stack.as_ref().unwrap().len(), 1);
    assert_eq!(sentio_trace.traces[0].traces[0].typ, "LOG3");
}