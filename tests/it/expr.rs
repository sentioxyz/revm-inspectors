use alloy_primitives::hex::FromHex;
use alloy_primitives::{Address, U256};
use revm::bytecode::OpCode;
use revm_inspectors::tracing::types::{CallTrace, CallTraceNode, CallTraceStep};
use revm_inspectors::tracing::{EvalCtx, Expr};
use std::str::FromStr;

#[test]
fn test_expr_1() {
    let raw = "((($op) == ($literal(SUB))) || (($op) == ($literal(EQ)))) && (((($stack(0)) == ($caller)) && (($stack(1)) == ($origin))) || ((($stack(0)) == ($origin)) && (($stack(1)) == ($caller))))";
    let expr = Expr::new(raw).unwrap();

    let ctx = EvalCtx {
        step: &CallTraceStep { op: OpCode::EQ, ..Default::default() },
        call_node: &CallTraceNode {
            trace: CallTrace {
                caller: Address::from_hex("0x086142af1321eaac4270422081c1EdA31eEcFf00").unwrap(),
                ..Default::default()
            },
            ..Default::default()
        },
        stack: &vec![
            U256::from_str("0x086142af1321eaac4270422081c1EdA31eEcFf0c").unwrap(),
            U256::from_str("0x086142af1321eaac4270422081c1EdA31eEcFf00").unwrap(),
        ],
        origin: &Address::from_hex("0x086142af1321eaac4270422081c1EdA31eEcFf0c").unwrap(),
        debug: false,
    };
    let ret = expr.eval(&ctx).unwrap();
    assert_eq!(ret, "true");
}

#[test]
fn test_expr_2() {
    let raw = "((($op) == ($literal(SUB))) || (($op) == ($literal(EQ)))) && (((($stack(0)) == ($caller)) && (($stack(1)) == ($origin))) || ((($stack(0)) == ($origin)) && (($stack(1)) == ($caller))))";
    let expr = Expr::new(raw).unwrap();

    let ctx = EvalCtx {
        step: &CallTraceStep { op: OpCode::EQ, ..Default::default() },
        call_node: &CallTraceNode {
            trace: CallTrace {
                caller: Address::from_hex("0x086142af1321eaac4270422081c1EdA31eEcFf01").unwrap(),
                ..Default::default()
            },
            ..Default::default()
        },
        stack: &vec![
            U256::from_str("0x086142af1321eaac4270422081c1EdA31eEcFf0c").unwrap(),
            U256::from_str("0x086142af1321eaac4270422081c1EdA31eEcFf00").unwrap(),
        ],
        origin: &Address::from_hex("0x086142af1321eaac4270422081c1EdA31eEcFf0c").unwrap(),
        debug: false,
    };
    let ret = expr.eval(&ctx).unwrap();
    assert_eq!(ret, "false");
}
