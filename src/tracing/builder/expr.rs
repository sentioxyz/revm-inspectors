const OP_EQ: &str = "==";
const OP_NEQ: &str = "!=";
const OP_AND: &str = "&&";
const OP_OR: &str = "||";
const OP_VMOP: &str = "$op";
const OP_STACK: &str = "$stack";
const OP_CALLER: &str = "$caller";
const OP_ORIGIN: &str = "$origin";
const OP_LITERAL: &str = "$literal";

use crate::tracing::types::{CallTraceNode, CallTraceStep};
use alloy_primitives::{Address, U256};
use std::collections::HashMap;
use std::fmt;

lazy_static::lazy_static! {
    pub static ref FUNC_OP_ARG_COUNT: HashMap<&'static str, usize> = {
        let mut m = HashMap::new();
        m.insert(OP_VMOP, 0);
        m.insert(OP_STACK, 1);
        m.insert(OP_CALLER, 0);
        m.insert(OP_ORIGIN, 0);
        m.insert(OP_LITERAL, 1);
        m
    };
    pub static ref BINARY_OPS: HashMap<&'static str, fn(&String, &String) -> String> = {
        let mut m: HashMap<&str, fn (&String, &String) -> String> = HashMap::new();
        m.insert(OP_EQ, |a, b| bool_to_string(a == b));
        m.insert(OP_NEQ, |a, b| bool_to_string(a != b));
        m.insert(OP_AND, |a, b| bool_to_string(a == "true" && b == "true"));
        m.insert(OP_OR, |a, b| bool_to_string(a == "true" || b == "true"));
        m
    };
}

#[derive(Clone, Debug)]
struct ExprNode {
    left: Option<Expr>,
    right: Option<Expr>,
    op: String,
    args: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Expr(Box<ExprNode>);

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

#[derive(Debug)]
pub struct EvalCtx<'a> {
    pub step: &'a CallTraceStep,
    pub call_node: &'a CallTraceNode,
    pub stack: &'a Vec<U256>,
    pub origin: &'a Address,
    pub debug: bool,
}

impl<'a> Expr {
    pub fn new(expr: &str) -> Result<Self, String> {
        let expr = expr.replace(" ", "");
        Self::parse(&expr)
    }

    fn parse(expr: &str) -> Result<Self, String> {
        let err_invalid_expr = format!("invalid expression \"{}\"", expr);
        let expr_bytes = expr.as_bytes();
        if expr_bytes[0] == b'(' {
            let mut s = 0;
            for (i, &b) in expr_bytes.iter().enumerate() {
                if b == b'(' {
                    s += 1;
                } else if b == b')' {
                    s -= 1;
                }
                if s == 0 {
                    if i == expr_bytes.len() - 1 {
                        return Self::parse(&expr[1..i]);
                    }
                    for op in BINARY_OPS.keys() {
                        if !expr[i + 1..].starts_with(*op) {
                            continue;
                        }
                        let left = Self::parse(&expr[1..i])?;
                        let t = &expr[i + 1 + op.len()..];
                        if t.chars().next() != Some('(') || t.chars().last() != Some(')') {
                            return Err(err_invalid_expr);
                        }
                        let right = Self::parse(&t[1..t.len() - 1])?;
                        return Ok(Expr(Box::new(ExprNode {
                            left: Some(left),
                            right: Some(right),
                            op: op.to_string(),
                            args: vec![],
                        })));
                    }
                    return Err(err_invalid_expr);
                }
            }
            return Err(err_invalid_expr);
        }
        for (op, &arg_cnt) in FUNC_OP_ARG_COUNT.iter() {
            if !expr.starts_with(*op) {
                continue;
            }
            if arg_cnt == 0 {
                if expr != *op {
                    return Err(err_invalid_expr);
                }
                return Ok(Expr(Box::new(ExprNode {
                    left: None,
                    right: None,
                    op: op.to_string(),
                    args: vec![],
                })));
            }
            let op_len = op.len();
            if expr.chars().nth(op_len) != Some('(') || expr.chars().last() != Some(')') {
                return Err(err_invalid_expr);
            }
            let args_str = &expr[op_len + 1..expr.len() - 1];
            let args: Vec<String> = args_str.split(',').map(|s| s.to_string()).collect();
            if args.len() != arg_cnt {
                return Err(err_invalid_expr);
            }
            return Ok(Expr(Box::new(ExprNode {
                left: None,
                right: None,
                op: op.to_string(),
                args,
            })));
        }
        Err(err_invalid_expr)
    }

    pub fn eval(&self, ctx: &EvalCtx<'_>) -> Result<String, String> {
        let f = || {
            if let Some(f) = BINARY_OPS.get(self.0.op.as_str()) {
                let l = self.0.left.as_ref().ok_or("missing left expr")?.eval(ctx)?;
                let r = self.0.right.as_ref().ok_or("missing right expr")?.eval(ctx)?;
                return Ok(f(&l, &r));
            }
            match self.0.op.as_str() {
                OP_LITERAL => {
                    if self.0.args.is_empty() {
                        return Err(format!("not enough arguments to {}", self.0.op));
                    }
                    Ok(self.0.args[0].clone())
                }
                OP_STACK => {
                    if self.0.args.is_empty() {
                        return Err(format!("not enough arguments to {}", self.0.op));
                    }
                    let idx = self.0.args[0].parse::<usize>().map_err(|_| "invalid stack index")?;
                    if idx >= ctx.stack.len() {
                        return Err(format!("stack index out of bounds: {}", idx));
                    }
                    Ok(serde_to_hex(&ctx.stack[ctx.stack.len() - 1 - idx]).unwrap())
                }
                OP_VMOP => Ok(ctx.step.op.to_string()),
                OP_CALLER => Ok(address_to_string(&ctx.call_node.trace.caller).unwrap()),
                OP_ORIGIN => Ok(address_to_string(&ctx.origin).unwrap()),
                _ => Err(format!("unknown op {}", self.0.op)),
            }
        };
        let ret = f();
        if ctx.debug {
            println!("{}: {:?}", self, ret);
        }
        ret
    }

    pub fn format(&self) -> String {
        let mut ops = self.0.op.clone();
        if !self.0.args.is_empty() {
            ops = format!("{}({})", self.0.op, self.0.args.join(", "));
        }
        if self.0.left.is_none() && self.0.right.is_none() {
            return ops;
        }
        format!(
            "({} {} {})",
            self.0.left.as_ref().map_or(String::new(), |l| l.format()),
            self.0.op,
            self.0.right.as_ref().map_or(String::new(), |r| r.format())
        )
    }
}

fn bool_to_string(b: bool) -> String {
    if b {
        "true".to_string()
    } else {
        "false".to_string()
    }
}

fn address_to_string(addr: &Address) -> serde_json::error::Result<String> {
    serde_to_hex(&U256::from_be_slice(addr.as_slice()))
}

fn serde_to_hex<T>(value: &T) -> serde_json::error::Result<String>
where
    T: serde::Serialize,
{
    serde_json::to_string(value).map(|s| s[1..s.len() - 1].to_string())
}
