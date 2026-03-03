// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

use wasmparser::{Operator, Parser, Payload};

pub fn enforce_soroban_compatibility(wasm: &[u8]) -> Result<(), String> {
    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.map_err(|e| e.to_string())?;
        if let Payload::CodeSectionEntry(body) = payload {
            let mut ops = body.get_operators_reader().map_err(|e| e.to_string())?;
            while !ops.eof() {
                let op = ops.read().map_err(|e| e.to_string())?;
                if is_float_op(&op) {
                    return Err(
                        "floating-point instructions are not allowed under strict Soroban compatibility"
                            .to_string(),
                    );
                }
            }
        }
    }
    Ok(())
}

fn is_float_op(op: &Operator) -> bool {
    let rep = format!("{:?}", op);
    rep.contains("F32") || rep.contains("F64")
}
