// SPDX-License-Identifier: Apache-2.0
use ficc_module_sdk::serve;
use serde_json::{json, Value};

fn echo(request: &Value) -> Vec<Value> {
    let message = request["parameters"]["message"].as_str();
    request["targets"].as_array().unwrap().iter().enumerate().map(|(index, target)| {
        if request["action"] != "echo" || message.is_none() {
            json!({"target":target,"error":{"code":"unsupported_action",
                   "message":"Select the echo action and supply a message."}})
        } else {
            json!({"target":target,"data":{"message":message.unwrap(),"index":index}})
        }
    }).collect()
}

fn main() {
    if serve(echo).is_err() {
        eprintln!("Invalid module request or result.");
        std::process::exit(1);
    }
}
