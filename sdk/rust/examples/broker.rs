// SPDX-License-Identifier: Apache-2.0
use ficc_module_sdk::{serve_broker, Broker};
use serde_json::{json, Value};
use std::io;
fn resources(request: &Value, broker: &mut Broker<'_>) -> io::Result<Vec<Value>> {
    if request["action"] != "read" {
        return Ok(request["targets"].as_array().unwrap().iter().map(|target|
            json!({"target":target,"error":{"code":"unsupported_action","message":"Select the read action."}})).collect());
    }
    broker.call("system.resources.read", &request["targets"], &json!({}))
}
fn main() {
    if serve_broker(resources).is_err() {
        eprintln!("Invalid module request, cancellation or broker result.");
        std::process::exit(1);
    }
}
