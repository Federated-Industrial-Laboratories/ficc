// SPDX-License-Identifier: Apache-2.0
//! Serve one host request with a complete target batch.
use serde_json::{json, Value};
use std::io::{self, Read, Write};

const MAX_FRAME: usize = 1024 * 1024;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid module request or result")
}

fn read_frame(input: &mut impl Read) -> io::Result<Value> {
    read_counted(input, &mut 0)
}

fn read_counted(input: &mut impl Read, total: &mut usize) -> io::Result<Value> {
    let mut header = [0u8; 4];
    input.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME { return Err(invalid()); }
    *total += size + 4;
    if *total > 2 * (MAX_FRAME + 4) { return Err(invalid()); }
    let mut data = vec![0u8; size];
    input.read_exact(&mut data)?;
    serde_json::from_slice(&data).map_err(|_| invalid())
}

fn frame(value: &Value) -> io::Result<Vec<u8>> {
    let data = serde_json::to_vec(value).map_err(|_| invalid())?;
    if data.is_empty() || data.len() > MAX_FRAME { return Err(invalid()); }
    let mut output = (data.len() as u32).to_be_bytes().to_vec();
    output.extend(data);
    Ok(output)
}

/// The handler owns the whole batch. It returns one result per requested target.
pub fn serve(handler: impl FnOnce(&Value) -> Vec<Value>) -> io::Result<()> {
    let mut input = io::stdin().lock();
    let hello = read_frame(&mut input)?;
    let request = read_frame(&mut input)?;
    let mut extra = [0u8; 1];
    if input.read(&mut extra)? != 0 ||
        hello != json!({"version":1,"type":"hello","host_api":1}) ||
        request.as_object().map(|m| m.len()) != Some(6) ||
        request["version"].as_u64() != Some(1) || request["type"] != "invoke" ||
        request["action"].as_str().is_none() || !request["parameters"].is_object() {
        return Err(invalid());
    }
    let id = request["id"].as_str().ok_or_else(invalid)?;
    let targets = request["targets"].as_array().ok_or_else(invalid)?;
    if id.is_empty() || id.len() > 128 || targets.is_empty() || targets.len() > 64 {
        return Err(invalid());
    }
    let mut unique = std::collections::HashSet::new();
    for target in targets {
        let name = target.as_str().ok_or_else(invalid)?;
        if name.is_empty() || name.chars().count() > 128 || name.contains(['/', '\\', ':', '\0']) ||
            !unique.insert(name) { return Err(invalid()); }
    }
    let mut output = frame(&json!({"version":1,"type":"hello","protocol":1}))?;
    output.extend(frame(&json!({"version":1,"type":"result","id":id,
                               "results":handler(&request)}))?);
    io::stdout().lock().write_all(&output)
}

fn bounded(value: &Value, depth: usize) -> io::Result<()> {
    if depth > 12 { return Err(invalid()); }
    match value {
        Value::String(text) if text.chars().count() > 65536 || text.contains('\0') => return Err(invalid()),
        Value::Number(number) => {
            if number.as_i64().is_some_and(|n| n.unsigned_abs() > 9007199254740991) ||
                number.as_u64().is_some_and(|n| n > 9007199254740991) ||
                !number.as_f64().is_some_and(|n| n.is_finite()) { return Err(invalid()); }
        }
        Value::Array(items) => {
            if items.len() > 256 { return Err(invalid()); }
            for item in items { bounded(item, depth + 1)?; }
        }
        Value::Object(items) => {
            if items.len() > 256 { return Err(invalid()); }
            for (key, item) in items {
                if key.chars().count() > 240 || key.contains('\0') { return Err(invalid()); }
                bounded(item, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 96 && value.as_bytes()[0].is_ascii_lowercase() &&
        value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
}

fn target_batch(value: &Value) -> io::Result<&Vec<Value>> {
    let targets = value.as_array().ok_or_else(invalid)?;
    if targets.is_empty() || targets.len() > 64 { return Err(invalid()); }
    let mut unique = std::collections::HashSet::new();
    for target in targets {
        let name = target.as_str().ok_or_else(invalid)?;
        if name.is_empty() || name.chars().count() > 128 || name.contains(['/', '\\', ':', '\0']) ||
            !unique.insert(name) { return Err(invalid()); }
    }
    Ok(targets)
}

fn result_batch(value: &Value, targets: &[Value]) -> io::Result<Vec<Value>> {
    bounded(value, 0)?;
    let rows = value.as_array().ok_or_else(invalid)?;
    if rows.len() != targets.len() { return Err(invalid()); }
    for (row, target) in rows.iter().zip(targets) {
        let item = row.as_object().ok_or_else(invalid)?;
        if item.len() != 2 || row["target"] != *target ||
            item.contains_key("data") == item.contains_key("error") { return Err(invalid()); }
        if let Some(error) = item.get("error") {
            if error.as_object().map(|v| v.len()) != Some(2) ||
                !error["code"].as_str().is_some_and(identifier) ||
                !error["message"].as_str().is_some_and(|m| m.chars().count() <= 1024) { return Err(invalid()); }
        }
    }
    Ok(rows.clone())
}

/// The broker owns the inherited pipes and the frozen invocation scope.
pub struct Broker<'a> {
    input: io::StdinLock<'a>,
    output: io::StdoutLock<'a>,
    id: String,
    targets: Vec<Value>,
    incoming: usize,
    outgoing: usize,
    calls: u32,
    failed: bool,
}

impl Broker<'_> {
    fn receive(&mut self) -> io::Result<Value> {
        let value = read_counted(&mut self.input, &mut self.incoming)?;
        bounded(&value, 0)?;
        Ok(value)
    }
    fn send(&mut self, value: &Value) -> io::Result<()> {
        bounded(value, 0)?;
        let bytes = frame(value)?;
        self.outgoing += bytes.len();
        if self.outgoing > 2 * (MAX_FRAME + 4) { return Err(invalid()); }
        self.output.write_all(&bytes)?;
        self.output.flush()
    }
    /// Request a declared primitive for a nonempty subset of the invocation.
    pub fn call(&mut self, primitive: &str, targets: &Value, parameters: &Value) -> io::Result<Vec<Value>> {
        if self.failed { return Err(invalid()); }
        let result = self.call_inner(primitive, targets, parameters);
        if result.is_err() { self.failed = true; }
        result
    }
    fn call_inner(&mut self, primitive: &str, targets: &Value, parameters: &Value) -> io::Result<Vec<Value>> {
        self.calls += 1;
        let selected = target_batch(targets)?;
        if self.calls > 16 || !identifier(primitive) || selected.iter().any(|t| !self.targets.contains(t)) ||
            !parameters.is_object() || serde_json::to_vec(parameters).map_err(|_| invalid())?.len() > 65536 {
            return Err(invalid());
        }
        bounded(parameters, 0)?;
        let mut id = format!("{:032x}", self.calls);
        if id == self.id { id.replace_range(0..1, "f"); }
        self.send(&json!({"version":2,"type":"broker","id":id,"invocation_id":self.id,
                         "primitive":primitive,"targets":selected,"parameters":parameters}))?;
        let reply = self.receive()?;
        if reply.as_object().map(|v| v.len()) != Some(5) || reply["version"].as_u64() != Some(2) ||
            reply["type"] != "broker-result" || reply["id"] != id || reply["invocation_id"] != self.id {
            return Err(invalid());
        }
        result_batch(&reply["results"], selected)
    }
}

/// Call one complete-batch handler with protocol-two broker access.
pub fn serve_broker(handler: impl FnOnce(&Value, &mut Broker<'_>) -> io::Result<Vec<Value>>) -> io::Result<()> {
    let input = io::stdin();
    let output = io::stdout();
    let mut broker = Broker { input: input.lock(), output: output.lock(), id: String::new(),
        targets: vec![], incoming: 0, outgoing: 0, calls: 0, failed: false };
    let hello = broker.receive()?;
    let request = broker.receive()?;
    if hello != json!({"version":2,"type":"hello","host_api":1}) ||
        request.as_object().map(|v| v.len()) != Some(6) || request["version"].as_u64() != Some(2) ||
        request["type"] != "invoke" || !request["action"].as_str().is_some_and(identifier) ||
        !request["parameters"].is_object() { return Err(invalid()); }
    let id = request["id"].as_str().ok_or_else(invalid)?;
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err(invalid()); }
    broker.id = id.to_owned();
    broker.targets = target_batch(&request["targets"] )?.clone();
    broker.send(&json!({"version":2,"type":"hello","protocol":2}))?;
    let results = handler(&request, &mut broker)?;
    if broker.failed { return Err(invalid()); }
    result_batch(&json!(results), &broker.targets)?;
    broker.send(&json!({"version":2,"type":"result","id":id,"results":results}))
}
