//! Shared code for the `bw-app-gate` client and `bw-app-gate-agent` daemon.
//!
//! Design decisions and their reasons live in `docs/decisions.md`.

pub mod cache;
pub mod process;
pub mod prompt;
pub mod secret_ref;
pub mod vault;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Longest request line the agent accepts, in bytes.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Most secrets one request may name.
pub const MAX_SECRETS_PER_REQUEST: usize = 64;

/// One line of JSON from client to agent.
#[derive(Debug, Deserialize, Serialize)]
pub struct Request {
    pub secrets: Vec<String>,
}

/// One line of JSON from agent to client. `Secrets` holds the values in the order the request named them.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Secrets(Vec<String>),
    Error(String),
}

pub fn socket_path() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{uid}/bw-app-gate.sock"))
}
