//! Shared code for the `bw-app-gate` client and `bw-app-gate-agent` daemon.
//!
//! Design decisions and their reasons live in `docs/decisions.md`.

pub mod cache;
pub mod process;
pub mod prompt;
pub mod secret_ref;
pub mod typing;
pub mod vault;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Longest request line the agent accepts, in bytes.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Most secrets one request may name.
pub const MAX_SECRETS_PER_REQUEST: usize = 64;

/// One line of JSON from client to agent. `Get`, `Type` and `Forget` act on the requesting instance's own cache.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    Get(Vec<String>),
    /// Drops the named entries, or all of the instance's entries when empty.
    Forget(Vec<String>),
    /// Types one secret into the focused text field. `keyboard` uses the virtual keyboard instead of the input method, for apps without text-input-v3.
    Type {
        name: String,
        keyboard: bool,
    },
    /// The items with exactly this name.
    List(String),
    /// The items whose metadata contains every word of the query.
    Search(String),
}

/// One line of JSON from agent to client. `Secrets` holds the values in the order the request named them. `Forgot` is how many live entries a `Forget` dropped. `Typed` says where a `Type` went.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Secrets(Vec<String>),
    Forgot(usize),
    Typed(String),
    Items(Vec<Item>),
    Error(String),
}

/// One vault item as `list` and `search` return it. No values, only metadata.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Item {
    /// The gate name, `item[username]` when the item has a username, so it can be passed to `get` or `type` as it is.
    pub name: String,
    pub uris: Vec<String>,
    pub folder: Option<String>,
}

pub fn socket_path() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{uid}/bw-app-gate.sock"))
}
