//! Shared code for the `bw-app-gate` client and `bw-app-gate-agent` daemon.
//!
//! Design decisions and their reasons live in `docs/decisions.md`.

pub mod cache;
pub mod mail;
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
    /// Types one secret into the focused text field. `keyboard` uses the virtual keyboard instead of the input method, for apps without text-input-v3. `into` refuses, before any prompt, unless the focused window's title or app id contains it, ignoring case.
    Type {
        name: String,
        keyboard: bool,
        #[serde(default)]
        into: Option<String>,
    },
    /// The items with exactly this name.
    List(String),
    /// The items whose metadata contains every word of the query.
    Search(String),
    MailOtp(MailOtp),
}

/// Waits up to `wait_secs` for a one-time code in the inbox of `to` and types it into the focused field, or returns it when `print` is set. `from` limits the sender domains; empty accepts any sender but only exactly one message with a code. `into` is as for `Type`.
#[derive(Debug, Deserialize, Serialize)]
pub struct MailOtp {
    pub to: String,
    pub from: Vec<String>,
    pub print: bool,
    pub keyboard: bool,
    pub wait_secs: u64,
    #[serde(default)]
    pub into: Option<String>,
}

/// One line of JSON from agent to client. `Secrets` holds the values in the order the request named them. `Forgot` is how many live entries a `Forget` dropped. `Typed` says where a `Type` went.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Secrets(Vec<String>),
    Forgot(usize),
    Typed(String),
    Items(Vec<Item>),
    /// A `MailOtp` result: the authenticated sender domain, and the code when it was asked to print, or else where the code was typed.
    MailCode {
        sender: String,
        code: Option<String>,
        typed_into: Option<String>,
    },
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
