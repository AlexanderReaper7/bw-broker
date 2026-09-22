//! Finding the requesting application from the connecting process.
//!
//! The requester is the nearest process, starting from the one that connected, whose executable is neither a shell nor the `bw-app-gate` client. For an agent that runs `bash -c "bw-app-gate get ..."` this lands on the agent itself, so one agent session is one instance.
//!
//! Everything reads `/proc` directly and fails closed: an unreadable `exe` link is an error, never a fallback to the self-reported process name.

use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Executable file names skipped while walking up. Wrappers that only run another program belong here.
const PASS_THROUGH: &[&str] = &["sh", "bash", "dash", "zsh", "fish", "env", "bw-app-gate"];

/// One run of a process. The start time tells a live process apart from a later one that reuses its PID.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Instance {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Clone, Debug)]
pub struct Requester {
    pub instance: Instance,
    pub exe: PathBuf,
}

struct Stat {
    ppid: u32,
    start_time: u64,
}

/// Parses `/proc/<pid>/stat`. The command name in field 2 may contain spaces and parentheses, so fields are counted from the last `)`.
fn parse_stat(text: &str) -> Result<Stat> {
    let after_name = text
        .rfind(')')
        .map(|end| &text[end + 1..])
        .ok_or_else(|| anyhow!("malformed stat line"))?;
    // Fields after the name start at field 3 (state). ppid is field 4 and starttime is field 22.
    let fields: Vec<&str> = after_name.split_whitespace().collect();
    let field = |number: usize| {
        fields
            .get(number - 3)
            .ok_or_else(|| anyhow!("stat line has no field {number}"))
    };
    Ok(Stat {
        ppid: field(4)?.parse()?,
        start_time: field(22)?.parse()?,
    })
}

fn read_stat(pid: u32) -> Result<Stat> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("failed to read stat of process {pid}"))?;
    parse_stat(&text)
}

fn read_exe(pid: u32) -> Result<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe"))
        .with_context(|| format!("failed to read executable of process {pid}"))
}

pub fn is_alive(instance: Instance) -> bool {
    read_stat(instance.pid).is_ok_and(|stat| stat.start_time == instance.start_time)
}

pub fn find_requester(peer_pid: u32) -> Result<Requester> {
    let mut pid = peer_pid;
    loop {
        if pid <= 1 {
            bail!("no requesting application found above process {peer_pid}");
        }
        let stat = read_stat(pid)?;
        let exe = read_exe(pid)?;
        let file_name = exe.file_name().and_then(|name| name.to_str()).unwrap_or("");
        if !PASS_THROUGH.contains(&file_name) {
            // Read stat again after exe: if the PID was reused in between, the start time no longer matches and the request fails.
            if read_stat(pid)?.start_time != stat.start_time {
                bail!("process {pid} changed while being inspected");
            }
            return Ok(Requester {
                instance: Instance {
                    pid,
                    start_time: stat.start_time,
                },
                exe,
            });
        }
        pid = stat.ppid;
    }
}

/// A short name for an executable. A Nix store path becomes the package name without hash or version plus the file name, so `/nix/store/<hash>-claude-code-2.1.280/bin/.claude-wrapped` becomes `claude-code/.claude-wrapped`. Other paths are returned unchanged.
pub fn app_label(exe: &Path) -> String {
    let full = exe.to_string_lossy().into_owned();
    let Ok(in_store) = exe.strip_prefix("/nix/store") else {
        return full;
    };
    let Some(store_name) = in_store.iter().next().and_then(|part| part.to_str()) else {
        return full;
    };
    let Some((_hash, name)) = store_name.split_once('-') else {
        return full;
    };
    let file_name = exe
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    format!("{}/{file_name}", package_name(name))
}

/// The package name part of `<name>-<version>`, split the way Nix's `builtins.parseDrvName` does: at the first `-` not followed by a letter.
fn package_name(name_and_version: &str) -> &str {
    let bytes = name_and_version.as_bytes();
    (0..bytes.len())
        .find(|&i| bytes[i] == b'-' && !bytes.get(i + 1).is_some_and(u8::is_ascii_alphabetic))
        .map_or(name_and_version, |i| &name_and_version[..i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stat_handles_parentheses_in_name() {
        let line = "1234 (we)ird (name)) S 99 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 55555 1000 100";
        let stat = parse_stat(line).expect("should parse");
        assert_eq!(stat.ppid, 99);
        assert_eq!(stat.start_time, 55555);
    }

    #[test]
    fn stat_of_this_process_matches() {
        let pid = std::process::id();
        let stat = read_stat(pid).expect("own stat readable");
        assert_eq!(stat.ppid, std::os::unix::process::parent_id());
        assert!(is_alive(Instance {
            pid,
            start_time: stat.start_time
        }));
        assert!(!is_alive(Instance {
            pid,
            start_time: stat.start_time + 1
        }));
    }

    #[test]
    fn find_requester_stops_at_first_non_shell() {
        // The test binary is not a shell, so it is its own requester.
        let requester = find_requester(std::process::id()).expect("should resolve");
        assert_eq!(requester.instance.pid, std::process::id());
        assert_eq!(requester.exe, std::env::current_exe().unwrap());
    }

    #[test]
    fn package_name_follows_parse_drv_name() {
        assert_eq!(package_name("claude-code-2.1.280"), "claude-code");
        assert_eq!(package_name("bash-interactive-5.3p15"), "bash-interactive");
        assert_eq!(package_name("nodejs-slim-24.20.0"), "nodejs-slim");
        assert_eq!(package_name("hello"), "hello");
        assert_eq!(package_name("foo-"), "foo");
    }

    #[test]
    fn app_label_shortens_store_paths_only() {
        assert_eq!(
            app_label(Path::new(
                "/nix/store/ybbqnyp5nlwsjl6ypi2rg2qgsiiw3k61-claude-code-2.1.280/bin/.claude-wrapped"
            )),
            "claude-code/.claude-wrapped"
        );
        assert_eq!(app_label(Path::new("/usr/bin/editor")), "/usr/bin/editor");
    }
}
