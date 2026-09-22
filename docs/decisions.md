# Decisions

Settled 2026-09-22 unless a row says otherwise. Each entry keeps the reason, so a later change can tell whether the reason still holds.

## Threat model: least privilege for honest applications

The gate stops an application from getting a secret nobody approved for it, and it makes every first use visible in a prompt. It does not stop malware running as the same user. With `kernel.yama.ptrace_scope = 1` a process may trace its own children, so hostile code can start a trusted program as a child and make it call the gate. The identity the gate sees is then real, and the request is still hostile. Only a sandbox (Flatpak, bubblewrap, a separate uid) closes that, and nothing here depends on one.

## Delivery: a daemon and a small CLI

`bw-app-gate-agent` holds the cache and shows prompts. `bw-app-gate get NAME...` asks it over `/run/user/<uid>/bw-app-gate.sock` and prints to stdout. One name prints the raw value with no trailing newline, so `$(...)` gets it exactly. Several names print one JSON object. A launcher (`run -- app`) was considered and left out: under this threat model the daemon would have to trust whatever the launcher said it was starting, which is no stronger than inspecting the caller.

## The requester is the nearest ancestor that is not a shell

The agent walks up from the connecting process past `sh`, `bash`, `dash`, `zsh`, `fish`, `env` and the `bw-app-gate` client, and the first other process is the requester. An agent that runs `bash -c "bw-app-gate get x"` gets a new bash per call, so the direct parent would make every call a new requester and the cache useless. The walk lands on the agent process itself, so one agent session is one requester, which is also the scoping planned for later.

The walk reads `/proc/<pid>/exe` and fails when it cannot. It never falls back to the process name, because any process can set its own name with `prctl(PR_SET_NAME)`.

## The cache is per process instance, and it is the approval

An instance is a PID plus its start time from `/proc/<pid>/stat`, so a later process that reuses the PID is a stranger. A cached secret is dropped when its instance exits or after 15 minutes without a read by that instance. Nothing is written to disk.

Persisted grants ("claude-code may have github-token") were considered and dropped. The master password is needed on every cache miss anyway, so a stored grant would only have changed the prompt's wording, at the cost of a grants file, a naming scheme that survives Nix updates and revoke commands.

The idle timer counts on `CLOCK_BOOTTIME`, which keeps running through suspend. `Instant` uses `CLOCK_MONOTONIC`, which stops, so a machine suspended overnight would have woken with every timer where it left off.

Screen lock and suspend do not clear the cache: agent sessions keep running while the screen is locked.

## Prompt: one dialog per request, listing only what is new

The pinentry dialog names the application, its PID and the requested secrets missing from that instance's cache, and asks for the master password. Approve with the password grants all of them. Deny, or no answer in 120 seconds, refuses the whole request. Three wrong passwords fail the request. Only one dialog is open at a time, and the cache stays usable for other requesters while it is.

The application is shown by its Nix package name without hash or version plus its file name (`claude-code/.claude-wrapped`), using the same split as `builtins.parseDrvName`. Other paths are shown in full.

## Unlock: master password on every cache miss, keys dropped afterwards

The KDF runs once per approved request, and the vault keys live only for that request. A time-limited unlock, where a held key lets later prompts skip the password, is planned but not built. `vault::unlock` is the only place that would change.

## Secret names: `item[user]/field`, both qualifiers optional

`item` alone means the login password. Fields are `username`, `notes`, `totp` or a custom field's name. Two items with the same name are an error, not a guess.

`[user]` added 2026-09-23, after the user's vault turned out to hold several items with one name, such as two logins called `test`. It picks the item whose login or identity username matches exactly. Chosen over `user@item`, because usernames are often emails and item names can contain `@`; over a third path segment `item/field/user`, which needs the field spelled out to name a user; and over Bitwarden item IDs, which callers do not know and which the prompt could not show readably. Names are encrypted in rbw's copy, so an ambiguous name is only found after the password is entered.

`\` escapes the next character. `/`, `[` and `]` are special wherever they appear unescaped, and brackets are only valid as one trailing `[user]` on the item. Reserving them everywhere, including field names, keeps the rule one sentence long. `totp` returns the current code: the cache keeps the seed and computes the code on every read. A request that names a missing item fails as a whole and caches nothing.

Values are capped at 4096 bytes because `rbw::locked::Vec`, which keeps them in mlocked memory, is a fixed 4 KiB buffer.

## Vault copy: rbw, synced by rbw-agent as a user service

The gate reads the encrypted vault copy that rbw keeps in `~/.cache/rbw`. rbw-agent syncs it hourly and on server push. A systemd timer running `rbw sync` was the first plan. It was replaced because `rbw sync` logs in first, so before `rbw login` it would open a password prompt every hour.

Never run `rbw unlock` on this machine: an unlocked rbw-agent hands any secret to any process of the same user through `rbw get`, around the gate.

`rbw login` unlocks the agent as well, which was missed at first. Its `login_success` in rbw 1.15 syncs and then calls `rbw::actions::unlock`, keeping the keys for `lock_timeout` (3600 s by default). Found on 2026-09-22 when `rbw unlocked` exited 0 right after the first login. Decided the same day: run `rbw login && rbw lock`, every time rbw asks for a login. Setting `lock_timeout = 1` in the module was the alternative, and would close the window without anyone having to remember. The user chose the documented step instead.

## Known non-goal: cold boot attacks

Cached values are mlocked and zeroed on drop, which keeps them out of swap and shortens their life, but a chilled DIMM read in another machine still shows them. Encrypting the cache in software does not help, because its key would sit in the same RAM. AMD TSME (a BIOS option) encrypts all of DRAM with a key held in the CPU and is the real defense. It costs about 10 ns of memory latency and roughly 1-2 % in normal workloads, as reported for earlier Ryzen generations. It was left off on 2026-09-22 as a consideration only.
