# Decisions

Settled 2026-09-22 unless a row says otherwise. Each entry keeps the reason, so a later change can tell whether the reason still holds.

## Threat model: least privilege for honest applications

The gate stops an application from getting a secret nobody approved for it, and it makes every first use visible in a prompt. It does not stop malware running as the same user. With `kernel.yama.ptrace_scope = 1` a process may trace its own children, so hostile code can start a trusted program as a child and make it call the gate. The identity the gate sees is then real, and the request is still hostile. Only a sandbox (Flatpak, bubblewrap, a separate uid) closes that, and nothing here depends on one.

## Delivery: a daemon and a small CLI

`bw-app-gate-agent` holds the cache and shows prompts. `bw-app-gate get NAME...` asks it over `/run/user/<uid>/bw-app-gate.sock` and prints to stdout. One name prints the raw value with no trailing newline, so `$(...)` gets it exactly. Several names print one JSON object. A launcher (`run -- app`) was considered and left out: under this threat model the daemon would have to trust whatever the launcher said it was starting, which is no stronger than inspecting the caller.

## The requester is the nearest ancestor that is not a shell or Python

The agent walks up from the connecting process past `sh`, `bash`, `dash`, `zsh`, `fish`, `env` and the `bw-app-gate` client, and the first other process is the requester. An agent that runs `bash -c "bw-app-gate get x"` gets a new bash per call, so the direct parent would make every call a new requester and the cache useless. The walk lands on the agent process itself, so one agent session is one requester, which is also the scoping planned for later.

Python interpreters are skipped too since 2026-09-23, matched as `python` followed by digits and dots, because the file name carries the version (`python3.14`). Codex ran a Python snippet per secret, and every snippet was a new process, so every one prompted. The cost is that a Python program run as an application of its own, such as a user service, is attributed to its parent and shares that instance's cache with the parent's other children. Shell scripts already had that cost.

The walk reads `/proc/<pid>/exe` and fails when it cannot. It never falls back to the process name, because any process can set its own name with `prctl(PR_SET_NAME)`.

## The cache is per process instance, and it is the approval

An instance is a PID plus its start time from `/proc/<pid>/stat`, so a later process that reuses the PID is a stranger. A cached secret is dropped when its instance exits or after 15 minutes without a read by that instance. Nothing is written to disk.

Persisted grants ("claude-code may have github-token") were considered and dropped. The master password is needed on every cache miss anyway, so a stored grant would only have changed the prompt's wording, at the cost of a grants file, a naming scheme that survives Nix updates and revoke commands.

The idle timer counts on `CLOCK_BOOTTIME`, which keeps running through suspend. `Instant` uses `CLOCK_MONOTONIC`, which stops, so a machine suspended overnight would have woken with every timer where it left off.

Screen lock and suspend do not clear the cache: agent sessions keep running while the screen is locked.

## Forget: a process can drop only its own approvals (2026-09-23)

`bw-app-gate forget [NAME...]` drops the calling instance's entries, the named ones or all of them, with no prompt. It exists so a program that is done with a secret, or that fetched a stale one, can give up access before it exits or goes idle. The instance is resolved the same way as for `get`, so a shell script run by a program forgets on that program's behalf.

A program can not forget another program's approvals. Options considered were `--all` for every instance and `--pid N` for one other instance. Either would let any process of the user force re-prompts on every other one. That harm is small, but it is not needed: restarting `bw-app-gate-agent` already clears everything, because the cache exists only in its memory. Gating a clear-all on root was also suggested, but a root check would protect nothing that a same-user restart or kill does not already allow.

## Prompt: one dialog per request, listing only what is new

The pinentry dialog names the application, its PID and the requested secrets missing from that instance's cache, and asks for the master password. Approve with the password grants all of them. Deny, or no answer in 120 seconds, refuses the whole request. Three wrong passwords fail the request. Only one dialog is open at a time, and the cache stays usable for other requesters while it is.

The application is shown by its Nix package name without hash or version plus its file name (`claude-code/.claude-wrapped`), using the same split as `builtins.parseDrvName`. Other paths are shown in full.

Since 2026-09-23 the dialog also shows the requester's working directory and the app that started it, found by the same shell-skipping walk. Two Claude Code sessions have the same executable, and the directory tells them apart. Both are hints the process controls, through `chdir` or by who it was started from, so neither is part of the identity. The full command line was considered and dropped: Claude Code's is about 300 characters, and argv can itself hold tokens.

## Audit log: one journal line per request, names only (2026-09-23)

The agent writes one line to stderr, so to the journal, for every request: the requester with its PID and working directory, the names, and the outcome. For `get` the outcome is either "all cached" or which names needed approval. A refusal includes its reason, and a `forget` includes the count. Values are never logged. The threat model is honest apps that should not get more than they need, and before this nothing showed what an app fetched or how often. Read it with `journalctl --user -u bw-app-gate-agent`.

## Unlock: master password on every cache miss, keys dropped afterwards

The KDF runs once per approved request, and the vault keys live only for that request. A time-limited unlock, where a held key lets later prompts skip the password, is planned but not built. `vault::unlock` is the only place that would change.

## Secret names: `item[user]/field`, both qualifiers optional

`item` alone means the login password. Fields are `username`, `notes`, `totp` or a custom field's name. Two items with the same name are an error, not a guess.

`[user]` added 2026-09-23, after the user's vault turned out to hold several items with one name, such as two logins called `test`. It picks the item whose login or identity username matches exactly. Chosen over `user@item`, because usernames are often emails and item names can contain `@`; over a third path segment `item/field/user`, which needs the field spelled out to name a user; and over Bitwarden item IDs, which callers do not know and which the prompt could not show readably. Names are encrypted in rbw's copy, so an ambiguous name is only found after the password is entered.

`\` escapes the next character. `/`, `[` and `]` are special wherever they appear unescaped, and brackets are only valid as one trailing `[user]` on the item. Reserving them everywhere, including field names, keeps the rule one sentence long. `totp` returns the current code: the cache keeps the seed and computes the code on every read. A request that names a missing item fails as a whole and caches nothing.

## API keys and tokens: one per consumer, as a hidden field on the account item

Decided 2026-09-23, when the first real key (OpenRouter, for codex under T3) was set up and the user asked for a scheme to reuse for every key and token.

- Each consumer gets its own key at the provider. A consumer is one program or setup that uses the key, such as `t3-codex`. Revoking one consumer then breaks nothing else, and the provider's per-key usage shows who spent what.
- The key is a hidden custom field on the service's account login item, which is named by its domain. The field is named after the consumer, and the key's label at the provider is the same name. The gate name is `openrouter.ai/t3-codex`, or `github.com[work-user]/t3-codex` when there is more than one account.
- A consumer can't be called `password`, `username`, `notes` or `totp`, because those built-in fields take precedence over a custom field with the same name.

Rejected: one item per key, named `<domain> <consumer>`, which gives each key its own history and sharing but separates keys from the account that issued them; and several same-named items with the consumer in the username field, which fits the `[user]` qualifier but gives the username field a second meaning.

Values are capped at 4096 bytes because `rbw::locked::Vec`, which keeps them in mlocked memory, is a fixed 4 KiB buffer.

## Vault copy: rbw, synced by rbw-agent as a user service

The gate reads the encrypted vault copy that rbw keeps in `~/.cache/rbw`. rbw-agent syncs it hourly and on server push. A systemd timer running `rbw sync` was the first plan. It was replaced because `rbw sync` logs in first, so before `rbw login` it would open a password prompt every hour.

Never run `rbw unlock` on this machine: an unlocked rbw-agent hands any secret to any process of the same user through `rbw get`, around the gate.

`rbw login` unlocks the agent as well, which was missed at first. Its `login_success` in rbw 1.15 syncs and then calls `rbw::actions::unlock`, keeping the keys for `lock_timeout` (3600 s by default). Found on 2026-09-22 when `rbw unlocked` exited 0 right after the first login. Decided the same day: run `rbw login && rbw lock`, every time rbw asks for a login. Setting `lock_timeout = 1` in the module was the alternative, and would close the window without anyone having to remember. The user chose the documented step instead.

On 2026-09-23 the step became a command, `bw-app-gate login`, so it does not rely on memory. It runs `rbw login` and then `rbw lock` whatever the login did, since `&&` skips the lock when a login fails after unlocking. It catches Ctrl-C, SIGTERM, SIGHUP and SIGQUIT with a handler that does nothing, rather than ignoring them. exec resets handled signals to their default, so Ctrl-C still stops `rbw login`, and this process lives on to lock. A shell script with a `trap` in the nix module was the alternative. It was dropped because the command would only exist through the module.

## Known non-goal: cold boot attacks

Cached values are mlocked and zeroed on drop, which keeps them out of swap and shortens their life, but a chilled DIMM read in another machine still shows them. Encrypting the cache in software does not help, because its key would sit in the same RAM. AMD TSME (a BIOS option) encrypts all of DRAM with a key held in the CPU and is the real defense. It costs about 10 ns of memory latency and roughly 1-2 % in normal workloads, as reported for earlier Ryzen generations. It was left off on 2026-09-22 as a consideration only.

## Credential workflow for agents: type, list, search and mail-otp (2026-09-28)

The user wanted an agent to be able to log in to sites and read one-time codes from Gmail without the values passing through the agent, since everything a tool prints goes to the model provider. Four requests came out of that. They share the prompt, the audit log and the per-instance cache.

### `type NAME`: the agent writes the value into the focused text field

The value goes from the vault to the focused field and never to the caller. The prompt names the target window by app id and title, so the user sees where it will go before approving.

Delivery is a short-lived Wayland input method (`zwp_input_method_v2.commit_string`), with the virtual keyboard as an explicit fallback. It was first planned as keystrokes through the virtual keyboard with a focus check before each one, and changed the same day after a probe on this machine showed what the input method sees. When a text field gains focus, the compositor tells the input method, including the field's `content_purpose`. Firefox reported `Password` with `HiddenText | SensitiveData` for `<input type=password>` and `Normal` for a text input, and it sent `Deactivate` when a click left the field. That gives three things the keyboard does not:

- A password is refused unless the focused field says it is a password field. This was first planned with AT-SPI, which needs accessibility on for the whole session and an app restart, and which lets any same-user process read the widget text of every window. The user dropped that. The input method needs neither.
- A click that moves focus to another field, even inside the same window, arrives as `Deactivate` or a new `Activate`. The value goes in one request, and a `wl_display.sync` after it shows whether focus changed before the compositor delivered the value. If it did, the reply names the window that may have received it. The user's concern was that a stray click must not send the value somewhere else.
- The compositor delivers text, not key codes, so the keyboard layout does not matter and any Unicode works.

Apps without text-input-v3 get no `Activate`. That includes Electron apps: teams-for-linux 2.22 on Electron 43 sent nothing. Electron 43.6 started with `--enable-wayland-ime --wayland-text-input-version=3` did not help either. It bound `zwp_text_input_v3` and received `enter` for its surface, but never sent `enable` when a text field was clicked, so the input method got nothing. Measured on this machine the same day; the cause is not known. For those, `type --keyboard` uses `zwp_virtual_keyboard_v1` with one fixed keymap of the 95 printable ASCII characters. The same keymap every time means the focused app learns nothing about which characters the value uses, which a keymap built per value would reveal; values with other characters are refused (the user's choice). In keyboard mode the check is the window only: the focused toplevel is compared with the target before every key and after the last, and typing stops at the first mismatch. Keyboard mode has no field check and cannot tell a username field from a password field.

The fallback is a flag, not automatic. "No field is active" looks the same in an app without text-input-v3 and in Firefox with focus on a link or the page body, and typing a password into the page body can land in quick find. The requester decides, having looked at the screen.

Known gaps. A layer-shell surface that takes the keyboard, such as the launcher, is not a toplevel and is not seen by the window check in keyboard mode; in input-method mode it sends `Deactivate`. The Wayland client library takes `commit_string`'s text as a `String` and drops it without zeroing. That copy is short-lived but is outside the rule that values stay in locked or zeroed memory. Accepted by the user the same day, after measuring what it would take to read it: the machine has no swap, and the agent is non-dumpable with `LimitCORE=0`, so only root or a bug inside the agent could read the freed bytes. The same value also sits in the compositor and in the target app, which are less protected. The root fix, a global allocator in the agent that zeroes every freed block, was offered and declined. The same acceptance covers the library copies in `mail-otp`: async-imap formats the LOGIN command, app password included, into a `String`, and mail-parser decodes message bodies into plain strings.

Approvals. A `type` approval is cached like a `get` approval, but it does not allow `get`: the cache records which of the two was approved, and `get` needs a `get` approval. A `get` approval allows `type`, since a caller that has the value can type it itself. A cached `type` approval is not bound to the window shown in the prompt. Binding it would mean a prompt per window for the same secret, and an honest agent types into the window it just focused.

### `list ITEM` and `search QUERY`: metadata only

An agent choosing among several accounts needs the usernames. Autofill picks badly when a site has more than one account or when it cannot find the fields, so `type` is the main path and the Bitwarden extension's autofill is a shortcut. `list ITEM` returns the gate name `ITEM[username]` of every item named `ITEM`. `search QUERY` returns the same for every item where each whitespace-separated word of the query appears, case-insensitive, in one of the item name, a URI, the username, the folder name, a custom field's name, or the value of a text (not hidden) custom field. Notes and hidden fields are not searched, because notes often hold secrets and a match reveals a little about the content. Results carry the URIs and the folder.

The first `list` or `search` of an instance needs the master password, because names are encrypted in rbw's copy and the agent keeps no key. It was first built uncached, a password per query. Changed the same day at the user's request: the approval now decrypts the metadata of every item into an index that the cache keeps for that instance under the same 15-minute idle rule as a secret, and later queries show an approve/deny dialog without a password. The index holds names, usernames, URIs, folders, custom field names and text field values, zeroed on drop; notes and hidden fields stay encrypted. `forget` with no names drops it. The dialog stays, rather than no prompt at all, so the user still sees each query. A metadata approval grants no `get` or `type`.

### `mail-otp`: a code from Gmail, typed by default

Reads the inbox over IMAP (`imap.gmail.com:993`, rustls with the webpki roots) with a Google app password. The password is a hidden field on the Google login item, following the API-key scheme; the agent's `--mail-login NAME` names it without `[user]`. The agent reads it itself after the approval, and it never goes to the requester.

The user has two Gmail accounts, so each request names the inbox with a required `--to ADDRESS` (the user's choice, 2026-09-28, over checking every configured inbox). The agent reads `item[ADDRESS]/field`, so the address has to be the Google item's exact username, and logs in to IMAP as ADDRESS. The address is not a secret, so it goes in the request and the prompt rather than being read from the vault. Any address with an item and the field works; there is no separate allow-list, since the item holding an app password is already the opt-in. The inbox is opened with EXAMINE, read-only, and fetched with `BODY.PEEK`, so nothing is marked as read.

Every request needs the master password; nothing is cached (the user's choice). A cached approval would let a requester read any later code without the user seeing it.

Which messages count:

- Sender authentication trusts Gmail's own `Authentication-Results` header rather than checking DKIM signatures in the agent (the user's choice, 2026-09-28). Gmail is the receiving server and checked the signature at delivery with the DNS keys of that moment; a check hours later would redo it with a worse view, and fail on keys rotated since. Only the topmost `Authentication-Results` header counts, and only with authserv-id `mx.google.com`: Gmail puts its own on top, and anything below came with the message and can be written by anyone. mail-parser's `header_raw` returns the last one, so the code does not use it; a test with a forged header below Gmail's covers this.
- The message needs a `dkim=pass` for a domain aligned with the `From` domain: one is the other or a subdomain of it. This is DMARC's relaxed alignment without the public suffix list, slightly stricter than DMARC. It stops a message signed by `attacker.example` from showing `From: github.com`, which the reply would otherwise name as the sender.
- A message counts if it arrived at most 2 minutes before the request (`GRACE`), since the site often sends the code while the approval prompt is open, and until the wait ends (default 120 s, at most 600).
- `--from` is optional and takes several domains, matched against the authenticated `From` domain and its subdomains, because the domain that sends a code is often not the one being logged in to. With `--from`, the newest matching message with a code wins, since a resent code replaces the old one. Without it, the first check that finds any message with a code decides: exactly one is used, two or more fail and name the senders.

The code: 4 to 8 digit numbers standing alone, or two equal groups of 3 or 4 digits joined by a space or hyphen, within 150 characters after or 50 before a keyword (`code`, `kod`, `verif`, `one-time`, `bekräft`, and `otp` and `pin` as whole words). Numbers touching letters or number punctuation (prices, times, dates, `G-123456`), numbers inside a link (`http://`, `https://` or `www.` up to whitespace) and 4-digit numbers starting 19 or 20 are skipped. The subject and the text bodies are searched. When several distinct numbers qualify and exactly one of them stands alone on its line, that one is the code; otherwise exactly one distinct code is required, and two or more are an error, not a guess.

The link and own-line rules were added 2026-09-28 after Microsoft's Entra guest-account mail failed as ambiguous. Its footer, "If you didn't request a code, you can ignore this email", put `?LinkId=521839` and the ZIP code in `Redmond, WA 98052` within reach of the keyword, while the code itself stood alone on a line. The user chose the own-line tiebreak over stopping the keyword's reach at a blank line, which would break mails like `Your code:\n\n4839`, and over a postal-code rule, which would fix this sender and nothing else. Two numbers alone on their lines still fail.

The code is typed by default, like `type` but into any field (no password field check); `--print` returns it instead. The reply names the sender domain and never includes the body. Magic links are left out of the first version.
