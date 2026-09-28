# bw-app-gate

Programs ask for Bitwarden secrets by name. A pinentry dialog shows which program asks for what, and entering the master password approves it. The approved secrets are then cached for that one process for up to 15 minutes of idle time.

```sh
bw-app-gate get github-token                  # login password, printed raw
bw-app-gate get github-token/username npm/totp  # JSON object, name -> value
bw-app-gate get 'test[username1]'             # the item "test" whose username is username1
bw-app-gate forget github-token               # drop this program's approval of one secret
bw-app-gate forget                            # drop all of this program's approvals
bw-app-gate type github-token                 # type the password into the focused password field
bw-app-gate type --keyboard github-token      # type with a virtual keyboard, for apps without an input method
bw-app-gate list test                         # the usernames of the items named "test"
bw-app-gate search github work                # items whose metadata contains every word
bw-app-gate mail-otp --from github.com        # wait for a code mailed by github.com and type it
bw-app-gate mail-otp --print                  # exactly one code from any sender, printed
```

`type` prints nothing secret. Without `--keyboard` it goes through the Wayland input method, which only types into a text field that is focused and has reported itself, and a password goes only into a field that reports itself as a password field. `--keyboard` types into whatever has focus, so it checks the focused window but not the field. Both stop if focus moves to another window. Electron apps do not work with the input method, even with `--enable-wayland-ime`, so they need `--keyboard`.

`list` and `search` return names, URIs and folders, never values. The first one a program runs asks for the master password; after that its queries show an approve/deny dialog for 15 minutes of idle time. `search` matches names, URIs, usernames, folders, custom field names and text field values. It does not match notes or hidden fields.

`forget` only affects the program that runs it. To clear every program's approvals, restart the agent: `systemctl --user restart bw-app-gate-agent`.

Every request is logged by name, never by value: `journalctl --user -u bw-app-gate-agent`.

A name is `item`, `item/field`, `item[user]` or `item[user]/field`. `\` escapes `/`, `[`, `]` and `\` that are part of a name.

The reasoning behind every choice, including what this does not protect against, is in [docs/decisions.md](docs/decisions.md).

## Setup (NixOS + home-manager)

```nix
# flake inputs
bw-app-gate = {
  url = "git+https://github.com/AlexanderReaper7/bw-app-gate";
  inputs.nixpkgs.follows = "nixpkgs";
};

# home-manager
imports = [ inputs.bw-app-gate.homeManagerModules.default ];
services.bw-app-gate = {
  enable = true;
  email = "you@example.com";
  targetCpu = "znver5";  # optional
};
```

After switching, run `bw-app-gate login`. It runs `rbw login` and then `rbw lock` even if the login fails or is interrupted, because login leaves rbw-agent unlocked. Do the same whenever rbw asks for a new login. Do not run `rbw unlock`: see the vault section of the decisions.

`mail-otp` needs a [Google app password](https://myaccount.google.com/apppasswords) in a hidden custom field on the Google login item, and the module option `mailLogin = "google.com[you@gmail.com]/bw-app-gate-imap";` naming it.

## API keys

One key per consumer, stored as a hidden custom field named after the consumer on the service's login item, and labelled with the same name at the provider: `openrouter.ai/t3-codex`. The reasoning is in the decisions.

A program that runs a command for its token can call the client directly. For codex, `timeout_ms` has to cover the approval dialog, which waits up to 120 s; the default of 5 s is too short:

```toml
[model_providers.openrouter.auth]
command = "/etc/profiles/per-user/alexander/bin/bw-app-gate"
args = ["get", "openrouter.ai/t3-codex"]
timeout_ms = 130000
```

## Layout

- `src/bin/bw-app-gate.rs` is the client.
- `src/bin/bw-app-gate-agent.rs` is the daemon: socket, request flow, cache sweeping.
- `src/process.rs` finds the requesting process.
- `src/cache.rs` holds approved secrets per instance.
- `src/vault.rs` unlocks rbw's vault copy and decrypts values.
- `src/typing.rs` types into the focused window: input method, virtual keyboard, focus checks.
- `src/mail.rs` reads Gmail over IMAP and picks out one-time codes for `mail-otp`.
- `src/prompt.rs` builds the pinentry dialog.
- `src/secret_ref.rs` parses secret names.
- `examples/type-probe.rs` tests typing live without the vault: `cargo run --example type-probe -- [--password|--keyboard] TEXT`.
- `examples/mail-probe.rs` tests `mail-otp` without the agent, reading the app password from stdin.
- `nix/` has the package and the home-manager module.
