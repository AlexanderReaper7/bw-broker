# bw-app-gate

Programs ask for Bitwarden secrets by name. A pinentry dialog shows which program asks for what, and entering the master password approves it. The approved secrets are then cached for that one process for up to 15 minutes of idle time.

```sh
bw-app-gate get github-token                  # login password, printed raw
bw-app-gate get github-token/username npm/totp  # JSON object, name -> value
bw-app-gate get 'test[username1]'             # the item "test" whose username is username1
bw-app-gate forget github-token               # drop this program's approval of one secret
bw-app-gate forget                            # drop all of this program's approvals
```

`forget` only affects the program that runs it. To clear every program's approvals, restart the agent: `systemctl --user restart bw-app-gate-agent`.

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

After switching, run `rbw login && rbw lock`. Login leaves rbw-agent unlocked, and `rbw lock` closes that again. Do the same whenever rbw asks for a new login. Do not run `rbw unlock`: see the vault section of the decisions.

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
- `src/prompt.rs` builds the pinentry dialog.
- `src/secret_ref.rs` parses secret names.
- `nix/` has the package and the home-manager module.
