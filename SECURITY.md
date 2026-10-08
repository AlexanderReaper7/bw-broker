# Security

Report a vulnerability privately through GitHub: [Security → Report a vulnerability](https://github.com/AlexanderReaper7/bw-broker/security/advisories/new). Do not open a public issue for it.

Only `main` gets fixes. There are no release branches.

## In scope

Anything that lets a program get a secret value without a prompt the user approved for that program: a wrong requester identity, a cache entry served to another process, a secret value in the journal or in a plain `String` that outlives its use, a way to unlock rbw-agent through bw-broker, `type` writing into a field or window it should have refused.

## Out of scope

These are documented non-goals, with reasons, in [docs/decisions.md](docs/decisions.md):

- Malware running as the same user. It can start a trusted program as a child and make it ask. Only a sandbox or a separate uid closes that.
- Cold boot attacks on cached values in RAM.
