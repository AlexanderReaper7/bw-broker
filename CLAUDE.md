# bw-app-gate

Design decisions, with dates and reasons, are in `docs/decisions.md`. Read it before changing identity, caching, the prompt, or the protocol.

- Never run `rbw unlock` or add anything that unlocks rbw-agent: an unlocked rbw-agent serves any secret to any same-user process, around the gate.
- Secret values stay in `rbw::locked::Vec` or `Zeroizing` buffers. A plain `String` copy of a secret is a bug.
