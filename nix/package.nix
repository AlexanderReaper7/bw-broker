# `targetCpu` is an LLVM CPU name such as "znver5", passed as `-C target-cpu`.
# It is an argument rather than `native` so the instruction set is a build
# input: see nixcfg's modules/nixos/cpu.nix for why that matters.
{
  lib,
  rustPlatform,
  targetCpu ? null,
}:

let
  manifest = (lib.importTOML ../Cargo.toml).package;
in
rustPlatform.buildRustPackage {
  pname = manifest.name;
  inherit (manifest) version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../src
    ];
  };
  cargoLock.lockFile = ../Cargo.lock;

  env = lib.optionalAttrs (targetCpu != null) {
    RUSTFLAGS = "-C target-cpu=${targetCpu}";
  };

  meta = {
    description = "Per-application gate in front of a Bitwarden vault, with a pinentry approval prompt";
    mainProgram = "bw-app-gate";
    platforms = lib.platforms.linux;
  };
}
