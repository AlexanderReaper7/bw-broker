# The agent as a systemd user service, plus the rbw setup it reads from.
#
# rbw-agent runs as its own service for one reason: syncing. It pulls the
# vault every `sync_interval` seconds (rbw's default is 3600) and on push
# notifications from the server, and the gate only ever reads the copy it
# leaves on disk. A timer running `rbw sync` was the first plan and does not
# work before `rbw login`: `rbw sync` logs in first, so every tick would open a
# master password prompt. rbw-agent's own sync fails quietly instead.
#
# The rbw-agent never gets unlocked by anything here. Running `rbw unlock`
# would let every process of this user read the vault through `rbw get`,
# around the gate. `rbw login` unlocks it as a side effect, so it is run as
# `rbw login && rbw lock`.
self:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.bw-app-gate;
in
{
  options.services.bw-app-gate = {
    enable = lib.mkEnableOption "bw-app-gate, a per-application approval gate in front of rbw's vault copy";

    targetCpu = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "znver5";
      description = "LLVM CPU name to compile for. null builds for the x86-64 baseline.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { inherit (cfg) targetCpu; };
      defaultText = lib.literalExpression "built from this flake with `targetCpu`";
    };

    email = lib.mkOption {
      type = lib.types.str;
      description = "Email of the Bitwarden account, written to rbw's config.";
    };

    pinentry = lib.mkOption {
      type = lib.types.package;
      default = pkgs.pinentry-gnome3;
      defaultText = lib.literalExpression "pkgs.pinentry-gnome3";
      description = "Pinentry used for both the approval prompt and `rbw login`.";
    };
  };

  config = lib.mkIf cfg.enable {
    home.packages = [ cfg.package ];

    programs.rbw = {
      enable = true;
      settings = {
        inherit (cfg) email pinentry;
      };
    };

    systemd.user.services = {
      bw-app-gate-agent = {
        Unit = {
          Description = "bw-app-gate approval agent";
          # pinentry-gnome3 asks gcr-prompter over D-Bus to draw the dialog,
          # and gcr-prompter needs WAYLAND_DISPLAY, which the compositor only
          # exports once the graphical session is up.
          After = [ "graphical-session.target" ];
          PartOf = [ "graphical-session.target" ];
        };
        Service = {
          ExecStart = "${lib.getExe' cfg.package "bw-app-gate-agent"} --pinentry ${lib.getExe cfg.pinentry}";
          Restart = "on-failure";
          # The cache holds approved secrets in memory only. No core dumps, and
          # the process already makes itself non-dumpable.
          LimitCORE = 0;
          NoNewPrivileges = true;
        };
        Install.WantedBy = [ "graphical-session.target" ];
      };

      rbw-agent = {
        Unit.Description = "rbw agent, keeps the local vault copy synced";
        Service = {
          ExecStart = "${lib.getExe' config.programs.rbw.package "rbw-agent"} --no-daemonize";
          Restart = "on-failure";
        };
        Install.WantedBy = [ "default.target" ];
      };
    };
  };
}
