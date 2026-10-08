{
  description = "bw-broker: per-application approval gate in front of a Bitwarden vault";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      packages.${system}.default = pkgs.callPackage ./nix/package.nix { };

      homeManagerModules.default = import ./nix/home-module.nix self;

      checks.${system}.default = self.packages.${system}.default;

      formatter.${system} = pkgs.nixfmt-tree;
    };
}
