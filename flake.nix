{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  outputs = { self, nixpkgs, flake-utils, naersk, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [ (import rust-overlay) ];
      # Read from `rust-toolchain.toml` instead of adding `rust-bin.nightly.latest.default` to devShell `buildInputs`
      rustToolchain = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      naerskLib = pkgs.callPackage naersk {
        cargo = rustToolchain;
        rustc = rustToolchain;
      };

      pkgs = import nixpkgs {
        inherit system overlays;
        config = {
          allowUnfree = true;
        };
      };


      # Libraries that are mostly needed for raylib to build
      libraries = with pkgs; [
        cmake sqlite
      ];

      packages = with pkgs; [
      ];

      # Inputs needed at compile-time
      nativeBuildInputs = with pkgs; [ rustToolchain ];
      # Inputs needed at runtime
      buildInputs = with pkgs; [ ] ++ packages ++ libraries;
    in
    {
      packages.default = naerskLib.buildPackage {
         src = ./.;
      };

      devShells = {
        default = pkgs.mkShell {
          inherit buildInputs;
          nativeBuildInputs = nativeBuildInputs ++ [
            pkgs.cargo-watch
          ];

          # shellHook = ''
          # export LD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath libraries}
          # '';
        };
      };
    });
}
