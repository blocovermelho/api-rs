{ sources ? import ./sources.nix
, pkgs ? import sources.nixpkgs {}
}:

with pkgs;

buildEnv {
  name = "Bloco Vermelho API Developer Environment";
  paths = [
    clang
    rustup    

    sqlite
    sqliteman
  ];
}
