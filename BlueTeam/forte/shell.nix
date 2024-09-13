let
  oxalica_overlay = import (builtins.fetchTarball
    "https://github.com/oxalica/rust-overlay/archive/master.tar.gz");

  pkgs = import <nixpkgs> { overlays = [ oxalica_overlay ]; };
  rust_channel = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain;
  #rust_channel = pkgs.rust-bin.stable.latest.default;
in
pkgs.mkShell {
  nativeBuildInputs = [
    (rust_channel.override {
      extensions = [ "rust-src" "rust-std" "clippy" ];
      targets = [
        "x86_64-unknown-linux-gnu"
      ];
    })
  ];

  buildInputs = with pkgs; [
    openssl

    clang
    nettle
    pkgconfig

    gettext
    transifex-client
  ];

  # Set Environment Variables
  RUST_BACKTRACE = 1;

  # compilation of -sys packages requires manually setting this :(
  shellHook = ''
    export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib";
  '';
}

