{
  description = "rust zig musl toolchain for Asahi Linux aarch64";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "clippy"
            "rustfmt"
          ];

          targets = [
            "aarch64-unknown-linux-musl"
            "aarch64-unknown-linux-gnu"
            "x86_64-unknown-linux-musl"
            "x86_64-unknown-linux-gnu"
          ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            zig
            cargo-zigbuild
            pkg-config
            cmake
            gnumake
            binutils
          ];

          RUST_TARGET = "aarch64-unknown-linux-musl";

          shellHook = ''
            export PKG_CONFIG_ALLOW_CROSS=1
            echo "Build:"
            echo "  cargo zigbuild --release --target $RUST_TARGET"
          '';
        };
      }
    );
}