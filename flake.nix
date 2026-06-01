{
  description = "Easy certificate tool: helpful diagnostics, no requirements, no installation needed";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        renewc =
          with pkgs;
          let
            project_root = ./.;

            cargoTOML = lib.importTOML "${project_root}/renewc/Cargo.toml";
            rustToolchain = rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
            rust = makeRustPlatform {
              cargo = rustToolchain;
              rustc = rustToolchain;
            };
          in
          rust.buildRustPackage {
            pname = cargoTOML.package.name;
            version = cargoTOML.package.version;

            cargoLock = {
              lockFile = "${project_root}/Cargo.lock";
            };

            nativeBuildInputs = [ pkg-config ];
            buildInputs = [ openssl ];

            meta = {
              inherit (cargoTOML.package) description homepage;
              maintainers = cargoTOML.package.authors;
            };
          };
        devShell =
          with pkgs;
          mkShell {
            name = "renewc";
            inputsFrom = [ renewc ];
            RUST_SRC_PATH = "${rustPlatform.rustLibSrc}";
            CARGO_TERM_COLOR = "always";
          };
      in
      {
        devShells.default = devShell;
        packages.default = renewc;
      }
    )
    // {
      overlays.default = _: prev: {
        renewc = self.packages.${prev.system}.default;
      };
      nixosModules.renewc = ./nix_module.nix;
    };
}
