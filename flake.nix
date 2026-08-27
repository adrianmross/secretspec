{
  description = "secretspec — declarative secrets, every environment, any provider";

  # nixpkgs-unstable, not a release channel: the workspace pulls a dependency
  # that requires rustc 1.92, and nixos-25.11 ships 1.91.1 -- the build fails
  # outright on the release channel.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  # Exists so the CLI can be consumed as a package rather than only as a devenv
  # shell. Without it there is no way to `nix build`/`nix profile add` this
  # repo, which is what a CI image needs in order to ship the binary: a runner
  # cannot authenticate to Vault with a tool it has no way to install.
  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        secretspec = pkgs.rustPlatform.buildRustPackage {
          pname = "secretspec";
          version = "0.12.1";
          src = self;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          # Only the CLI and the vault provider. The default feature set also
          # pulls the AWS SDK, Google Cloud Secret Manager, Bitwarden and
          # keyring — four cloud SDKs this build will never call, and enough
          # extra compilation to exhaust a CI runner. Building the default
          # feature set inside an ARC runner image failed exactly that way.
          buildNoDefaultFeatures = true;
          buildFeatures = [
            "cli"
            "vault"
          ];
          cargoBuildFlags = [
            "--package"
            "secretspec"
          ];

          nativeBuildInputs = [ pkgs.pkg-config ];
          # No darwin.apple_sdk frameworks: nixos-25.11 removed those legacy
          # compatibility stubs, and the SDK now comes from the stdenv.
          buildInputs = [ pkgs.openssl ];

          # The suite includes provider integration tests that expect
          # credentials and network; `nix flake check` is not where those run.
          doCheck = false;

          meta = {
            description = "Declarative secrets, every environment, any provider";
            homepage = "https://secretspec.dev";
            mainProgram = "secretspec";
          };
        };

        default = secretspec;
      });
    };
}
