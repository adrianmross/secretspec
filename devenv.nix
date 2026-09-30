{ pkgs, ... }: {
  languages.rust = {
    enable = true;
    # Pinned to >= 1.92 for the detect-coding-agent dependency's MSRV.
    channel = "stable";
    version = "1.92.0";
  };
  languages.javascript = {
    enable = true;
    npm = {
      enable = true;
      install.enable = true;
    };
  };

  packages = [
    # keyring
    pkgs.dbus
    # coverage testing
    pkgs.cargo-tarpaulin
    # installers
    pkgs.cargo-dist
  ];

  git-hooks.hooks = {
    rustfmt.enable = true;
    clippy.enable = true;
    # TODO: this should be done by devenv
    clippy.settings.offline = false;
  };

  enterTest = ''
    cargo test --all
  '';

  scripts.test-cli-integration.exec = ''
    # Build the CLI for integration tests
    cargo build --release
    export PATH="$PWD/target/release:$PATH"
    
    # Run CLI integration tests
    bash tests/cli-integration.sh
  '';

  processes.docs.exec = ''
    cd docs && npm run dev
  '';

  enterShell = ''
    # mbx (Mr Boxington) shared Cargo build cache. Installed once per machine,
    # not by Nix, so it is never built twice: `cargo install mbx --locked &&
    # mbx setup --yes`. Required for local shells; CI skips the check. Its
    # cargo shim must precede this shell's cargo, and finds that cargo next.
    if command -v mbx >/dev/null; then
      mbx_shim=$(mbx setup --status 2>/dev/null | sed -n 's|^mbx setup is installed and current: \(.*\)/cargo$|\1|p')
      if [ -n "$mbx_shim" ]; then export PATH="$mbx_shim:$PATH"; else echo "mbx: run 'mbx setup --yes'" >&2; fi
      unset mbx_shim
    elif [ -z "''${CI:-}" ]; then
      echo "mbx is required: cargo install mbx --locked && mbx setup --yes" >&2
      exit 1
    fi
  '';
}
