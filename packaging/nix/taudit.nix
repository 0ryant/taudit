# Nix derivation for taudit.
# PLACEHOLDER values are filled as part of a concrete release cut.

{ lib, rustPlatform, fetchFromGitHub }:

rustPlatform.buildRustPackage rec {
  pname = "taudit";
  version = "0.1.1";

  src = fetchFromGitHub {
    owner = "0ryant";
    repo = "taudit";
    rev = "v${version}";
    hash = "sha256-PLACEHOLDER_SOURCE_HASH";
  };

  cargoHash = "sha256-PLACEHOLDER_CARGO_HASH";

  cargoBuildFlags = [
    "--package"
    "taudit"
    "--bin"
    "taudit"
  ];

  installPhase = ''
    runHook preInstall
    install -Dm755 target/release/taudit $out/bin/taudit
    runHook postInstall
  '';

  meta = {
    description = "CI/CD authority scanner for secrets, identities, and trust boundaries";
    homepage = "https://github.com/0ryant/taudit";
    license = with lib.licenses; [ mit asl20 ];
    platforms = lib.platforms.unix;
    mainProgram = "taudit";
  };
}