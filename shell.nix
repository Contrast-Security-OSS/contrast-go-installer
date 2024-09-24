# This file is for Nix users: https://nixos.org/
#
# shell.nix is a configuration for nix-shell, which allows users to quickly
# drop in to an environment which includes the basic tools needed for building
# and testing.
#
# For more information about this or why it's useful, see:
# https://nixos.org/guides/nix-pills/developing-with-nix-shell.html
{ pkgs ? import <nixpkgs> { } }:
let
  detect-secrets = with pkgs.python3Packages; buildPythonPackage
    rec {
      pname = "detect-secrets";
      version = "1.1.2";
      disabled = isPy27;

      src = pkgs.fetchFromGitHub {
        owner = "Contrast-Labs";
        repo = pname;
        rev = "7ed02347560610f3a2c963c0782a1aa853c6cde8";
        sha256 = "1l35wf4xchmg7qnm4i93kpqxjk50k04v3kff03dqvga34wqac4jx";
      };

      propagatedBuildInputs = [
        pyyaml
        requests
      ];

      meta = with pkgs.lib; {
        description = "An enterprise friendly way of detecting and preventing secrets in code";
        homepage = "https://github.com/Contrast-Labs/detect-secrets";
        license = licenses.asl20;
      };
    };
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    git
    go
    gnumake

    # This is used for our pre-commit/pre-push hooks, which is meant to run on
    # each commit to prevent accidental addition of sensitive information.
    detect-secrets
  ];
}
