{
  description = "Development environment and CI tooling for coquic";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    git-hooks.url = "github:cachix/git-hooks.nix";
  };

  outputs =
    {
      self,
      nixpkgs,
      git-hooks,
      ...
    }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
      };
      lib = pkgs.lib;
      llvmPkgs = pkgs.llvmPackages_20;
      fmt = (pkgs.fmt.override {
        stdenv = llvmPkgs.libcxxStdenv;
      }).overrideAttrs
        (old: {
          cmakeFlags = (old.cmakeFlags or [ ]) ++ [
            (lib.cmakeBool "FMT_TEST" false)
          ];
          doCheck = false;
        });
      spdlog = (pkgs.spdlog.override {
        stdenv = llvmPkgs.libcxxStdenv;
        inherit fmt;
      }).overrideAttrs
        (old: {
          cmakeFlags = (old.cmakeFlags or [ ]) ++ [
            (lib.cmakeBool "SPDLOG_BUILD_TESTS" false)
          ];
          doCheck = false;
        });
      pkgConfigPath = lib.makeSearchPath "lib/pkgconfig" [
        pkgs.openssl.dev
        spdlog.dev
        fmt.dev
      ];
      pre-commit-check = git-hooks.lib.${system}.run {
        src = ./.;
        hooks = {
          clang-format = {
            enable = true;
            types_or = lib.mkForce [ "c" "c++" ];
          };
          coquic-clang-tidy = {
            enable = true;
            name = "clang-tidy";
            entry = "${pkgs.bash}/bin/bash ./scripts/run-clang-tidy.sh";
            files = "\\.(c|cc|cpp|cxx|h|hh|hpp|hxx)$";
            language = "system";
            types_or = [ "c" "c++" ];
          };
        };
      };
    in
    {
      checks.${system}.pre-commit-check = pre-commit-check;

      devShells.${system}.default = pkgs.mkShell {
        packages =
          (with pkgs; [
            zig
            clang-tools
            gtest
            lldb
            llvmPkgs.llvm
            openssl
            spdlog
            pkg-config
          ])
          ++ pre-commit-check.enabledPackages;

        shellHook =
          pre-commit-check.shellHook
          + ''
            export GTEST_INCLUDE_DIR="${pkgs.gtest.dev}/include"
            export GTEST_SOURCE_DIR="${pkgs.gtest.src}"
            export GTEST_LIB_DIR="${pkgs.gtest}/lib"
            export OPENSSL_INCLUDE_DIR="${pkgs.openssl.dev}/include"
            export SPDLOG_INCLUDE_DIR="${spdlog.dev}/include"
            export FMT_INCLUDE_DIR="${fmt.dev}/include"
            export PKG_CONFIG_PATH="${pkgConfigPath}''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
            export LLVM_COV="${llvmPkgs.llvm}/bin/llvm-cov"
            export LLVM_PROFDATA="${llvmPkgs.llvm}/bin/llvm-profdata"
            export LLVM_PROFILE_RT="${llvmPkgs.compiler-rt}/lib/linux/libclang_rt.profile-x86_64.a"
            echo "coquic dev shell ready. Run: zig build"
          '';
      };
    };
}
