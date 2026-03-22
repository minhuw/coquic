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
      staticPkgs = pkgs.pkgsStatic;
      staticLlvmPkgs = staticPkgs.llvmPackages_20;
      muslLibgccEh = pkgs.runCommand "musl-libgcc-eh" { } ''
        mkdir -p $out/lib
        libgcc_archive="$(find ${staticPkgs.stdenv.cc.cc} -name libgcc.a | head -n 1)"
        if [ -z "$libgcc_archive" ]; then
          echo "unable to locate libgcc.a for musl toolchain" >&2
          exit 1
        fi
        ln -s "$libgcc_archive" $out/lib/libgcc_eh.a
      '';
      simulatorEndpointBase = pkgs.dockerTools.pullImage {
        imageName = "martenseemann/quic-network-simulator-endpoint";
        imageDigest = "sha256:3b2b9e6fa317da238c8140a7b6d2bf8d4d45a8464b873eecac3ff2a32520b71a";
        finalImageName = "martenseemann/quic-network-simulator-endpoint";
        finalImageTag = "latest";
        sha256 = "sha256-i2UnYhKaM4jn0Xnmnd6R7JAyXYc/88npPNBsON4of3w=";
      };
      projectSrc = lib.cleanSource ./.;
      quictlsVersion = "3.3.0-quic1";
      quictlsSrc = pkgs.fetchFromGitHub {
        owner = "quictls";
        repo = "openssl";
        rev = "openssl-${quictlsVersion}";
        hash = "sha256-kBPwldTJbJSuvBVylJNcLSJvF/Hbqh0mfT4Ub5Xc6dk=";
      };
      quictlsStatic = (pkgs.quictls.override { static = true; }).overrideAttrs (old: {
        version = quictlsVersion;
        src = quictlsSrc;
        configureFlags = (old.configureFlags or [ ]) ++ [ "no-tests" ];
      });
      boringssl = pkgs.boringssl;
      fmt = (pkgs.fmt.override {
        stdenv = llvmPkgs.libcxxStdenv;
      }).overrideAttrs
        (old: {
          cmakeFlags = (old.cmakeFlags or [ ]) ++ [
            (lib.cmakeBool "FMT_TEST" false)
          ];
          doCheck = false;
        });
      fmtStatic = (pkgs.fmt.override {
        stdenv = llvmPkgs.libcxxStdenv;
      }).overrideAttrs
        (old: {
          cmakeFlags = (old.cmakeFlags or [ ]) ++ [
            (lib.cmakeBool "BUILD_SHARED_LIBS" false)
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
      spdlogStatic = (pkgs.spdlog.override {
        stdenv = llvmPkgs.libcxxStdenv;
        fmt = fmtStatic;
      }).overrideAttrs
        (old: {
          cmakeFlags = (old.cmakeFlags or [ ]) ++ [
            (lib.cmakeBool "SPDLOG_BUILD_SHARED" false)
            (lib.cmakeBool "SPDLOG_BUILD_STATIC" true)
            (lib.cmakeBool "SPDLOG_BUILD_TESTS" false)
          ];
          doCheck = false;
        });
      muslFmtStatic = (staticPkgs.fmt.override {
        stdenv = staticLlvmPkgs.libcxxStdenv;
      }).overrideAttrs
        (old: {
          cmakeFlags = (old.cmakeFlags or [ ]) ++ [
            (lib.cmakeBool "BUILD_SHARED_LIBS" false)
            (lib.cmakeBool "FMT_TEST" false)
          ];
          NIX_LDFLAGS = (old.NIX_LDFLAGS or "") + " -L${muslLibgccEh}/lib";
          doCheck = false;
        });
      muslSpdlogStatic = (staticPkgs.spdlog.override {
        stdenv = staticLlvmPkgs.libcxxStdenv;
        fmt = muslFmtStatic;
      }).overrideAttrs
        (old: {
          cmakeFlags = (old.cmakeFlags or [ ]) ++ [
            (lib.cmakeBool "SPDLOG_BUILD_SHARED" false)
            (lib.cmakeBool "SPDLOG_BUILD_STATIC" true)
            (lib.cmakeBool "SPDLOG_BUILD_TESTS" false)
          ];
          NIX_LDFLAGS = (old.NIX_LDFLAGS or "") + " -L${muslLibgccEh}/lib";
          doCheck = false;
        });
      mkProfile =
        {
          name,
          tlsBackend,
          tlsPackage,
          tlsLinkage,
          spdlogPackage,
          fmtPackage,
          zigTarget ? null,
          spdlogShared ? true,
          pkgConfigAllStatic ? false,
        }:
        {
          inherit
            name
            tlsBackend
            tlsPackage
            tlsLinkage
            spdlogPackage
            fmtPackage
            zigTarget
            spdlogShared
            pkgConfigAllStatic
            ;
          pkgConfigPath = lib.makeSearchPath "lib/pkgconfig" [
            spdlogPackage.dev
            fmtPackage.dev
          ];
        };
      quictlsProfile = mkProfile {
        name = "quictls";
        tlsBackend = "quictls";
        tlsPackage = quictlsStatic;
        tlsLinkage = "static";
        spdlogPackage = spdlogStatic;
        fmtPackage = fmtStatic;
        spdlogShared = false;
        pkgConfigAllStatic = true;
      };
      boringsslProfile = mkProfile {
        name = "boringssl";
        tlsBackend = "boringssl";
        tlsPackage = boringssl;
        tlsLinkage = "static";
        spdlogPackage = spdlogStatic;
        fmtPackage = fmtStatic;
        spdlogShared = false;
      };
      boringsslMuslProfile = mkProfile {
        name = "boringssl-musl";
        tlsBackend = "boringssl";
        tlsPackage = staticPkgs.boringssl;
        tlsLinkage = "static";
        spdlogPackage = muslSpdlogStatic;
        fmtPackage = muslFmtStatic;
        zigTarget = "x86_64-linux-musl";
        spdlogShared = false;
        pkgConfigAllStatic = true;
      };
      mkCoquicEnv = profile: ''
        export GTEST_INCLUDE_DIR="${pkgs.gtest.dev}/include"
        export GTEST_SOURCE_DIR="${pkgs.gtest.src}"
        export GTEST_LIB_DIR="${pkgs.gtest}/lib"
        export COQUIC_TLS_BACKEND="${profile.tlsBackend}"
        export COQUIC_TLS_LINKAGE="${profile.tlsLinkage}"
        ${
          if profile.tlsBackend == "quictls" then
            ''
              export QUICTLS_INCLUDE_DIR="${profile.tlsPackage.dev}/include"
              export QUICTLS_LIB_DIR="${profile.tlsPackage.out}/lib"
              export OPENSSL_INCLUDE_DIR="${profile.tlsPackage.dev}/include"
            ''
          else
            ''
              export BORINGSSL_INCLUDE_DIR="${profile.tlsPackage.dev}/include"
              export BORINGSSL_LIB_DIR="${profile.tlsPackage.out}/lib"
            ''
        }
        export SPDLOG_INCLUDE_DIR="${profile.spdlogPackage.dev}/include"
        export FMT_INCLUDE_DIR="${profile.fmtPackage.dev}/include"
        export PKG_CONFIG_PATH="${profile.pkgConfigPath}''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
        ${lib.optionalString profile.pkgConfigAllStatic ''
          export PKG_CONFIG_ALL_STATIC=1
        ''}
        export LLVM_COV="${llvmPkgs.llvm}/bin/llvm-cov"
        export LLVM_PROFDATA="${llvmPkgs.llvm}/bin/llvm-profdata"
        export LLVM_PROFILE_RT="${llvmPkgs.compiler-rt}/lib/linux/libclang_rt.profile-x86_64.a"
      '';
      mkZigBuildArgs = profile:
        lib.concatStringsSep " " (
          [
            "-Dtls_backend=${profile.tlsBackend}"
            "-Doptimize=ReleaseFast"
            "-Dspdlog_shared=${if profile.spdlogShared then "true" else "false"}"
          ]
          ++ lib.optionals (profile.zigTarget != null) [
            "-Dtarget=${profile.zigTarget}"
          ]
        );
      mkCoquicPackage = profile:
        pkgs.stdenv.mkDerivation {
          pname = "coquic-${profile.name}";
          version = "dev";
          src = projectSrc;
          strictDeps = true;
          nativeBuildInputs = [
            pkgs.bash
            pkgs.gtest
            pkgs.pkg-config
            pkgs.zig
            llvmPkgs.llvm
          ];
          buildInputs = [
            profile.tlsPackage
            profile.spdlogPackage
            profile.fmtPackage
          ];
          dontConfigure = true;
          doCheck = false;

          buildPhase = ''
            runHook preBuild
            export HOME="$TMPDIR"
            ${mkCoquicEnv profile}
            zig build ${mkZigBuildArgs profile}
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin
            cp zig-out/bin/coquic $out/bin/coquic
            runHook postInstall
          '';
        };
      mkCoquicCheck = profile:
        pkgs.stdenv.mkDerivation {
          pname = "coquic-${profile.name}-tests";
          version = "dev";
          src = projectSrc;
          strictDeps = true;
          nativeBuildInputs = [
            pkgs.bash
            pkgs.gtest
            pkgs.pkg-config
            pkgs.zig
            llvmPkgs.llvm
          ];
          buildInputs = [
            profile.tlsPackage
            profile.spdlogPackage
            profile.fmtPackage
          ];
          dontConfigure = true;
          doCheck = false;

          buildPhase = ''
            runHook preBuild
            export HOME="$TMPDIR"
            ${mkCoquicEnv profile}
            zig build test ${mkZigBuildArgs profile}
            runHook postBuild
          '';

          installPhase = ''
            mkdir -p $out
            touch $out/passed
          '';
        };
      interopRuntimeTools = pkgs.buildEnv {
        name = "coquic-interop-runtime-tools";
        paths = [
          pkgs.bash
          pkgs.coreutils
          pkgs.ethtool
          pkgs.gnugrep
          pkgs.inetutils
          pkgs.iproute2
          pkgs.nettools
        ];
        pathsToLink = [ "/bin" ];
      };
      mkInteropRoot =
        {
          name,
          coquicPackage,
        }:
        pkgs.runCommand "${name}-rootfs" { } ''
          mkdir -p $out
          mkdir -p $out/bin
          cp -a ${interopRuntimeTools}/bin/. $out/bin/
          chmod u+w $out/bin
          rm -f $out/bin/sh
          ln -s bash $out/bin/sh
          mkdir -p $out/usr/bin $out/usr/local/bin
          ln -s /bin/env $out/usr/bin/env
          ln -s ${coquicPackage}/bin/coquic $out/usr/local/bin/coquic
          cp ${./scripts/run_endpoint.sh} $out/run_endpoint.sh
          cp ${./scripts/simulator_setup.sh} $out/setup.sh
          cp ${./scripts/wait-for-it.sh} $out/wait-for-it.sh
          chmod +x $out/run_endpoint.sh $out/setup.sh $out/wait-for-it.sh
          ln -s /run_endpoint.sh $out/entrypoint.sh
        '';
      mkInteropImage =
        {
          profile,
          coquicPackage,
          fromImage ? null,
          tag ? profile.name,
          includeSimulatorScripts ? true,
        }:
        pkgs.dockerTools.buildLayeredImage {
          name = "coquic-interop";
          inherit fromImage tag;
          contents = [
            (mkInteropRoot {
            name = "coquic-interop-${profile.name}";
            inherit coquicPackage;
            })
          ];
          config = {
            Entrypoint = [ "/run_endpoint.sh" ];
            Env = [ "PATH=/bin:/usr/bin:/usr/local/bin" ];
            WorkingDir = "/";
          };
        };
      mkOfficialEndpointOverlay =
        {
          name,
          coquicPackage,
        }:
        pkgs.runCommand "${name}-overlay" { } ''
          mkdir -p $out/usr/local/bin
          ln -s ${coquicPackage}/bin/coquic $out/usr/local/bin/coquic
          cp ${./scripts/run_endpoint.sh} $out/run_endpoint.sh
          chmod +x $out/run_endpoint.sh
          ln -s /run_endpoint.sh $out/entrypoint.sh
        '';
      mkCoquicShell =
        {
          profile,
          banner,
          extraPackages ? [ ],
          includePreCommit ? false,
        }:
        pkgs.mkShell {
          packages =
            [
              pkgs.zig
              pkgs.gtest
              pkgs.gawk
              pkgs.binutils
              llvmPkgs.llvm
              profile.tlsPackage
              profile.spdlogPackage
              profile.fmtPackage
              pkgs.pkg-config
            ]
            ++ extraPackages
            ++ lib.optionals includePreCommit pre-commit-check.enabledPackages;

          shellHook =
            (if includePreCommit then pre-commit-check.shellHook else "")
            + mkCoquicEnv profile
            + ''
              echo "${banner}"
            '';
      };
      quictlsPackage = mkCoquicPackage quictlsProfile;
      boringsslPackage = mkCoquicPackage boringsslProfile;
      boringsslMuslPackage = mkCoquicPackage boringsslMuslProfile;
      quictlsImage = mkInteropImage {
        profile = quictlsProfile;
        coquicPackage = quictlsPackage;
      };
      boringsslImage = mkInteropImage {
        profile = boringsslProfile;
        coquicPackage = boringsslPackage;
      };
      boringsslMuslImage = pkgs.dockerTools.buildLayeredImage {
        name = "coquic-interop";
        tag = "boringssl-musl";
        fromImage = simulatorEndpointBase;
        contents = [
          (mkOfficialEndpointOverlay {
            name = "coquic-interop-boringssl-musl";
            coquicPackage = boringsslMuslPackage;
          })
        ];
        config = {
          Entrypoint = [ "/run_endpoint.sh" ];
          WorkingDir = "/";
        };
      };
      quictlsShell = mkCoquicShell {
        profile = quictlsProfile;
        banner = "coquic quictls shell ready. Run: zig build -Dtls_backend=quictls";
      };
      boringsslShell = mkCoquicShell {
        profile = boringsslProfile;
        banner = "coquic boringssl shell ready. Run: zig build -Dtls_backend=boringssl";
      };
      boringsslMuslShell = mkCoquicShell {
        profile = boringsslMuslProfile;
        banner = "coquic boringssl musl shell ready. Run: zig build -Dtls_backend=boringssl -Dtarget=x86_64-linux-musl -Dspdlog_shared=false";
      };
      defaultShell = mkCoquicShell {
        profile = quictlsProfile;
        includePreCommit = true;
        banner = "coquic dev shell ready. Run: zig build";
        extraPackages = [
          pkgs.clang-tools
          pkgs.lldb
          boringssl
          pkgs.python3
          pkgs.qdrant
          pkgs.wireshark
        ];
      };
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
      qdrant-dev-app = pkgs.writeShellApplication {
        name = "qdrant-dev";
        runtimeInputs = [
          pkgs.bash
          pkgs.python3
          pkgs.qdrant
        ];
        text = ''
          search_dir="$PWD"
          while true; do
            if [ -f "$search_dir/build.zig" ] && [ -d "$search_dir/docs/rfc" ]; then
              exec "$search_dir/tools/rag/scripts/qdrant-dev" "$@"
            fi
            if [ "$search_dir" = "/" ]; then
              echo "Unable to find repository root from $PWD" >&2
              exit 1
            fi
            search_dir="$(dirname "$search_dir")"
          done
        '';
      };
    in
    {
      checks.${system} = {
        pre-commit-check = pre-commit-check;
        coquic-quictls = quictlsPackage;
        coquic-boringssl = boringsslPackage;
        coquic-boringssl-musl = boringsslMuslPackage;
        coquic-tests-quictls = mkCoquicCheck quictlsProfile;
        coquic-tests-boringssl = mkCoquicCheck boringsslProfile;
      };

      packages.${system} = {
        default = quictlsPackage;
        coquic-quictls = quictlsPackage;
        coquic-boringssl = boringsslPackage;
        coquic-boringssl-musl = boringsslMuslPackage;
        interop-image = quictlsImage;
        interop-image-quictls = quictlsImage;
        interop-image-boringssl = boringsslImage;
        interop-image-boringssl-musl = boringsslMuslImage;
      };

      apps.${system} = {
        qdrant-dev = {
          type = "app";
          program = "${qdrant-dev-app}/bin/qdrant-dev";
        };
        coquic-quictls = {
          type = "app";
          program = "${quictlsPackage}/bin/coquic";
        };
        coquic-boringssl = {
          type = "app";
          program = "${boringsslPackage}/bin/coquic";
        };
        coquic-boringssl-musl = {
          type = "app";
          program = "${boringsslMuslPackage}/bin/coquic";
        };
      };

      devShells.${system} = {
        default = defaultShell;
        quictls = quictlsShell;
        interop-image = quictlsShell;
        boringssl = boringsslShell;
        boringssl-musl = boringsslMuslShell;
      };
    };
}
