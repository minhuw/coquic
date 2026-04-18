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
      quictlsMuslAsyncPatch = pkgs.writeText "quictls-musl-async-posix.patch" ''
        diff --git a/crypto/async/arch/async_posix.h b/crypto/async/arch/async_posix.h
        --- a/crypto/async/arch/async_posix.h
        +++ b/crypto/async/arch/async_posix.h
        @@ -13,4 +13,4 @@
         #if defined(OPENSSL_SYS_UNIX) \
             && defined(OPENSSL_THREADS) && !defined(OPENSSL_NO_ASYNC) \
        -    && !defined(__ANDROID__) && !defined(__OpenBSD__)
        +    && !defined(__ANDROID__) && !defined(__OpenBSD__) && 0
      '';
      quictlsStatic = llvmPkgs.libcxxStdenv.mkDerivation {
        pname = "quictls-static";
        version = quictlsVersion;
        src = quictlsSrc;
        outputs = [
          "out"
          "dev"
        ];
        setOutputFlags = false;
        nativeBuildInputs = [ pkgs.perl ];
        postPatch = ''
          patchShebangs Configure config
          substituteInPlace config --replace '/usr/bin/env' '${pkgs.coreutils}/bin/env'
        '';
        configurePhase = ''
          runHook preConfigure
          ./Configure linux-x86_64 \
            no-shared \
            no-tests \
            --prefix=$out \
            --libdir=lib \
            --openssldir=$out/etc/ssl
          runHook postConfigure
        '';
        enableParallelBuilding = true;
        installPhase = ''
          runHook preInstall
          make install_sw
          mkdir -p $out/etc/ssl
          install -Dm644 apps/openssl.cnf $out/etc/ssl/openssl.cnf
          mkdir -p $dev
          mv $out/include $dev/include
          runHook postInstall
        '';
      };
      quictlsMuslStatic = staticLlvmPkgs.libcxxStdenv.mkDerivation {
        pname = "quictls-musl-static";
        version = quictlsVersion;
        src = quictlsSrc;
        # Match the current nixpkgs musl quictls workaround with an explicit patch.
        patches = [ quictlsMuslAsyncPatch ];
        outputs = [
          "out"
          "dev"
        ];
        setOutputFlags = false;
        nativeBuildInputs = [ pkgs.perl ];
        NIX_LDFLAGS = "-L${muslLibgccEh}/lib";
        postPatch = ''
          patchShebangs Configure config
          substituteInPlace config --replace '/usr/bin/env' '${pkgs.coreutils}/bin/env'
        '';
        configurePhase = ''
          runHook preConfigure
          ./Configure linux-x86_64 \
            no-shared \
            no-tests \
            --prefix=$out \
            --libdir=lib \
            --openssldir=$out/etc/ssl
          runHook postConfigure
        '';
        enableParallelBuilding = true;
        installPhase = ''
          runHook preInstall
          make install_sw
          mkdir -p $out/etc/ssl
          install -Dm644 apps/openssl.cnf $out/etc/ssl/openssl.cnf
          mkdir -p $dev
          mv $out/include $dev/include
          runHook postInstall
        '';
      };
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
          tlsExtraLinkFlags ? [ ],
          spdlogPackage,
          fmtPackage,
          ioUringPackage,
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
            tlsExtraLinkFlags
            spdlogPackage
            fmtPackage
            ioUringPackage
            zigTarget
            spdlogShared
            pkgConfigAllStatic
            ;
          pkgConfigPath = lib.makeSearchPath "lib/pkgconfig" [
            spdlogPackage.dev
            fmtPackage.dev
            ioUringPackage.dev
          ];
        };
      quictlsProfile = mkProfile {
        name = "quictls";
        tlsBackend = "quictls";
        tlsPackage = quictlsStatic;
        tlsLinkage = "static";
        spdlogPackage = spdlogStatic;
        fmtPackage = fmtStatic;
        ioUringPackage = pkgs.liburing;
        spdlogShared = false;
        pkgConfigAllStatic = true;
      };
      quictlsMuslProfile = mkProfile {
        name = "quictls-musl";
        tlsBackend = "quictls";
        tlsPackage = quictlsMuslStatic;
        tlsLinkage = "static";
        spdlogPackage = muslSpdlogStatic;
        fmtPackage = muslFmtStatic;
        ioUringPackage = staticPkgs.liburing;
        zigTarget = "x86_64-linux-musl";
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
        ioUringPackage = pkgs.liburing;
        spdlogShared = false;
      };
      boringsslMuslProfile = mkProfile {
        name = "boringssl-musl";
        tlsBackend = "boringssl";
        tlsPackage = staticPkgs.boringssl;
        tlsLinkage = "static";
        spdlogPackage = muslSpdlogStatic;
        fmtPackage = muslFmtStatic;
        ioUringPackage = staticPkgs.liburing;
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
        export LIBURING_INCLUDE_DIR="${profile.ioUringPackage.dev}/include"
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
            profile.ioUringPackage
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
            cp zig-out/bin/h3-server $out/bin/h3-server
            cp zig-out/bin/coquic-perf $out/bin/coquic-perf
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
            profile.ioUringPackage
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
      mkOfficialEndpointOverlay =
        {
          name,
          coquicPackage,
        }:
        pkgs.runCommand "${name}-overlay" { } ''
          mkdir -p $out/usr/local/bin
          ln -s ${coquicPackage}/bin/coquic $out/usr/local/bin/coquic
          cp ${./interop/entrypoint.sh} $out/entrypoint.sh
          chmod +x $out/entrypoint.sh
        '';
      mkPerfEndpointOverlay =
        {
          name,
          coquicPackage,
        }:
        pkgs.runCommand "${name}-overlay" { } ''
          mkdir -p $out/usr/local/bin
          ln -s ${coquicPackage}/bin/coquic-perf $out/usr/local/bin/coquic-perf
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
              pkgs.curlHTTP3
              llvmPkgs.llvm
              profile.tlsPackage
              profile.spdlogPackage
              profile.fmtPackage
              profile.ioUringPackage
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
      quictlsMuslPackage = mkCoquicPackage quictlsMuslProfile;
      boringsslPackage = mkCoquicPackage boringsslProfile;
      boringsslMuslPackage = mkCoquicPackage boringsslMuslProfile;
      quictlsMuslImage = pkgs.dockerTools.buildLayeredImage {
        name = "coquic-interop";
        tag = "quictls-musl";
        fromImage = simulatorEndpointBase;
        contents = [
          (mkOfficialEndpointOverlay {
            name = "coquic-interop-quictls-musl";
            coquicPackage = quictlsMuslPackage;
          })
        ];
        config = {
          Entrypoint = [ "/entrypoint.sh" ];
          WorkingDir = "/";
        };
      };
      quictlsMuslPerfImage = pkgs.dockerTools.buildLayeredImage {
        name = "coquic-perf";
        tag = "quictls-musl";
        fromImage = simulatorEndpointBase;
        contents = [
          (mkPerfEndpointOverlay {
            name = "coquic-perf-quictls-musl";
            coquicPackage = quictlsMuslPackage;
          })
        ];
        config = {
          Entrypoint = [ "/usr/local/bin/coquic-perf" ];
          WorkingDir = "/";
        };
      };
      quictlsMuslPerfImageStream = pkgs.dockerTools.streamLayeredImage {
        name = "coquic-perf";
        tag = "quictls-musl";
        fromImage = simulatorEndpointBase;
        contents = [
          (mkPerfEndpointOverlay {
            name = "coquic-perf-quictls-musl";
            coquicPackage = quictlsMuslPackage;
          })
        ];
        config = {
          Entrypoint = [ "/usr/local/bin/coquic-perf" ];
          WorkingDir = "/";
        };
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
          Entrypoint = [ "/entrypoint.sh" ];
          WorkingDir = "/";
        };
      };
      quictlsShell = mkCoquicShell {
        profile = quictlsProfile;
        banner = "coquic quictls shell ready (default package uses static non-system deps). Run: zig build -Dtls_backend=quictls";
      };
      quictlsMuslShell = mkCoquicShell {
        profile = quictlsMuslProfile;
        banner = "coquic quictls musl shell ready. Run: zig build -Dtls_backend=quictls -Dtarget=x86_64-linux-musl -Dspdlog_shared=false";
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
          llvmPkgs.clang
          llvmPkgs.clang-tools
          pkgs.lldb
          pkgs.mkcert
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
        coquic-quictls-musl = quictlsMuslPackage;
        coquic-boringssl = boringsslPackage;
        coquic-boringssl-musl = boringsslMuslPackage;
        coquic-tests-quictls = mkCoquicCheck quictlsProfile;
        coquic-tests-boringssl = mkCoquicCheck boringsslProfile;
      };

      packages.${system} = {
        default = quictlsPackage;
        coquic-quictls = quictlsPackage;
        coquic-quictls-musl = quictlsMuslPackage;
        coquic-boringssl = boringsslPackage;
        coquic-boringssl-musl = boringsslMuslPackage;
        curl-http3 = pkgs.curlHTTP3;
        interop-image-quictls-musl = quictlsMuslImage;
        interop-image-boringssl-musl = boringsslMuslImage;
        perf-image-quictls-musl = quictlsMuslPerfImage;
        perf-image-stream-quictls-musl = quictlsMuslPerfImageStream;
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
        coquic-perf-quictls = {
          type = "app";
          program = "${quictlsPackage}/bin/coquic-perf";
        };
        h3-server-quictls = {
          type = "app";
          program = "${quictlsPackage}/bin/h3-server";
        };
        coquic-quictls-musl = {
          type = "app";
          program = "${quictlsMuslPackage}/bin/coquic";
        };
        coquic-perf-quictls-musl = {
          type = "app";
          program = "${quictlsMuslPackage}/bin/coquic-perf";
        };
        h3-server-quictls-musl = {
          type = "app";
          program = "${quictlsMuslPackage}/bin/h3-server";
        };
        coquic-boringssl = {
          type = "app";
          program = "${boringsslPackage}/bin/coquic";
        };
        h3-server-boringssl = {
          type = "app";
          program = "${boringsslPackage}/bin/h3-server";
        };
        coquic-boringssl-musl = {
          type = "app";
          program = "${boringsslMuslPackage}/bin/coquic";
        };
        h3-server-boringssl-musl = {
          type = "app";
          program = "${boringsslMuslPackage}/bin/h3-server";
        };
        curl-http3 = {
          type = "app";
          program = "${pkgs.curlHTTP3}/bin/curl";
        };
      };

      devShells.${system} = {
        default = defaultShell;
        quictls = quictlsShell;
        quictls-musl = quictlsMuslShell;
        interop-image = quictlsMuslShell;
        boringssl = boringsslShell;
        boringssl-musl = boringsslMuslShell;
      };
    };
}
