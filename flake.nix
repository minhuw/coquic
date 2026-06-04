{
  description = "Development environment and CI tooling for coquic";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
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
      zig = pkgs.zig_0_16;
      ngtcp2TlsPackage = pkgs.openssl;
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
      boringssl = pkgs.boringssl.override {
        withShared = false;
      };
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
          profileHooks ? true,
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
            profileHooks
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
      quictlsMuslPerfProfile = quictlsMuslProfile // {
        name = "quictls-musl-perf";
        profileHooks = false;
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
      boringsslMuslPerfProfile = boringsslMuslProfile // {
        name = "boringssl-musl-perf";
        profileHooks = false;
      };
      boringsslMuslProfileHooksProfile = boringsslMuslProfile // {
        name = "boringssl-musl-profile-hooks";
        profileHooks = true;
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
        # Keep the selected TLS backend ahead of OpenSSL headers propagated by shell tools.
        export NIX_CFLAGS_COMPILE="-isystem ${profile.tlsPackage.dev}/include ''${NIX_CFLAGS_COMPILE:-}"
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
            "-Dprofile_hooks=${if profile.profileHooks then "true" else "false"}"
          ]
          ++ lib.optionals (profile.zigTarget != null) [
            "-Dtarget=${profile.zigTarget}"
          ]
        );
      mkCoquicPackage =
        {
          profile,
          includeFfiSdk ? false,
        }:
        pkgs.stdenv.mkDerivation {
          pname = "coquic-${profile.name}";
          version = "dev";
          src = projectSrc;
          strictDeps = true;
          nativeBuildInputs = [
            pkgs.bash
            pkgs.gtest
            pkgs.pkg-config
            zig
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
            ${lib.optionalString includeFfiSdk "zig build package ${mkZigBuildArgs profile}"}
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            ${
              if includeFfiSdk then
                ''
                  mkdir -p $out
                  cp -R zig-out/. $out/
                ''
              else
                ''
                  mkdir -p $out/bin
                  cp zig-out/bin/coquic $out/bin/coquic
                  cp zig-out/bin/h3-server $out/bin/h3-server
                  cp zig-out/bin/coquic-perf $out/bin/coquic-perf
                ''
            }
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
            zig
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
          quicgoPerfClient ? null,
          quinnPerfClient ? null,
          picoquicPerfClient ? null,
          msquicPerfClient ? null,
          quichePerfClient ? null,
          quiclyPerfClient ? null,
          coquicRustPerfClient ? null,
          coquicPythonPerfClient ? null,
          coquicGoPerfClient ? null,
          googleQuichePerfClient ? null,
          tquicPerfClient ? null,
          mvfstPerfClient ? null,
          s2nQuicPerfClient ? null,
          xquicPerfClient ? null,
          aioquicPerfClient ? null,
          ngtcp2PerfClient ? null,
          lsquicPerfClient ? null,
          neqoPerfClient ? null,
        }:
        pkgs.runCommand "${name}-overlay" { } ''
          mkdir -p $out/usr/local/bin
          ln -s ${coquicPackage}/bin/coquic-perf $out/usr/local/bin/coquic-perf
          ${lib.optionalString (quicgoPerfClient != null) ''
            ln -s ${quicgoPerfClient}/bin/quicgo-perf $out/usr/local/bin/quicgo-perf
          ''}
          ${lib.optionalString (quinnPerfClient != null) ''
            ln -s ${quinnPerfClient}/bin/quinn-perf $out/usr/local/bin/quinn-perf
          ''}
          ${lib.optionalString (picoquicPerfClient != null) ''
            ln -s ${picoquicPerfClient}/bin/picoquic-perf $out/usr/local/bin/picoquic-perf
          ''}
          ${lib.optionalString (msquicPerfClient != null) ''
            ln -s ${msquicPerfClient}/bin/msquic-perf $out/usr/local/bin/msquic-perf
          ''}
          ${lib.optionalString (quichePerfClient != null) ''
            ln -s ${quichePerfClient}/bin/quiche-perf $out/usr/local/bin/quiche-perf
          ''}
          ${lib.optionalString (quiclyPerfClient != null) ''
            ln -s ${quiclyPerfClient}/bin/quicly-perf $out/usr/local/bin/quicly-perf
          ''}
          ${lib.optionalString (coquicRustPerfClient != null) ''
            ln -s ${coquicRustPerfClient}/bin/coquic-rust-perf $out/usr/local/bin/coquic-rust-perf
          ''}
          ${lib.optionalString (coquicPythonPerfClient != null) ''
            ln -s ${coquicPythonPerfClient}/bin/coquic-python-perf $out/usr/local/bin/coquic-python-perf
          ''}
          ${lib.optionalString (coquicGoPerfClient != null) ''
            ln -s ${coquicGoPerfClient}/bin/coquic-go-perf $out/usr/local/bin/coquic-go-perf
          ''}
          ${lib.optionalString (googleQuichePerfClient != null) ''
            ln -s ${googleQuichePerfClient}/bin/google-quiche-perf $out/usr/local/bin/google-quiche-perf
          ''}
          ${lib.optionalString (tquicPerfClient != null) ''
            ln -s ${tquicPerfClient}/bin/tquic-perf $out/usr/local/bin/tquic-perf
          ''}
          ${lib.optionalString (mvfstPerfClient != null) ''
            ln -s ${mvfstPerfClient}/bin/mvfst-perf $out/usr/local/bin/mvfst-perf
          ''}
          ${lib.optionalString (s2nQuicPerfClient != null) ''
            ln -s ${s2nQuicPerfClient}/bin/s2n-quic-perf $out/usr/local/bin/s2n-quic-perf
          ''}
          ${lib.optionalString (xquicPerfClient != null) ''
            ln -s ${xquicPerfClient}/bin/xquic-perf $out/usr/local/bin/xquic-perf
          ''}
          ${lib.optionalString (aioquicPerfClient != null) ''
            ln -s ${aioquicPerfClient}/bin/aioquic-perf $out/usr/local/bin/aioquic-perf
          ''}
          ${lib.optionalString (ngtcp2PerfClient != null) ''
            ln -s ${ngtcp2PerfClient}/bin/ngtcp2-perf $out/usr/local/bin/ngtcp2-perf
          ''}
          ${lib.optionalString (lsquicPerfClient != null) ''
            ln -s ${lsquicPerfClient}/bin/lsquic-perf $out/usr/local/bin/lsquic-perf
          ''}
          ${lib.optionalString (neqoPerfClient != null) ''
            ln -s ${neqoPerfClient}/bin/neqo-perf $out/usr/local/bin/neqo-perf
          ''}
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
              zig
              pkgs.gtest
              pkgs.gawk
              pkgs.binutils
              pkgs.curl
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
              export LD_LIBRARY_PATH="${lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib pkgs.zlib ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
              echo "${banner}"
            '';
      };
      quictlsPackage = mkCoquicPackage {
        profile = quictlsProfile;
        includeFfiSdk = true;
      };
      quictlsMuslPackage = mkCoquicPackage {
        profile = quictlsMuslProfile;
      };
      quictlsMuslPerfPackage = mkCoquicPackage {
        profile = quictlsMuslPerfProfile;
      };
      boringsslPackage = mkCoquicPackage {
        profile = boringsslProfile;
        includeFfiSdk = true;
      };
      boringsslMuslPackage = mkCoquicPackage {
        profile = boringsslMuslProfile;
      };
      boringsslMuslPerfPackage = mkCoquicPackage {
        profile = boringsslMuslPerfProfile;
      };
      boringsslMuslProfileHooksPackage = mkCoquicPackage {
        profile = boringsslMuslProfileHooksProfile;
      };
      quicgoPerfClient = pkgs.buildGoModule {
        pname = "quicgo-perf-client";
        version = "dev";
        src = ./bench/quicgo-perf;
        vendorHash = "sha256-lqos9WjFCedcUHa1Y6lWVxaggTrS4fwlbn352OqLTfw=";
        env.CGO_ENABLED = "0";
      };
      quinnPerfClient = pkgs.rustPlatform.buildRustPackage {
        pname = "quinn-perf-client";
        version = "dev";
        src = ./bench/quinn-perf;
        cargoHash = "sha256-k3wfuwWKkH6lMe6TXRwts5qIX1xC47x/JvbfF6Pkw2c=";
      };
      coquicRustPerfClient = pkgs.rustPlatform.buildRustPackage {
        pname = "coquic-rust-perf-client";
        version = "dev";
        src = projectSrc;
        cargoRoot = "bench/coquic-rust-perf";
        buildAndTestSubdir = "bench/coquic-rust-perf";
        cargoLock = {
          lockFile = ./bench/coquic-rust-perf/Cargo.lock;
        };
        cargoBuildFlags = [
          "--bin"
          "coquic-rust-perf"
        ];
        nativeBuildInputs = [
          pkgs.makeWrapper
        ];
        buildInputs = [
          boringsslPackage
        ];
        COQUIC_TLS_BACKEND = "boringssl";
        COQUIC_LIB_DIR = "${boringsslPackage}/lib";
        COQUIC_LIB_NAME = "coquic-boringssl";
        COQUIC_LINK_KIND = "dylib";
        LD_LIBRARY_PATH = lib.makeLibraryPath [
          boringsslPackage
          pkgs.stdenv.cc.cc.lib
        ];
        postFixup = ''
          wrapProgram "$out/bin/coquic-rust-perf" \
            --prefix LD_LIBRARY_PATH : ${
              lib.makeLibraryPath [
                boringsslPackage
                pkgs.stdenv.cc.cc.lib
              ]
          }
        '';
      };
      coquicPythonPerfClient = pkgs.stdenvNoCC.mkDerivation {
        pname = "coquic-python-perf-client";
        version = "dev";
        src = projectSrc;
        dontBuild = true;
        nativeBuildInputs = [
          pkgs.makeWrapper
        ];
        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin $out/share/coquic-python $out/share/coquic-python-perf
          cp -R bindings/python/coquic $out/share/coquic-python/coquic
          cp -R bench/coquic-python-perf/coquic_python_perf $out/share/coquic-python-perf/coquic_python_perf
          makeWrapper "${pkgs.python3}/bin/python" "$out/bin/coquic-python-perf" \
            --add-flags "-m coquic_python_perf" \
            --set COQUIC_LIB_DIR "${boringsslPackage}/lib" \
            --set COQUIC_LIB_NAME "coquic-boringssl" \
            --prefix LD_LIBRARY_PATH : ${
              lib.makeLibraryPath [
                boringsslPackage
                pkgs.stdenv.cc.cc.lib
              ]
            } \
            --prefix PYTHONPATH : "$out/share/coquic-python:$out/share/coquic-python-perf"
          runHook postInstall
        '';
      };
      coquicGoPerfClient = pkgs.stdenv.mkDerivation {
        pname = "coquic-go-perf-client";
        version = "dev";
        src = projectSrc;
        nativeBuildInputs = [
          pkgs.go
          pkgs.makeWrapper
        ];
        buildInputs = [
          boringsslPackage
        ];
        CGO_ENABLED = "1";
        CGO_LDFLAGS = "-L${boringsslPackage}/lib -lcoquic-boringssl";
        LD_LIBRARY_PATH = lib.makeLibraryPath [
          boringsslPackage
          pkgs.stdenv.cc.cc.lib
        ];
        buildPhase = ''
          runHook preBuild
          export GOCACHE="$TMPDIR/go-cache"
          export GOPATH="$TMPDIR/go"
          export GOFLAGS="-mod=mod"
          pushd bench/coquic-go-perf
          go build -tags boringssl -trimpath -o coquic-go-perf ./cmd/coquic-go-perf
          popd
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          install -Dm755 bench/coquic-go-perf/coquic-go-perf "$out/bin/coquic-go-perf"
          runHook postInstall
        '';
        postFixup = ''
          wrapProgram "$out/bin/coquic-go-perf" \
            --prefix LD_LIBRARY_PATH : ${
              lib.makeLibraryPath [
                boringsslPackage
                pkgs.stdenv.cc.cc.lib
              ]
            }
        '';
      };
      aioquicPerfClient = pkgs.stdenvNoCC.mkDerivation {
        pname = "aioquic-perf-client";
        version = "dev";
        src = ./bench/aioquic-perf;
        dontBuild = true;
        pythonEnv = pkgs.python3.withPackages (ps: [
          ps.aioquic
        ]);
        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin $out/share/aioquic-perf
          cp aioquic-perf $out/share/aioquic-perf/aioquic-perf.py
          makeWrapper "$pythonEnv/bin/python" "$out/bin/aioquic-perf" \
            --add-flags "$out/share/aioquic-perf/aioquic-perf.py"
          runHook postInstall
        '';
        nativeBuildInputs = [
          pkgs.makeWrapper
        ];
      };
      ngtcp2PerfClient = pkgs.stdenv.mkDerivation {
        pname = "ngtcp2-perf-client";
        version = pkgs.ngtcp2.version;
        src = pkgs.ngtcp2.src;
        perfSource = ./bench/ngtcp2-perf/ngtcp2-perf.c;
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.perl
          pkgs.pkg-config
        ];
        buildInputs = [
          pkgs.brotli
          pkgs.libev
          pkgs.nghttp3
          ngtcp2TlsPackage
        ];
        cmakeFlags = [
          "-DENABLE_STATIC_LIB=FALSE"
          "-DENABLE_SHARED_LIB=TRUE"
          "-DENABLE_LIB_ONLY=FALSE"
          "-DENABLE_OPENSSL=TRUE"
          "-DENABLE_GNUTLS=FALSE"
          "-DENABLE_BORINGSSL=FALSE"
          "-DENABLE_PICOTLS=FALSE"
          "-DENABLE_WOLFSSL=FALSE"
          "-DBUILD_TESTING=OFF"
        ];
        buildPhase = ''
          runHook preBuild
          source_root="$(pwd)/.."
          cmake --build . --target ngtcp2 ngtcp2_crypto_ossl
          $CC \
            -O2 \
            -I"$source_root/lib/includes" \
            -Ilib/includes \
            -I"$source_root/crypto/includes" \
            -I${ngtcp2TlsPackage.dev}/include \
            -o ngtcp2-perf \
            "$perfSource" \
            lib/libngtcp2.so \
            crypto/ossl/libngtcp2_crypto_ossl.so \
            -L${ngtcp2TlsPackage.out}/lib \
            -Wl,-rpath,$out/lib \
            -Wl,-rpath,${
              lib.makeLibraryPath [
                pkgs.brotli.lib
                pkgs.libev
                pkgs.nghttp3
                ngtcp2TlsPackage
                pkgs.glibc
                pkgs.stdenv.cc.cc.lib
              ]
            } \
            -lssl \
            -lcrypto \
            -lm
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin $out/lib
          cp lib/libngtcp2.so* crypto/ossl/libngtcp2_crypto_ossl.so* $out/lib/
          ngtcp2_rpath="${
            lib.makeLibraryPath [
              pkgs.brotli.lib
              pkgs.libev
              pkgs.nghttp3
              ngtcp2TlsPackage
              pkgs.glibc
              pkgs.stdenv.cc.cc.lib
            ]
          }:$out/lib"
          cp ngtcp2-perf $out/bin/ngtcp2-perf
          for libfile in $out/lib/*.so*; do
            if [ -f "$libfile" ] && [ ! -L "$libfile" ]; then
              patchelf --set-rpath "$ngtcp2_rpath" "$libfile"
            fi
          done
          runHook postInstall
        '';
      };
      lsquicSrc = pkgs.fetchFromGitHub {
        owner = "litespeedtech";
        repo = "lsquic";
        rev = "v4.7.1";
        fetchSubmodules = true;
        hash = "sha256-Krz718ndMTMODTNRBTlAW093adKksVjV4xLskFwrOow=";
      };
      lsquicPerfClient = pkgs.stdenv.mkDerivation {
        pname = "lsquic-perf-client";
        version = "4.7.1";
        src = lsquicSrc;
        perfSource = ./bench/lsquic-perf/lsquic-perf.c;
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.perl
        ];
        buildInputs = [
          boringssl
          pkgs.libevent
          pkgs.zlib
        ];
        cmakeFlags = [
          "-DCMAKE_BUILD_TYPE=Release"
          "-DLSQUIC_LIBSSL=BORINGSSL"
          "-DLSQUIC_BIN=ON"
          "-DLSQUIC_TESTS=OFF"
          "-DLIBSSL_DIR=${boringssl}"
          "-DSSLLIB_INCLUDE=${boringssl.dev}/include"
          "-DLIBSSL_LIB_ssl=${boringssl}/lib/libssl.a"
          "-DLIBSSL_LIB_crypto=${boringssl}/lib/libcrypto.a"
          "-DZLIB_INCLUDE_DIR=${pkgs.zlib.dev}/include"
          "-DZLIB_LIB=${pkgs.zlib.static}/lib/libz.a"
          "-DEVENT_INCLUDE_DIR=${pkgs.libevent.dev}/include"
          "-DEVENT_LIB=${pkgs.libevent}/lib/libevent.so"
        ];
        buildPhase = ''
          runHook preBuild
          cmake --build . --target lsquic
          $CC -O3 -std=gnu11 -Wall -Wextra \
            -I$src/include \
            -I$src/bin \
            -I$src/src/lshpack \
            -I$src/src/liblsquic \
            -I$src/src/liblsquic/ls-qpack \
            -Ibin \
            "$perfSource" \
            "$src/bin/prog.c" \
            "$src/bin/test_common.c" \
            "$src/bin/test_cert.c" \
            -o lsquic-perf \
            src/liblsquic/liblsquic.a \
            ${boringssl}/lib/libssl.a \
            ${boringssl}/lib/libcrypto.a \
            ${pkgs.zlib.static}/lib/libz.a \
            ${pkgs.libevent}/lib/libevent.so \
            -lstdc++ -lpthread -lm
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin
          cp lsquic-perf $out/bin/lsquic-perf
          patchelf --set-rpath "${lib.makeLibraryPath [ pkgs.libevent pkgs.stdenv.cc.cc.lib ]}" \
            $out/bin/lsquic-perf
          runHook postInstall
        '';
      };
      neqoSrc = pkgs.fetchFromGitHub {
        owner = "mozilla";
        repo = "neqo";
        rev = "v0.28.1";
        hash = "sha256-/H3bvSuoX0tChLLlf65xMc0nUZBipRL2u8YuMql41Cg=";
      };
      nssForNeqoPerf = pkgs.nss_latest;
      neqoPerfClient = pkgs.rustPlatform.buildRustPackage {
        pname = "neqo-perf-client";
        version = "0.28.1";
        src = neqoSrc;
        cargoHash = "sha256-xRjNfIckWKhW0EqNYmsKI8bT66jRl0xWh/4Ckr27VPk=";
        depsExtraArgs.postPatch = ''
          cp ${./bench/neqo-perf/Cargo.lock} Cargo.lock
        '';
        buildAndTestSubdir = "neqo-bin";
        perfSource = ./bench/neqo-perf/neqo-perf.rs;
        nativeBuildInputs = [
          pkgs.makeWrapper
          pkgs.pkg-config
          pkgs.rustPlatform.bindgenHook
        ];
        buildInputs = [
          pkgs.nspr
          nssForNeqoPerf
        ];
        cargoBuildFlags = [
          "--bin"
          "neqo-perf"
        ];
        doCheck = false;
        postPatch = ''
          cp ${./bench/neqo-perf/Cargo.lock} Cargo.lock
          cp "$perfSource" neqo-bin/src/bin/neqo-perf.rs
          cat >> neqo-bin/Cargo.toml <<'EOF'

[[bin]]
name = "neqo-perf"
path = "src/bin/neqo-perf.rs"
bench = false
EOF
        '';
        postInstall = ''
          mkdir -p $out/libexec/neqo-perf
          cp -R $src/test-fixture/db $out/libexec/neqo-perf/db
          wrapProgram $out/bin/neqo-perf \
            --set NEQO_PERF_DB "$out/libexec/neqo-perf/db" \
            --prefix LD_LIBRARY_PATH : "${lib.makeLibraryPath [ pkgs.nspr nssForNeqoPerf pkgs.sqlite pkgs.zlib pkgs.stdenv.cc.cc.lib ]}"
        '';
      };
      sodiumCmakeModule = pkgs.writeTextDir "share/cmake/Modules/FindSodium.cmake" ''
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(Sodium REQUIRED IMPORTED_TARGET libsodium)
        if (NOT TARGET Sodium::sodium)
          add_library(Sodium::sodium ALIAS PkgConfig::Sodium)
        endif()
        set(Sodium_FOUND TRUE)
      '';
      facebookQuicVersion = "2026.05.25.00";
      follyForMvfstPerf = pkgs.folly.overrideAttrs (
        finalAttrs: previousAttrs: {
          version = facebookQuicVersion;
          src = pkgs.fetchFromGitHub {
            owner = "facebook";
            repo = "folly";
            tag = "v${finalAttrs.version}";
            hash = "sha256-27TVY8xcePU7LK8aWswREnHNvx9v+ST5QUc8JW2fBQY=";
          };
          patches = [ ];
          cmakeFlags =
            lib.filter (
              flag:
              !(lib.hasPrefix "-DBUILD_TESTS" flag) && !(lib.hasPrefix "-DBUILD_EXAMPLES" flag)
            ) (previousAttrs.cmakeFlags or [ ])
            ++ [
              "-DBUILD_TESTS:BOOL=FALSE"
              "-DBUILD_EXAMPLES:BOOL=FALSE"
            ];
          doCheck = false;
        }
      );
      fizzForMvfstPerf = pkgs.fizz.overrideAttrs (
        finalAttrs: previousAttrs: {
          version = facebookQuicVersion;
          src = pkgs.fetchFromGitHub {
            owner = "facebookincubator";
            repo = "fizz";
            tag = "v${finalAttrs.version}";
            hash = "sha256-pBWcv+aRUFvkEOgXmOAe+ZZHTX509uWbNqxcQX8RZOA=";
          };
          patches = [ ];
          cmakeFlags =
            lib.filter (
              flag:
              !(lib.hasPrefix "-DBUILD_TESTS" flag) && !(lib.hasPrefix "-DBUILD_EXAMPLES" flag)
            ) (previousAttrs.cmakeFlags or [ ])
            ++ [
              "-DBUILD_TESTS:BOOL=FALSE"
              "-DBUILD_EXAMPLES:BOOL=FALSE"
            ];
          doCheck = false;
          postInstall = (previousAttrs.postInstall or "") + ''
            mkdir -p "$bin"
          '';
          propagatedBuildInputs = [
            follyForMvfstPerf
            pkgs.libsodium
            pkgs.zlib
          ];
        }
      );
      mvfstForMvfstPerf = pkgs.mvfst.overrideAttrs (
        finalAttrs: previousAttrs: {
          version = facebookQuicVersion;
          src = pkgs.fetchFromGitHub {
            owner = "facebook";
            repo = "mvfst";
            tag = "v${finalAttrs.version}";
            hash = "sha256-UQeRXs70wdX/xxycedFrRoXEiQ+/kash7D5EMgWogjU=";
          };
          patches = [ ];
          cmakeFlags =
            lib.filter (flag: !(lib.hasPrefix "-DBUILD_TESTS" flag)) (previousAttrs.cmakeFlags or [ ])
            ++ [
              "-DBUILD_TESTS:BOOL=FALSE"
            ];
          doCheck = false;
          postInstall = (previousAttrs.postInstall or "") + ''
            mkdir -p "$bin"
          '';
          buildInputs = [
            follyForMvfstPerf
            pkgs.gflags
            pkgs.glog
            pkgs.fmt
            pkgs.openssl
          ];
          propagatedBuildInputs = [
            fizzForMvfstPerf
          ];
        }
      );
      mvfstPerfClient = pkgs.stdenv.mkDerivation {
        pname = "mvfst-perf-client";
        version = facebookQuicVersion;
        src = ./bench/mvfst-perf;
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.makeWrapper
          pkgs.ninja
          pkgs.pkg-config
        ];
        buildInputs = [
          mvfstForMvfstPerf
          follyForMvfstPerf
          fizzForMvfstPerf
          pkgs.boost
          pkgs.gflags
          pkgs.glog
          pkgs.openssl
          pkgs.zlib
          pkgs.libsodium
          pkgs.libsodium.dev
        ];
        cmakeFlags = [
          "-DCMAKE_MODULE_PATH=${sodiumCmakeModule}/share/cmake/Modules"
        ];
        postFixup = ''
          wrapProgram "$out/bin/mvfst-perf" \
            --prefix LD_LIBRARY_PATH : ${
              lib.makeLibraryPath [
                mvfstForMvfstPerf
                follyForMvfstPerf
                fizzForMvfstPerf
                pkgs.boost
                pkgs.gflags
                pkgs.glog
                pkgs.openssl
                pkgs.zlib
                pkgs.libsodium
                pkgs.double-conversion
                pkgs.libevent
                pkgs.fmt
                pkgs.xz
                pkgs.lz4
                pkgs.zstd
                pkgs.libunwind
                pkgs.icu
                pkgs.stdenv.cc.cc.lib
              ]
            }
        '';
      };
      s2nQuicPerfClient = pkgs.rustPlatform.buildRustPackage {
        pname = "s2n-quic-perf-client";
        version = "dev";
        src = ./bench/s2n-quic-perf;
        cargoHash = "sha256-k1DA7O55DTDRdTIWYhUEZBlH3+p9NcgzHI/qgagqrq8=";
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.pkg-config
        ];
      };
      libmsquicForMsquicPerf = pkgs.libmsquic.overrideAttrs (
        finalAttrs: _previousAttrs: {
          version = "2.5.8";
          src = pkgs.fetchFromGitHub {
            owner = "microsoft";
            repo = "msquic";
            tag = "v${finalAttrs.version}";
            hash = "sha256-IOPKIjJVZUBU13YkL7C7c9Y6cA9L62FYRKvFiXWTeLE=";
            fetchSubmodules = true;
          };
          buildInputs = [
            pkgs.libatomic_ops
          ]
          ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
            pkgs.lttng-tools
          ];
        }
      );
      msquicPerfClient = pkgs.rustPlatform.buildRustPackage {
        pname = "msquic-perf-client";
        version = "dev";
        src = ./bench/msquic-perf;
        cargoHash = "sha256-XOSZdG0Af1XZkuXDOCIVSONlxQzHu/LRI5tR3bxXRV4=";
        buildInputs = [
          libmsquicForMsquicPerf
        ];
        postPatch = ''
          msquic_async_toml="$(find "$cargoDepsCopy" -path '*/msquic-async-0.4.1/Cargo.toml' -print -quit)"
          msquic_build_rs="$(find "$cargoDepsCopy" -path '*/msquic-2.5.1-beta/scripts/build.rs' -print -quit)"
          if [ -z "$msquic_async_toml" ] || [ -z "$msquic_build_rs" ]; then
            echo "unable to locate vendored msquic crates under $cargoDepsCopy" >&2
            exit 1
          fi
          substituteInPlace "$msquic_async_toml" \
            --replace-fail 'msquic-2-5-static = ["msquic-v2-5/static"]' 'msquic-2-5-static = ["msquic-v2-5"]' \
            --replace-fail 'features = ["preview-api"]' 'features = ["preview-api", "find"]' \
            --replace-fail 'version = "2.5.1-beta"' $'version = "2.5.1-beta"\ndefault-features = false'
          substituteInPlace "$msquic_build_rs" \
            --replace-fail 'let installed_dir = "/usr/lib/x86_64-linux-gnu";' 'let installed_dir = "${libmsquicForMsquicPerf}/lib";'
        '';
      };
      quichePerfClient = pkgs.rustPlatform.buildRustPackage {
        pname = "quiche-perf-client";
        version = "dev";
        src = ./bench/quiche-perf;
        cargoHash = "sha256-5m+oup7YJJ8xDk2zfZjnkcZvlsp9j42whzNnMO3RZkc=";
        nativeBuildInputs = [
          pkgs.git
          llvmPkgs.clang
          llvmPkgs.libclang
          pkgs.pkg-config
        ];
        buildInputs = [
          pkgs.libffi
        ];
        LIBCLANG_PATH = "${llvmPkgs.libclang.lib}/lib";
        LD_LIBRARY_PATH = lib.makeLibraryPath [
          llvmPkgs.libclang.lib
          pkgs.libffi
        ];
        preBuild = ''
          export PATH="${pkgs.cmake}/bin:${pkgs.gnumake}/bin:$PATH"
        '';
      };
      quiclySrc = pkgs.fetchFromGitHub {
        owner = "h2o";
        repo = "quicly";
        rev = "61ae24151f65a6a1b06f4d766530c95dcb7b88aa";
        fetchSubmodules = true;
        hash = "sha256-2CfTKQlyiw6vzfo+RcIvxmSIfev0O8WdO0I1mJO+Adw=";
      };
      quiclyPerfClient = pkgs.stdenv.mkDerivation {
        pname = "quicly-perf-client";
        version = "dev";
        src = quiclySrc;
        perfSource = ./bench/quicly-perf/quicly-perf.c;
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.perl
          pkgs.pkg-config
        ];
        buildInputs = [
          pkgs.openssl
        ];
        cmakeFlags = [
          "-DWITH_FUSION=OFF"
          "-DCMAKE_BUILD_TYPE=Release"
        ];
        buildPhase = ''
          runHook preBuild
          cmake --build . --target quicly
          $CC -O3 -std=gnu11 -Wall -Wextra \
            -DQUICLY_USE_TRACER=0 \
            -I$src/include \
            -I$src/deps/klib \
            -I$src/deps/picotls/include \
            -I$src/deps/picotest \
            -I. \
            "$perfSource" \
            "$src/deps/picotls/lib/hpke.c" \
            "$src/deps/picotls/lib/openssl.c" \
            "$src/deps/picotls/lib/pembase64.c" \
            "$src/deps/picotls/lib/picotls.c" \
            -o quicly-perf \
            libquicly.a \
            ${pkgs.openssl.out}/lib/libcrypto.so \
            -ldl -lm
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin
          cp quicly-perf $out/bin/quicly-perf
          patchelf --set-rpath "${lib.makeLibraryPath [ pkgs.openssl pkgs.stdenv.cc.cc.lib ]}" \
            $out/bin/quicly-perf
          runHook postInstall
        '';
      };
      googleQuicheSrc = pkgs.fetchFromGitHub {
        owner = "google";
        repo = "quiche";
        rev = "e05dcf9143b7827bc39a1a4fab61af7703eb444c";
        hash = "sha256-K4f5P+JO26Xr5HPCfvgDQps8wGXEfRWbraSexr8sbuM=";
      };
      googleQuicheBazelCentralRegistry = pkgs.fetchFromGitHub {
        owner = "bazelbuild";
        repo = "bazel-central-registry";
        rev = "5079f39dd37c78df6c2172b7a03b696f2525d0a8";
        hash = "sha256-AjmbMHjHLwGuWwp88B3QhYBbktCOhPL/L8sRa3Pf7w0=";
      };
      googleQuichePerfClient = pkgs.buildBazelPackage {
        pname = "google-quiche-perf-client";
        version = "dev";
        src = googleQuicheSrc;
        perfSource = ./bench/google-quiche-perf/google-quiche-perf.cc;
        bazel = pkgs.bazel_7;
        bazelFlags = [
          "--registry"
          "file://${googleQuicheBazelCentralRegistry}"
        ];
        postPatch = ''
          substituteInPlace .bazelversion --replace-fail '8.2.1' '7.6.0'
          echo "common --repository_cache=\"$bazelOut/external/repository_cache\"" >> .bazelrc
          cp "$perfSource" quiche/quic/tools/google_quiche_perf.cc
          cat >> quiche/BUILD.bazel <<'EOF'

cc_binary(
    name = "google_quiche_perf",
    srcs = ["quic/tools/google_quiche_perf.cc"],
    deps = [
        ":io_tool_support",
        ":quiche_core",
        ":quiche_tool_support",
        "@boringssl//:crypto",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/strings",
    ],
)
EOF
        '';
        nativeBuildInputs = [
          pkgs.jdk
        ];
        buildInputs = [
          pkgs.icu
        ];
        removeRulesCC = false;
        bazelBuildFlags = [
          "--repository_cache=$bazelOut/external/repository_cache"
          "--repository_disable_download"
          "-c opt"
        ];
        bazelTargets = [
          "//quiche:google_quiche_perf"
        ];
        fetchAttrs = {
          hash = "sha256-0ap9eH2Mt9K4f2XbupSQMN/5KTrfZN6BY0nVXFiTSdA=";
          postPatch = ''
            substituteInPlace .bazelversion --replace-fail '8.2.1' '7.6.0'
            echo "common --repository_cache=\"$bazelOut/external/repository_cache\"" >> .bazelrc
            cp "$perfSource" quiche/quic/tools/google_quiche_perf.cc
            cat >> quiche/BUILD.bazel <<'EOF'

cc_binary(
    name = "google_quiche_perf",
    srcs = ["quic/tools/google_quiche_perf.cc"],
    deps = [
        ":io_tool_support",
        ":quiche_core",
        ":quiche_tool_support",
        "@boringssl//:crypto",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/strings",
    ],
)
EOF
          '';
          installPhase = ''
            runHook preInstall

            rm -rf $bazelOut/external/{bazel_tools,\@bazel_tools.marker}
            rm -rf $bazelOut/external/{embedded_jdk,\@embedded_jdk.marker}
            rm -rf $bazelOut/external/{local_config_cc,\@local_config_cc.marker}
            rm -rf $bazelOut/external/{local_*,\@local_*.marker}

            rm -rf $bazelOut/external/*[~+]{local_config_cc,local_config_cc.marker}
            rm -rf $bazelOut/external/*[~+]{local_config_sh,local_config_sh.marker}
            rm -rf $bazelOut/external/*[~+]{local_jdk,local_jdk.marker}

            find $bazelOut/external -name '@*\.marker' -exec sh -c 'echo > {}' \;
            rm -rf $(find $bazelOut/external -type d -name .git)
            rm -rf $(find $bazelOut/external -type d -name .svn)
            rm -rf $(find $bazelOut/external -type d -name .hg)

            find $bazelOut/external -maxdepth 1 -type l | while read symlink; do
              name="$(basename "$symlink")"
              rm "$symlink"
              test -f "$bazelOut/external/@$name.marker" && rm "$bazelOut/external/@$name.marker" || true
            done

            find $bazelOut/external -type l | while read symlink; do
              new_target="$(readlink "$symlink" | sed "s,$NIX_BUILD_TOP,NIX_BUILD_TOP,")"
              rm "$symlink"
              ln -sf "$new_target" "$symlink"
            done

            echo '${pkgs.bazel_7.name}' > $bazelOut/external/.nix-bazel-version

            (cd $bazelOut/ && tar czf $out --sort=name --mtime='@1' --owner=0 --group=0 --numeric-owner external/)

            runHook postInstall
          '';
        };
        buildAttrs = {
          preConfigure = ''
            echo "common --repository_cache=\"$bazelOut/external/repository_cache\"" >> .bazelrc
            echo "common --repository_disable_download" >> .bazelrc
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin
            cp bazel-bin/quiche/google_quiche_perf $out/bin/google-quiche-perf
            runHook postInstall
          '';
        };
      };
      tquicSrc = pkgs.fetchFromGitHub {
        owner = "Tencent";
        repo = "tquic";
        rev = "d87a9a072475e381e64bfeb5732f2f505c2c28b7";
        hash = "sha256-c0f5rPMhuOBq0xMHr5LthZoAi/ryLHphw0sbd8fc7YE=";
      };
      tquicPerfClient = pkgs.rustPlatform.buildRustPackage {
        pname = "tquic-perf-client";
        version = "dev";
        src = tquicSrc;
        buildAndTestSubdir = "tools";
        cargoHash = "sha256-QzfLW+5eOrPilBEl0C25Mkj411lWZPGAqjW320rTjuU=";
        depsExtraArgs.postPatch = ''
          cp ${./bench/tquic-perf/Cargo.lock} Cargo.lock
          substituteInPlace tools/Cargo.toml --replace-fail 'tquic = { path = "..", version = "1.5.0"}' 'tquic = { path = "..", version = "1.6.0"}'
        '';
        perfSource = ./bench/tquic-perf/tquic-perf.rs;
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.makeWrapper
          pkgs.ninja
          pkgs.perl
        ];
        buildInputs = [
          boringssl
        ];
        BORINGSSL_LIB_DIR = "${boringssl}/lib";
        RUSTFLAGS = "-C link-arg=-lstdc++";
        dontUseNinjaBuild = true;
        dontUseNinjaInstall = true;
        doCheck = false;
        postPatch = ''
          cp ${./bench/tquic-perf/Cargo.lock} Cargo.lock
          substituteInPlace tools/Cargo.toml --replace-fail 'tquic = { path = "..", version = "1.5.0"}' 'tquic = { path = "..", version = "1.6.0"}'
          cp "$perfSource" tools/src/bin/tquic-perf.rs
        '';
        cargoBuildFlags = [
          "--bin"
          "tquic-perf"
        ];
        postInstall = ''
          mkdir -p $out/bin
        '';
      };
      xquicSrc = pkgs.fetchFromGitHub {
        owner = "alibaba";
        repo = "xquic";
        rev = "e5f7fe9555f6dfb87581deddd24e86fb86dfe2de";
        hash = "sha256-kwxqmxAs43bmiVVclv/T0z6sMSFJT4sY3iorX/qxA0U=";
      };
      xquicPerfClient = pkgs.stdenv.mkDerivation {
        pname = "xquic-perf-client";
        version = "dev";
        src = xquicSrc;
        perfSource = ./bench/xquic-perf/xquic-perf.c;
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.pkg-config
        ];
        buildInputs = [
          boringssl
        ];
        CFLAGS = "-Wno-error=dangling-pointer";
        cmakeFlags = [
          "-DSSL_TYPE=boringssl"
          "-DSSL_PATH=${boringssl.dev}"
          "-DSSL_INC_PATH=${boringssl.dev}/include"
          "-DSSL_LIB_PATH=${boringssl.out}/lib/libssl.a;${boringssl.out}/lib/libcrypto.a"
          "-DXQC_ENABLE_RENO=ON"
          "-DXQC_ENABLE_COPA=ON"
        ];
        buildPhase = ''
          runHook preBuild
          cmake --build . --target xquic-static
          $CXX -O3 -std=gnu++17 -x c "$perfSource" -x none \
            -I$src/include \
            -o xquic-perf \
            libxquic-static.a \
            ${boringssl.out}/lib/libssl.a \
            ${boringssl.out}/lib/libcrypto.a \
            -ldl -lpthread -lm
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin
          cp xquic-perf $out/bin/xquic-perf
          runHook postInstall
        '';
      };
      picotlsSrc = pkgs.fetchFromGitHub {
        owner = "h2o";
        repo = "picotls";
        rev = "bfa67875982afc4c24f21e146cef4747fa189c2f";
        fetchSubmodules = true;
        hash = "sha256-67U2C33ROWgEW9poAA3GtiKvoamBWfGmKiT7wpP5BJM=";
      };
      picoquicSrc = pkgs.fetchFromGitHub {
        owner = "private-octopus";
        repo = "picoquic";
        rev = "d4c442531c7696ce9fcdf5eafa58ff21869b8589";
        hash = "sha256-XqPH0Dx65G+vAzuj19K+PyDj1c0fwDAO/DsBOmUjLZY=";
      };
      picotlsPackage = pkgs.stdenv.mkDerivation {
        pname = "picotls-for-picoquic";
        version = "dev";
        src = picotlsSrc;
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.ninja
          pkgs.pkg-config
        ];
        buildInputs = [
          pkgs.openssl
        ];
        cmakeFlags = [
          "-DWITH_FUSION=OFF"
          "-DWITH_DTRACE=OFF"
        ];
        buildPhase = ''
          runHook preBuild
          cmake --build . --target picotls-core picotls-minicrypto picotls-openssl
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          mkdir -p $out/lib $out/include
          cp libpicotls-core.a libpicotls-minicrypto.a libpicotls-openssl.a $out/lib/
          cp -R $src/include/. $out/include/
          runHook postInstall
        '';
      };
      picoquicPerfClient = pkgs.stdenv.mkDerivation {
        pname = "picoquic-perf-client";
        version = "dev";
        src = picoquicSrc;
        perfSource = ./bench/picoquic-perf/picoquic-perf.c;
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.ninja
          pkgs.pkg-config
        ];
        buildInputs = [
          pkgs.openssl
          picotlsPackage
        ];
        cmakeFlags = [
          "-Dpicoquic_BUILD_TESTS=OFF"
          "-DBUILD_PICO_SIM=OFF"
          "-DBUILD_DEMO=OFF"
          "-DBUILD_PQBENCH=OFF"
          "-DBUILD_LOGREADER=OFF"
          "-DBUILD_LOGLIB=ON"
          "-DBUILD_HTTP=OFF"
          "-DPICOQUIC_FETCH_PTLS=OFF"
          "-DPTLS_CORE_LIBRARY=${picotlsPackage}/lib/libpicotls-core.a"
          "-DPTLS_OPENSSL_LIBRARY=${picotlsPackage}/lib/libpicotls-openssl.a"
          "-DPTLS_MINICRYPTO_LIBRARY=${picotlsPackage}/lib/libpicotls-minicrypto.a"
          "-DPTLS_INCLUDE_DIR=${picotlsPackage}/include"
        ];
        buildPhase = ''
          runHook preBuild
          cmake --build . --target picoquic-core picoquic-log
          $CC -O3 -std=c11 -Wall -Wextra \
            -I$src/picoquic -I$src/loglib \
            "$perfSource" \
            -o picoquic-perf \
            -Wl,--start-group libpicoquic-core.a libpicoquic-log.a -Wl,--end-group \
            ${picotlsPackage}/lib/libpicotls-openssl.a \
            ${picotlsPackage}/lib/libpicotls-minicrypto.a \
            ${picotlsPackage}/lib/libpicotls-core.a \
            -lssl -lcrypto -lpthread
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin
          cp picoquic-perf $out/bin/picoquic-perf
          runHook postInstall
        '';
      };
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
            coquicPackage = quictlsMuslPerfPackage;
            inherit quicgoPerfClient;
            inherit quinnPerfClient;
            inherit coquicRustPerfClient;
            inherit coquicPythonPerfClient;
            inherit picoquicPerfClient;
            inherit msquicPerfClient;
            inherit quichePerfClient;
            inherit quiclyPerfClient;
            inherit googleQuichePerfClient;
            inherit tquicPerfClient;
            inherit mvfstPerfClient;
            inherit s2nQuicPerfClient;
            inherit xquicPerfClient;
            inherit aioquicPerfClient;
            inherit ngtcp2PerfClient;
            inherit lsquicPerfClient;
            inherit neqoPerfClient;
          })
        ];
        config = {
          Entrypoint = [ "/usr/local/bin/coquic-perf" ];
          WorkingDir = "/";
        };
      };
      mkQuictlsMuslPerfImage =
        name: perfClients:
        pkgs.dockerTools.buildLayeredImage {
          inherit name;
          tag = "quictls-musl";
          fromImage = simulatorEndpointBase;
          contents = [
            (mkPerfEndpointOverlay (
              {
                name = "${name}-quictls-musl";
                coquicPackage = quictlsMuslPerfPackage;
              }
              // perfClients
            ))
          ];
          config = {
            Entrypoint = [ "/usr/local/bin/coquic-perf" ];
            WorkingDir = "/";
          };
      };
      quictlsMuslCoquicPerfImage = mkQuictlsMuslPerfImage "coquic-perf-coquic" { };
      boringsslMuslCoquicRustPerfImage = pkgs.dockerTools.buildLayeredImage {
        name = "coquic-perf-coquic-rust";
        tag = "boringssl-musl";
        fromImage = simulatorEndpointBase;
        contents = [
          (mkPerfEndpointOverlay {
            name = "coquic-perf-coquic-rust-boringssl-musl";
            coquicPackage = boringsslMuslPerfPackage;
            inherit coquicRustPerfClient;
          })
        ];
        config = {
          Entrypoint = [ "/usr/local/bin/coquic-rust-perf" ];
          WorkingDir = "/";
        };
      };
      boringsslMuslCoquicPythonPerfImage = pkgs.dockerTools.buildLayeredImage {
        name = "coquic-perf-coquic-python";
        tag = "boringssl-musl";
        fromImage = simulatorEndpointBase;
        contents = [
          (mkPerfEndpointOverlay {
            name = "coquic-perf-coquic-python-boringssl-musl";
            coquicPackage = boringsslMuslPerfPackage;
            inherit coquicPythonPerfClient;
          })
        ];
        config = {
          Entrypoint = [ "/usr/local/bin/coquic-python-perf" ];
          WorkingDir = "/";
        };
      };
      boringsslMuslCoquicGoPerfImage = pkgs.dockerTools.buildLayeredImage {
        name = "coquic-perf-coquic-go";
        tag = "boringssl-musl";
        fromImage = simulatorEndpointBase;
        contents = [
          (mkPerfEndpointOverlay {
            name = "coquic-perf-coquic-go-boringssl-musl";
            coquicPackage = boringsslMuslPerfPackage;
            inherit coquicGoPerfClient;
          })
        ];
        config = {
          Entrypoint = [ "/usr/local/bin/coquic-go-perf" ];
          WorkingDir = "/";
        };
      };
      boringsslMuslCoquicPerfImage = pkgs.dockerTools.buildLayeredImage {
        name = "coquic-perf-coquic";
        tag = "boringssl-musl";
        fromImage = simulatorEndpointBase;
        contents = [
          (mkPerfEndpointOverlay {
            name = "coquic-perf-coquic-boringssl-musl";
            coquicPackage = boringsslMuslPerfPackage;
          })
        ];
        config = {
          Entrypoint = [ "/usr/local/bin/coquic-perf" ];
          WorkingDir = "/";
        };
      };
      boringsslMuslCoquicProfileImage = pkgs.dockerTools.buildLayeredImage {
        name = "coquic-perf-coquic-profile";
        tag = "boringssl-musl";
        fromImage = simulatorEndpointBase;
        contents = [
          (mkPerfEndpointOverlay {
            name = "coquic-perf-coquic-profile-boringssl-musl";
            coquicPackage = boringsslMuslProfileHooksPackage;
          })
        ];
        config = {
          Entrypoint = [ "/usr/local/bin/coquic-perf" ];
          WorkingDir = "/";
        };
      };
      quictlsMuslQuicgoPerfImage = mkQuictlsMuslPerfImage "coquic-perf-quic-go" { inherit quicgoPerfClient; };
      quictlsMuslQuinnPerfImage = mkQuictlsMuslPerfImage "coquic-perf-quinn" { inherit quinnPerfClient; };
      quictlsMuslPicoquicPerfImage = mkQuictlsMuslPerfImage "coquic-perf-picoquic" { inherit picoquicPerfClient; };
      quictlsMuslMsquicPerfImage = mkQuictlsMuslPerfImage "coquic-perf-msquic" { inherit msquicPerfClient; };
      quictlsMuslQuichePerfImage = mkQuictlsMuslPerfImage "coquic-perf-quiche" { inherit quichePerfClient; };
      quictlsMuslQuiclyPerfImage = mkQuictlsMuslPerfImage "coquic-perf-quicly" { inherit quiclyPerfClient; };
      quictlsMuslGoogleQuichePerfImage = mkQuictlsMuslPerfImage "coquic-perf-google-quiche" { inherit googleQuichePerfClient; };
      quictlsMuslTquicPerfImage = mkQuictlsMuslPerfImage "coquic-perf-tquic" { inherit tquicPerfClient; };
      quictlsMuslMvfstPerfImage = mkQuictlsMuslPerfImage "coquic-perf-mvfst" { inherit mvfstPerfClient; };
      quictlsMuslS2nQuicPerfImage = mkQuictlsMuslPerfImage "coquic-perf-s2n-quic" { inherit s2nQuicPerfClient; };
      quictlsMuslXquicPerfImage = mkQuictlsMuslPerfImage "coquic-perf-xquic" { inherit xquicPerfClient; };
      quictlsMuslAioquicPerfImage = mkQuictlsMuslPerfImage "coquic-perf-aioquic" { inherit aioquicPerfClient; };
      quictlsMuslNgtcp2PerfImage = mkQuictlsMuslPerfImage "coquic-perf-ngtcp2" { inherit ngtcp2PerfClient; };
      quictlsMuslLsquicPerfImage = mkQuictlsMuslPerfImage "coquic-perf-lsquic" { inherit lsquicPerfClient; };
      quictlsMuslNeqoPerfImage = mkQuictlsMuslPerfImage "coquic-perf-neqo" { inherit neqoPerfClient; };
      quictlsMuslPerfImageStream = pkgs.dockerTools.streamLayeredImage {
        name = "coquic-perf";
        tag = "quictls-musl";
        fromImage = simulatorEndpointBase;
        contents = [
          (mkPerfEndpointOverlay {
            name = "coquic-perf-quictls-musl";
            coquicPackage = quictlsMuslPackage;
            inherit quicgoPerfClient;
            inherit quinnPerfClient;
            inherit coquicRustPerfClient;
            inherit picoquicPerfClient;
            inherit msquicPerfClient;
            inherit quichePerfClient;
            inherit quiclyPerfClient;
            inherit googleQuichePerfClient;
            inherit tquicPerfClient;
            inherit mvfstPerfClient;
            inherit s2nQuicPerfClient;
            inherit xquicPerfClient;
            inherit aioquicPerfClient;
            inherit ngtcp2PerfClient;
            inherit lsquicPerfClient;
            inherit neqoPerfClient;
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
          pkgs.uv
          pkgs.qdrant
          pkgs.wireshark
        ];
      };
      lintShell = mkCoquicShell {
        profile = quictlsProfile;
        banner = "coquic lint shell ready. Run: pre-commit run coquic-clang-tidy";
        extraPackages =
          [
            llvmPkgs.clang
            llvmPkgs.clang-tools
            pkgs.git
            pkgs.pre-commit
            pkgs.python3
          ]
          ++ pre-commit-check.enabledPackages;
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
            if [ -f "$search_dir/build.zig" ]; then
              exec "$search_dir/rag/scripts/qdrant-dev" "$@"
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
        curl-http3 = pkgs.curl;
        interop-image-quictls-musl = quictlsMuslImage;
        interop-image-boringssl-musl = boringsslMuslImage;
        perf-image-quictls-musl = quictlsMuslPerfImage;
        perf-image-stream-quictls-musl = quictlsMuslPerfImageStream;
        perf-image-coquic-quictls-musl = quictlsMuslCoquicPerfImage;
        perf-image-coquic-boringssl-musl = boringsslMuslCoquicPerfImage;
        perf-image-coquic-rust-boringssl-musl = boringsslMuslCoquicRustPerfImage;
        perf-image-coquic-python-boringssl-musl = boringsslMuslCoquicPythonPerfImage;
        perf-image-coquic-go-boringssl-musl = boringsslMuslCoquicGoPerfImage;
        perf-image-coquic-profile-boringssl-musl = boringsslMuslCoquicProfileImage;
        perf-image-quic-go-quictls-musl = quictlsMuslQuicgoPerfImage;
        perf-image-quinn-quictls-musl = quictlsMuslQuinnPerfImage;
        perf-image-picoquic-quictls-musl = quictlsMuslPicoquicPerfImage;
        perf-image-msquic-quictls-musl = quictlsMuslMsquicPerfImage;
        perf-image-quiche-quictls-musl = quictlsMuslQuichePerfImage;
        perf-image-quicly-quictls-musl = quictlsMuslQuiclyPerfImage;
        perf-image-google-quiche-quictls-musl = quictlsMuslGoogleQuichePerfImage;
        perf-image-tquic-quictls-musl = quictlsMuslTquicPerfImage;
        perf-image-mvfst-quictls-musl = quictlsMuslMvfstPerfImage;
        perf-image-s2n-quic-quictls-musl = quictlsMuslS2nQuicPerfImage;
        perf-image-xquic-quictls-musl = quictlsMuslXquicPerfImage;
        perf-image-aioquic-quictls-musl = quictlsMuslAioquicPerfImage;
        perf-image-ngtcp2-quictls-musl = quictlsMuslNgtcp2PerfImage;
        perf-image-lsquic-quictls-musl = quictlsMuslLsquicPerfImage;
        perf-image-neqo-quictls-musl = quictlsMuslNeqoPerfImage;
        quicgo-perf-client = quicgoPerfClient;
        coquic-rust-perf-client = coquicRustPerfClient;
        coquic-python-perf-client = coquicPythonPerfClient;
        coquic-go-perf-client = coquicGoPerfClient;
        quinn-perf-client = quinnPerfClient;
        picoquic-perf-client = picoquicPerfClient;
        msquic-perf-client = msquicPerfClient;
        quiche-perf-client = quichePerfClient;
        quicly-perf-client = quiclyPerfClient;
        google-quiche-perf-client = googleQuichePerfClient;
        tquic-perf-client = tquicPerfClient;
        mvfst-perf-client = mvfstPerfClient;
        s2n-quic-perf-client = s2nQuicPerfClient;
        xquic-perf-client = xquicPerfClient;
        aioquic-perf-client = aioquicPerfClient;
        ngtcp2-perf-client = ngtcp2PerfClient;
        lsquic-perf-client = lsquicPerfClient;
        neqo-perf-client = neqoPerfClient;
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
          program = "${pkgs.curl}/bin/curl";
        };
      };

      devShells.${system} = {
        default = defaultShell;
        quictls = quictlsShell;
        quictls-musl = quictlsMuslShell;
        interop-image = quictlsMuslShell;
        boringssl = boringsslShell;
        boringssl-musl = boringsslMuslShell;
        lint = lintShell;
      };
    };
}
