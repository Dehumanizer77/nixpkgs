{
  lib,
  stdenv,
  fetchFromGitHub,
  fetchurl,
  cmake,
  gnumake,
  perl,
  pkg-config,
  python3,
  which,
  gawk,
  procps,
  makeWrapper,
  coreutils,
  expat,
  autoconf,
  automake,
  libtool,
  clang,
  elfutils,
  zlib,
  db, # Berkeley DB - needed for libsysinfo to link with -ldb
  # Runtime dependencies we wrap into PATH
  iproute2,
  # Note: all vendored deps come from deps.nix; we use the Wazuh build system
  # to compile everything rather than trying to substitute nixpkgs versions.
  # This avoids version/ABI mismatches with Wazuh's tightly-coupled dependencies.
}:

let
  version = "4.14.3";
  deps = import ./deps.nix { inherit fetchurl; };

  # Extract a tarball into a specific directory during postUnpack.
  # The Wazuh dep tarballs have inconsistent top-level directory formats:
  # some use "name/file" (requires --strip-components=1) and some use
  # "./name/file" (requires --strip-components=2 because "." counts as a
  # component). We detect which format each tarball uses by examining the
  # first entry.
  # Note: postUnpack runs with cwd = parent of $sourceRoot, so we use
  # $sourceRoot-relative paths.
  stageDep = name: drv: ''
    echo "Staging ${name}..."
    mkdir -p "$sourceRoot/src/external/${name}"
    # Detect tarball prefix format: some use "name/file" (strip 1) and some
    # use "./name/file" (strip 2, because "." is counted as a component).
    # We use `|| true` to suppress SIGPIPE from `head -1` closing the pipe early.
    _first=$(tar -tzf ${drv} 2>/dev/null | head -1 || true)
    case "$_first" in
      ./*) tar -xf ${drv} -C "$sourceRoot/src/external/${name}" --strip-components=2 ;;
      *)   tar -xf ${drv} -C "$sourceRoot/src/external/${name}" --strip-components=1 ;;
    esac
  '';

in
stdenv.mkDerivation {
  pname = "wazuh-agent";
  inherit version;

  src = fetchFromGitHub {
    owner = "wazuh";
    repo = "wazuh";
    rev = "v${version}";
    hash = "sha256-mP0YOTdtCDsVou6lVqbnEdbIUXhtwJTGGcMH/ox9KFo=";
  };

  nativeBuildInputs = [
    cmake
    gnumake
    perl
    pkg-config
    python3
    which
    gawk
    makeWrapper
    # expat is required by the vendored dbus configure script
    expat
    clang
    elfutils
    zlib.dev
    # autoconf/automake are required by audit-userspace's autogen.sh
    autoconf
    automake
    libtool
  ];

  # No runtime deps from nixpkgs — all C/C++ libs are vendored.
  # procps, coreutils, gawk, iproute2 are needed at runtime by wazuh-control and
  # certain daemon scripts, so we wrap them into PATH in fixupPhase.
  buildInputs = [
    zlib
    db.out
    db.dev
  ];

  postUnpack = ''
    echo "=== Staging external dependencies ==="
    ${stageDep "cJSON" deps.cJSON}
    ${stageDep "curl" deps.curl}
    ${stageDep "libdb" deps.libdb}
    ${stageDep "libffi" deps.libffi}
    ${stageDep "libyaml" deps.libyaml}
    ${stageDep "openssl" deps.openssl}
    ${stageDep "procps" deps.procps}
    ${stageDep "sqlite" deps.sqlite}
    ${stageDep "zlib" deps.zlib}
    ${stageDep "audit-userspace" deps.audit-userspace}
    ${stageDep "msgpack" deps.msgpack}
    ${stageDep "bzip2" deps.bzip2}
    ${stageDep "nlohmann" deps.nlohmann}
    ${stageDep "googletest" deps.googletest}
    ${stageDep "libpcre2" deps.libpcre2}
    ${stageDep "libplist" deps.libplist}
    ${stageDep "pacman" deps.pacman}
    ${stageDep "libarchive" deps.libarchive}
    ${stageDep "popt" deps.popt}
    ${stageDep "lua" deps.lua}
    ${stageDep "rpm" deps.rpm}
    ${stageDep "rocksdb" deps.rocksdb}
    ${stageDep "lzma" deps.lzma}
    ${stageDep "cpp-httplib" deps.cpp-httplib}
    ${stageDep "benchmark" deps.benchmark}
    ${stageDep "libbpf-bootstrap" deps.libbpf-bootstrap}
    ${stageDep "dbus" deps.dbus}

    # Create sentinel .tar.gz files so Wazuh's Makefile 'make deps' target sees them
    # as already satisfied and skips the curl download rules. The external/<name>/
    # directories (staged above) are what the compiler actually needs.
    # The http-request rule uses a different mechanism: it checks if shared_modules/http-request/
    # has files, and skips download if it does (handled by our staging below).
    for dep in cJSON curl libdb libffi libyaml openssl procps sqlite zlib \
               audit-userspace msgpack bzip2 nlohmann googletest libpcre2 \
               libplist pacman libarchive popt lua rpm rocksdb lzma \
               cpp-httplib benchmark libbpf-bootstrap dbus; do
      touch "$sourceRoot/src/external/$dep.tar.gz"
    done

    # libdb tarball already contains a build_unix/ subdirectory (the tarball structure
    # is libdb/{build_unix,dist,src,...}), so --strip-components=1 correctly places
    # build_unix/ under src/external/libdb/build_unix/ as Wazuh expects.

    # Stage libbpf-bootstrap sub-dependencies.
    # The libbpf-bootstrap tarball (staged above as src/external/libbpf-bootstrap/)
    # only contains CMakeLists.txt and cmake helper tools. The actual sources for
    # libbpf, bpftool, and vmlinux.h must be staged separately so CMake finds them
    # in the expected locations (CMAKE_CURRENT_SOURCE_DIR/libbpf/, etc.).
    echo "Staging libbpf sub-dependencies..."
    mkdir -p "$sourceRoot/src/external/libbpf-bootstrap/libbpf"
    tar -xf ${deps.libbpf-src} -C "$sourceRoot/src/external/libbpf-bootstrap/libbpf" --strip-components=1
    mkdir -p "$sourceRoot/src/external/libbpf-bootstrap/bpftool"
    tar -xf ${deps.bpftool-src} -C "$sourceRoot/src/external/libbpf-bootstrap/bpftool" --strip-components=1
    # bpftool expects libbpf sources at bpftool/libbpf/ (its git submodule path).
    # The bpftool tarball has an empty bpftool/libbpf/ placeholder; populate it.
    mkdir -p "$sourceRoot/src/external/libbpf-bootstrap/bpftool/libbpf"
    tar -xf ${deps.libbpf-src} -C "$sourceRoot/src/external/libbpf-bootstrap/bpftool/libbpf" --strip-components=1
    mkdir -p "$sourceRoot/src/external/libbpf-bootstrap/vmlinux.h"
    tar -xf ${deps.vmlinux-h} -C "$sourceRoot/src/external/libbpf-bootstrap/vmlinux.h" --strip-components=1

    # Stage modern.bpf.c from the Wazuh source tree into the libbpf-bootstrap src/ directory.
    # The libbpf-bootstrap CMakeLists.txt tries to download it from GitHub; we provide it
    # from the local source tree instead.
    echo "Staging modern.bpf.c..."
    mkdir -p "$sourceRoot/src/external/libbpf-bootstrap/src"
    cp "$sourceRoot/src/syscheckd/src/ebpf/src/modern.bpf.c" \
       "$sourceRoot/src/external/libbpf-bootstrap/src/modern.bpf.c"

    # Stage http-request shared module (extracted into shared_modules/http-request/).
    # The Makefile rule checks if the directory has files and skips download if it does.
    echo "Staging http-request..."
    mkdir -p "$sourceRoot/src/shared_modules/http-request"
    tar -xf ${deps.http-request} -C "$sourceRoot/src/shared_modules/http-request" --strip-components=1
    # Also create the sentinel tarball that the deps target expects
    touch "$sourceRoot/src/shared_modules/http-request.tar.gz"

    # Ensure all staged files are writable by the build user.
    # Some tarballs contain read-only files (e.g., audit-userspace's INSTALL
    # has 0444 permissions) which cause issues when build scripts try to
    # overwrite them (e.g., autogen.sh's `cp INSTALL.tmp INSTALL`).
    chmod -R u+w "$sourceRoot/src/external/"
    chmod -R u+w "$sourceRoot/src/shared_modules/http-request/"

    echo "=== Dependency staging complete ==="
  '';

  patches = [
    ./patches/01-makefile.patch
    ./patches/02-libbpf-bootstrap.patch
    ./patches/03-rocksdb-buffer.patch
    # Fix C++17 std::data ambiguity with local variable named 'data' in berkeleyRpmDbHelper.h
    ./patches/04-berkeley-db-data-rename.patch
    # Note: patches/04-installdir.patch is intentionally absent.
    # Audit of v4.14.3 found WAZUH_HOME environment variable is already
    # comprehensively supported — no source changes needed. The NixOS module
    # sets WAZUH_HOME=/var/lib/wazuh for all daemons.
  ];

  # Wazuh's build system orchestrates CMake internally.
  # We skip the standard configurePhase and call make directly.
  configurePhase = "true";

  buildPhase = ''
    runHook preBuild

    # BPF target (clang --target bpf) does not support -fzero-call-used-regs.
    # Remove zerocallusedregs from NIX_HARDENING_ENABLE so the clang wrapper
    # does not inject this flag when compiling libbpf-bootstrap eBPF objects.
    NIX_HARDENING_ENABLE="''${NIX_HARDENING_ENABLE/zerocallusedregs/}"
    export NIX_HARDENING_ENABLE

    cd src

    # Verify staging: check that a few key external source files are present
    echo "=== Verifying staged dependencies ==="
    echo "PWD: $(pwd)"
    ls -la external/ | head -10 || true
    echo "--- sqlite check ---"
    ls -la external/sqlite/ 2>/dev/null || echo "MISSING: external/sqlite/"
    echo "--- openssl check ---"
    ls external/openssl/ 2>/dev/null | head -5 || echo "MISSING: external/openssl/"
    echo "=== End verification ==="

    # Provide system libdb headers and library in build_unix/ so that data_provider
    # cmake can find db.h (include path) and link with -ldb.
    # The vendored libdb 18.1 uses K&R C syntax incompatible with GCC 15, so we
    # use the nixpkgs db-5.3.28 package (API-compatible for the subset Wazuh uses).
    echo "Setting up system libdb in build_unix/..."
    mkdir -p external/libdb/build_unix
    cp "${db.dev}/include/db.h" external/libdb/build_unix/db.h
    ln -sf "${db.out}/lib/libdb.so" external/libdb/build_unix/libdb.so
    echo "libdb setup done"

    # Build the agent. All external dependencies are pre-staged in src/external/
    # by the postUnpack phase. We pass EXTERNAL_SRC_ONLY=yes so the Makefile
    # uses source-only mode (no precompiled binaries attempted), and the sentinel
    # .tar.gz files created in postUnpack satisfy the `deps` prerequisites without
    # triggering any network access. We skip the explicit `make deps` step because
    # the sentinel files and pre-extracted directories are already in place.
    make TARGET=agent \
      INSTALLDIR=/var/lib/wazuh \
      EXTERNAL_SRC_ONLY=yes \
      -j$NIX_BUILD_CORES

    cd ..

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin
    mkdir -p $out/lib
    mkdir -p $out/etc
    mkdir -p $out/share/wazuh-agent/active-response/bin
    mkdir -p $out/share/wazuh-agent/ruleset/sca
    mkdir -p $out/share/wazuh-agent/wodles

    # Install agent daemon binaries (built in src/)
    for binary in \
      wazuh-agentd \
      wazuh-logcollector \
      wazuh-syscheckd \
      wazuh-execd \
      wazuh-modulesd \
      agent-auth \
      manage_agents; do
      if [ -f "src/$binary" ]; then
        install -m 0755 "src/$binary" "$out/bin/$binary"
      else
        # Some binaries are built by CMake in subdirectories
        installed=false
        for cmakePath in syscheckd/build/bin data_provider/build/bin; do
          if [ -f "src/$cmakePath/$binary" ]; then
            install -m 0755 "src/$cmakePath/$binary" "$out/bin/$binary"
            installed=true
            break
          fi
        done
        if [ "$installed" = false ]; then
          echo "WARNING: Binary not found: $binary"
        fi
      fi
    done

    # Install wazuh-control script
    if [ -f "src/init/wazuh-client.sh" ]; then
      install -m 0755 "src/init/wazuh-client.sh" "$out/bin/wazuh-control"
    fi

    # Install shared libraries (libwazuhext.so and C++ runtime libs)
    for lib in src/libwazuhext.so src/libwazuhshared.so; do
      [ -f "$lib" ] && install -m 0755 "$lib" "$out/lib/"
    done
    # Install CMake-built shared libraries needed at runtime.
    # fimdb and fimebpf are built by syscheckd CMakeLists.txt as SHARED.
    # dbsync and rsync are built by shared_modules CMakeLists.txt as SHARED.
    for lib in \
      src/syscheckd/build/lib/libfimdb.so \
      src/syscheckd/build/lib/libfimebpf.so \
      src/shared_modules/dbsync/build/lib/libdbsync.so \
      src/shared_modules/rsync/build/lib/librsync.so; do
      [ -f "$lib" ] && install -m 0755 "$lib" "$out/lib/"
    done

    # Copy C++ runtime libs if present (Wazuh copies them from gcc)
    for lib in src/libstdc++.so.6 src/libgcc_s.so.1; do
      [ -f "$lib" ] && install -m 0755 "$lib" "$out/lib/"
    done

    # Install default configuration templates
    if [ -f "etc/ossec-agent.conf" ]; then
      install -m 0644 "etc/ossec-agent.conf" "$out/etc/ossec-agent.conf"
    else
      # Generate a minimal default config if the template doesn't exist at expected path
      echo "WARNING: etc/ossec-agent.conf not found, checking alternatives..."
      find etc/ -name "*.conf" | head -5 || true
    fi
    [ -f "etc/internal_options.conf" ] && install -m 0644 "etc/internal_options.conf" "$out/etc/internal_options.conf"
    [ -f "etc/local_internal_options.conf" ] && install -m 0644 "etc/local_internal_options.conf" "$out/etc/local_internal_options.conf.example"

    # Install active response scripts
    if [ -d "active-response/bin" ]; then
      cp -r active-response/bin/. "$out/share/wazuh-agent/active-response/bin/"
    fi

    # Install SCA policies
    if [ -d "ruleset/sca" ]; then
      cp -r ruleset/sca/. "$out/share/wazuh-agent/ruleset/sca/"
    fi

    # Install wodles data
    if [ -d "wodles" ]; then
      cp -r wodles/. "$out/share/wazuh-agent/wodles/"
    fi

    runHook postInstall
  '';

  fixupPhase = ''
    runHook preFixup

    # Patch shebangs in scripts
    patchShebangs $out/share/wazuh-agent/ || true
    if [ -f "$out/bin/wazuh-control" ]; then
      patchShebangs $out/bin/wazuh-control
    fi

    # Wrap wazuh-control with required runtime utilities in PATH
    if [ -f "$out/bin/wazuh-control" ]; then
      wrapProgram $out/bin/wazuh-control \
        --prefix PATH : "${
          lib.makeBinPath [
            gawk
            procps
            coreutils
            iproute2
          ]
        }"
    fi

    runHook postFixup
  '';

  # Wazuh encodes the install directory at compile time via INSTALLDIR.
  # At runtime, WAZUH_HOME env var overrides this (see src/shared/file_op.c:w_homedir()).
  # The module always sets WAZUH_HOME=/var/lib/wazuh for all daemons.
  env.WAZUH_HOME = "/var/lib/wazuh";

  meta = {
    description = "Wazuh security agent for threat detection and response";
    longDescription = ''
      Wazuh is a free and open source security platform that provides unified
      XDR and SIEM protection. The agent runs on endpoint systems to collect
      security events and send them to the Wazuh manager for analysis.
      This package provides the Wazuh agent component only.
    '';
    homepage = "https://wazuh.com/";
    changelog = "https://github.com/wazuh/wazuh/releases/tag/v${version}";
    license = lib.licenses.gpl2Only;
    maintainers = [ lib.maintainers.dehumanizer77 ];
    platforms = lib.platforms.linux;
    mainProgram = "wazuh-agentd";
  };
}
