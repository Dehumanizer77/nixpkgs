# External dependency source tarballs for Wazuh agent v4.14.3
#
# These are the vendored C/C++ dependencies that Wazuh's Makefile
# downloads during `make deps`. We pre-fetch them here as fixed-output
# derivations so the build can run in the Nix sandbox without network access.
#
# DEPS_VERSION = 49 (from src/Makefile: DEPS_VERSION = 49)
# Base URL: https://packages.wazuh.com/deps/49/libraries/sources/
#
# Hashes are SHA256 of the raw downloaded tarball (not unpacked),
# as required by fetchurl's `hash` attribute.
#
{ fetchurl }:
let
  depsVersion = "49";
  baseUrl = "https://packages.wazuh.com/deps/${depsVersion}/libraries/sources";
  dep =
    name: hash:
    fetchurl {
      url = "${baseUrl}/${name}.tar.gz";
      inherit hash;
    };
in
{
  # JSON library — small, Wazuh may patch, keep vendored
  cJSON = dep "cJSON" "sha256-2oCfcLfQOsUprmIj1DkL+ibNKfjDLI6LO2Me+hZniS0=";

  # Berkeley DB — specific version required, complex build
  libdb = dep "libdb" "sha256-fpxE6Mf9sYb/UhqNCFsb+mNNNC3Md37Oofv5qYq13F4=";

  # MessagePack — custom build integration, specific version
  msgpack = dep "msgpack" "sha256-BtY7zzKJbNCvVIDEARNLGtHBZv2E6+W0hueSEB7oVOI=";

  # nlohmann JSON — header-only, version-specific
  nlohmann = dep "nlohmann" "sha256-zvsHk209W/3T78Xpu408gH1oEnO9rC6Ds9Z67y0RWMQ=";

  # Google Test — build-only, version-specific
  googletest = dep "googletest" "sha256-jB6KCn8iHCEl6Z5qy3CdorpHJHa00FfFjeUEvr841Bc=";

  # Google Benchmark — build-only, version-specific
  benchmark = dep "benchmark" "sha256-lMV6oMsr142+nnfTMsvGRNrw/s3JoJYyBIvm4J+c7Ws=";

  # PCRE2 — Wazuh builds with specific flags (--enable-jit=no), keep vendored
  libpcre2 = dep "libpcre2" "sha256-WoDWVNfRSz25+jpJ179EpJhoO0Z4SojOxRSosZR2e5I=";

  # libplist — custom build, less common in nixpkgs
  libplist = dep "libplist" "sha256-iCeNS9/BvWo6GlWk89kzaD0nMroJz3p0n+jsjuxAbjw=";

  # pacman (libalpm) — build integration complexity
  pacman = dep "pacman" "sha256-Yxq+Bl7JgttWv+wFzzfDOo9on9f0Fkw5J3KEvXoNDjE=";

  # libarchive — Wazuh builds without several features, keep vendored
  libarchive = dep "libarchive" "sha256-VA/0pV3vp1d4osQFZ6gwZIzlNnuK6hIzZodNlrc074A=";

  # popt — small, may be patched
  popt = dep "popt" "sha256-1ogKBmIsoy3EqjmtXc977y+qgb2TGvvmS6Q0rY/uHao=";

  # Lua — embedded, potentially patched
  lua = dep "lua" "sha256-Iz6H6HEJC9MMS2kqxzvXFDYcFQURSOTu7IKKHfhDbso=";

  # RPM — build integration complexity
  rpm = dep "rpm" "sha256-kNhy9U6rzzdzbZCsF6jTEwEtqE5oWxn9Lav0oBKVcpA=";

  # RocksDB — Wazuh patches (buffer fix), specific version required
  rocksdb = dep "rocksdb" "sha256-7u1go9Tin3MF55+fXOvUJhF0JhIn8bWn0F2lVWVnVDY=";

  # procps — used for agent monitoring internals
  procps = dep "procps" "sha256-Ih85XinRvb5LrMnbOWAu7guuaFqTVDe+DX/rQuMZLQc=";

  # cpp-httplib — header-only, specific version
  cpp-httplib = dep "cpp-httplib" "sha256-ZRdXMmNhFoa5IZunlsNfVKMG6yfcPHLhgH8qCjTKweg=";

  # libbpf-bootstrap — complex build with sub-deps (libbpf, bpftool, vmlinux.h)
  # Requires patch 02 to disable network fetches
  libbpf-bootstrap = dep "libbpf-bootstrap" "sha256-hh74B1ePDobIfuXC2YdHaFPmQGm/xLsTon4jPtNXSDI=";

  # libbpf-bootstrap sub-dependencies
  # The libbpf-bootstrap tarball only contains CMakeLists.txt and helper tools.
  # The actual libbpf, bpftool, and vmlinux.h repos are pre-fetched here so
  # they can be staged before the build (cmake would otherwise clone them).
  libbpf-src = fetchurl {
    url = "https://github.com/libbpf/libbpf/archive/refs/tags/v1.5.0.tar.gz";
    hash = "sha256-U0kq/23Ufk2gTvXmctdTuXQ4SL2zjp2Q6vvhkLeYPEQ=";
  };
  bpftool-src = fetchurl {
    url = "https://github.com/libbpf/bpftool/archive/refs/tags/v7.5.0.tar.gz";
    hash = "sha256-oSb4ywb4h3Qc5FzU+CNYOucK68P2FcxO0qXuyGdqloE=";
  };
  vmlinux-h = fetchurl {
    url = "https://github.com/libbpf/vmlinux.h/archive/refs/heads/main.tar.gz";
    hash = "sha256-FiYFp2XHso9F72tuS006KjaS1TV2guyZyxQODoid5vA=";
  };

  # http-request — shared module, fetched from GitHub
  http-request = fetchurl {
    url = "https://github.com/wazuh/wazuh-http-request/tarball/cd50797cfe03c27f3759bdc243fecca6f7535d35";
    hash = "sha256-B3vGCrE0Vm4gcaa+70DwWAPNIGHCl+Ed1ImT07eI2aI=";
  };

  # openssl — keeping vendored; Wazuh builds with specific flags and links statically
  openssl = dep "openssl" "sha256-A4b+Ogv0i64spNF0KlPfmo/LG3NYO6Iuj4p936E3XNk=";

  # curl — keeping vendored; Wazuh links against its own openssl build
  curl = dep "curl" "sha256-MM9xQuQoJxjOsjfhe1y/da/NfJ84gKA5xe/qYtsJRwk=";

  # libffi — keeping vendored to avoid version mismatch during initial build
  libffi = dep "libffi" "sha256-DpcfZLrMIglOifA0u6B1tA7MLCwpAO7NeuhYFf1sn2k=";

  # libyaml — keeping vendored for initial build
  libyaml = dep "libyaml" "sha256-NdqtYIs3LVzgmfc4wPIb/MA9aSDZL0SDhsWE5mTxN2o=";

  # audit-userspace — keeping vendored; requires autogen and specific flags
  audit-userspace = dep "audit-userspace" "sha256-6Coy5e35OwVRYOFLyX9B3q05KHklhR3ICnY44tTTBDQ=";

  # dbus — keeping vendored; complex build system
  dbus = dep "dbus" "sha256-fGVKyaT2i1DzLWdJIsGP/nQdMoqX15RFdhj8OgekjTo=";

  # sqlite — keeping vendored; Wazuh may use specific pragmas
  sqlite = dep "sqlite" "sha256-qBv/MLtK/9GwakmD/4jvgntKuuoxkbOa/37bKNHd0AM=";

  # zlib — keeping vendored; used during static linking
  zlib = dep "zlib" "sha256-tZ04FJ8MKexU0nZmEevFpRoDK/lxfjmprwD7bLhTK4s=";

  # bzip2 — keeping vendored
  bzip2 = dep "bzip2" "sha256-J2iO4DFqZLOeURssIkBwytl8OUpfcR+dBV/BgJ2JW80=";

  # lzma — keeping vendored
  lzma = dep "lzma" "sha256-TODBktQQcrVnmvibtTHvtoXIJnpLfiAFmZFJrBcCgTQ=";
}
