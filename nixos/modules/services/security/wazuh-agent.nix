{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    mkPackageOption
    optionalString
    concatStringsSep
    naturalSort
    splitString
    ;

  cfg = config.services.wazuh-agent;
  pkg = cfg.package;
  stateDir = "/var/lib/wazuh";

  # Converts a Nix attribute set to Wazuh-compatible ossec.conf XML.
  generateOssecConf =
    settings: extraConfig:
    let
      isNull_ = v: v == null;

      # XML escape: & < > " '
      xmlEscape =
        s:
        let
          s1 = builtins.replaceStrings [ "&" ] [ "&amp;" ] s;
          s2 = builtins.replaceStrings [ "<" ] [ "&lt;" ] s1;
          s3 = builtins.replaceStrings [ ">" ] [ "&gt;" ] s2;
          s4 = builtins.replaceStrings [ "\"" ] [ "&quot;" ] s3;
          s5 = builtins.replaceStrings [ "'" ] [ "&apos;" ] s4;
        in
        s5;

      # Convert a scalar Nix value to an XML text string
      scalarToStr =
        v:
        if builtins.isBool v then
          (if v then "yes" else "no")
        else if builtins.isInt v || builtins.isFloat v then
          toString v
        else if builtins.isString v then
          xmlEscape v
        else
          xmlEscape (toString v);

      # Indent every non-empty line in `s` by `n` spaces
      indentStr =
        n: s:
        let
          pad = builtins.concatStringsSep "" (builtins.genList (_: " ") n);
          ls = splitString "\n" s;
          indented = map (l: if l == "" then "" else pad + l) ls;
        in
        concatStringsSep "\n" indented;

      # Render an attribute set body (children) — returns a string of XML lines
      renderAttrsBody =
        attrs:
        let
          keys = naturalSort (builtins.attrNames attrs);
          rendered = map (k: renderKV k attrs.${k}) keys;
          nonEmpty = builtins.filter (s: s != "") rendered;
        in
        concatStringsSep "\n" nonEmpty;

      # Render a wrapping XML element for an attribute set.
      # Special case: "wodle" uses name= as an XML attribute, not a child element.
      renderAttrsAsElement =
        key: attrs:
        if key == "wodle" then
          let
            wodleName = xmlEscape (attrs.name or "");
            innerAttrs = builtins.removeAttrs attrs [ "name" ];
            inner = renderAttrsBody innerAttrs;
          in
          if inner == "" then
            ''<wodle name="${wodleName}"/>''
          else
            "<wodle name=\"${wodleName}\">\n${indentStr 2 inner}\n</wodle>"
        else
          let
            inner = renderAttrsBody attrs;
          in
          if inner == "" then "<${key}/>" else "<${key}>\n${indentStr 2 inner}\n</${key}>";

      # Render a single key-value pair to an XML string
      renderKV =
        key: val:
        if isNull_ val then
          "" # skip nulls
        else if builtins.isBool val then
          "<${key}>${scalarToStr val}</${key}>"
        else if builtins.isInt val || builtins.isFloat val then
          "<${key}>${scalarToStr val}</${key}>"
        else if builtins.isString val then
          "<${key}>${scalarToStr val}</${key}>"
        else if builtins.isList val then
          # Each list element is emitted as a repeated <key> element
          let
            renderItem =
              item:
              if isNull_ item then
                ""
              else if builtins.isAttrs item then
                renderAttrsAsElement key item
              else
                "<${key}>${scalarToStr item}</${key}>";
            rendered = map renderItem val;
            nonEmpty = builtins.filter (s: s != "") rendered;
          in
          concatStringsSep "\n" nonEmpty
        else if builtins.isAttrs val then
          renderAttrsAsElement key val
        else
          "<${key}>${xmlEscape (toString val)}</${key}>";

      # Top-level rendering: each key in settings becomes a top-level XML block.
      # "wodle" and "localfile" are lists of attrsets, each becoming its own element.
      renderTopLevel =
        attrs:
        let
          keys = naturalSort (builtins.attrNames attrs);
          renderOne =
            k:
            let
              val = attrs.${k};
            in
            if isNull_ val then
              ""
            else if k == "wodle" then
              if builtins.isList val then
                let
                  items = builtins.filter (x: !isNull_ x) val;
                  rendered = map (w: renderAttrsAsElement "wodle" w) items;
                  nonEmpty = builtins.filter (s: s != "") rendered;
                in
                concatStringsSep "\n" nonEmpty
              else
                ""
            else if k == "localfile" then
              if builtins.isList val then
                let
                  items = builtins.filter (x: !isNull_ x) val;
                  rendered = map (lf: renderAttrsAsElement "localfile" lf) items;
                  nonEmpty = builtins.filter (s: s != "") rendered;
                in
                concatStringsSep "\n" nonEmpty
              else
                ""
            else
              renderKV k val;

          rendered = map renderOne keys;
          nonEmpty = builtins.filter (s: s != "") rendered;
        in
        concatStringsSep "\n" nonEmpty;

      body = renderTopLevel settings;
      extra = optionalString (extraConfig != "") ("\n" + extraConfig);
    in
    "<ossec_config>\n${indentStr 2 body}${extra}\n</ossec_config>\n";

  # Store the generated ossec.conf as a Nix derivation (immutable, in /nix/store)
  configFile = pkgs.writeText "ossec.conf" (generateOssecConf cfg.settings cfg.extraConfig);

  # All 5 daemon service unit names (used in before/wantedBy)
  daemonServices = [
    "wazuh-execd.service"
    "wazuh-agentd.service"
    "wazuh-modulesd.service"
    "wazuh-syscheckd.service"
    "wazuh-logcollector.service"
  ];

  # Shared serviceConfig applied to every daemon
  commonServiceConfig = {
    User = cfg.user;
    Group = cfg.group;
    Restart = "on-failure";
    RestartSec = "5s";

    # Wazuh's w_homedir() (src/shared/file_op.c) determines the agent home by
    # reading /proc/self/exe, then stripping the "/bin/<name>" suffix. For binaries
    # in the Nix store this yields the store path, not /var/lib/wazuh. WAZUH_HOME
    # env var is only a fallback when /proc/self/exe is unavailable (never on Linux).
    #
    # Solution: the setup service copies daemon binaries to ${stateDir}/bin/.
    # When the daemon runs from ${stateDir}/bin/wazuh-*, /proc/self/exe resolves to
    # that path, so w_homedir() correctly computes home = ${stateDir}. All relative
    # paths (etc/ossec.conf, logs/, queue/, var/, tmp/) then resolve to the state dir.
    # Binaries are re-copied by the setup service on each nixos-rebuild switch.

    # systemd creates /var/lib/wazuh and sets ownership via StateDirectory
    StateDirectory = "wazuh";
    StateDirectoryMode = "0750";
    ReadWritePaths = [ stateDir ];

    # Systemd security hardening
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;

    # Capabilities — all dropped; systemd handles user/group switching via
    # User=/Group=. The Privsep patch makes Privsep_SetUser/SetGroup no-ops.
    NoNewPrivileges = true;
    CapabilityBoundingSet = [ "" ];

    # Required for journald log collection (wazuh-logcollector reads the journal)
    SupplementaryGroups = [ "systemd-journal" ];

    ProtectClock = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectKernelModules = true;
    ProtectKernelTunables = true;
    ProtectHostname = true;
    LockPersonality = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    RestrictNamespaces = true;
    MemoryDenyWriteExecute = true;
    RemoveIPC = true;
    SystemCallArchitectures = "native";
    UMask = "0027";

    # Restrict socket families to only those actually used.
    # Base: AF_UNIX for inter-daemon communication via /var/lib/wazuh/queue/sockets/.
    # Network daemons (agentd, execd) additionally need AF_INET/AF_INET6;
    # those services override this setting below.
    RestrictAddressFamilies = [ "AF_UNIX" ];
  }
  // lib.optionalAttrs (cfg.environmentFile != null) {
    EnvironmentFile = cfg.environmentFile;
  };

  # Environment variables injected into every daemon service
  commonEnvironment = {
    WAZUH_HOME = stateDir;
    # wazuh-logcollector uses dlopen("libsystemd.so.0") to read the systemd journal.
    # The library is not in the default ld.so search path under NixOS, so we point
    # LD_LIBRARY_PATH at the state lib dir (which contains a symlink to the systemd lib)
    # and at the systemd package's lib dir as a fallback.
    LD_LIBRARY_PATH = "${stateDir}/lib:${pkgs.systemd}/lib";
  };

  # Runtime PATH additions for all daemon services
  commonPath = [
    pkgs.gawk
    pkgs.procps
    pkgs.coreutils
    pkgs.iproute2
  ];

in
{
  options.services.wazuh-agent = {

    enable = mkEnableOption "Wazuh security agent";

    package = mkPackageOption pkgs "wazuh-agent" { };

    user = mkOption {
      type = lib.types.str;
      default = "wazuh";
      description = "User account under which the Wazuh agent daemons run.";
    };

    group = mkOption {
      type = lib.types.str;
      default = "wazuh";
      description = "Group under which the Wazuh agent daemons run.";
    };

    settings = mkOption {
      type = lib.types.submodule {
        # Use attrsOf anything for the freeform type to allow arbitrary Wazuh settings
        # without triggering infinite recursion from a self-referential type.
        freeformType = lib.types.attrsOf lib.types.anything;

        options = {
          client = mkOption {
            type = lib.types.submodule {
              freeformType = lib.types.attrsOf lib.types.anything;
              options = {
                server = mkOption {
                  type = lib.types.submodule {
                    options = {
                      address = mkOption {
                        type = lib.types.str;
                        description = "IP address or hostname of the Wazuh manager to connect to.";
                        example = "10.0.0.1";
                      };
                      port = mkOption {
                        type = lib.types.port;
                        default = 1514;
                        description = "TCP/UDP port for agent-manager communication (default: 1514).";
                      };
                      protocol = mkOption {
                        type = lib.types.enum [
                          "tcp"
                          "udp"
                        ];
                        default = "tcp";
                        description = "Network protocol for agent-manager communication.";
                      };
                    };
                  };
                  description = "Wazuh manager server connection settings.";
                };
                crypto_method = mkOption {
                  type = lib.types.enum [
                    "aes"
                    "blowfish"
                  ];
                  default = "aes";
                  description = "Encryption method for agent-manager communication.";
                };
              };
            };
            default = { };
            description = "Agent-to-manager (client) connection settings.";
          };

          client_buffer = mkOption {
            type = lib.types.submodule {
              options = {
                disabled = mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = "Whether to disable the agent-side event buffer.";
                };
                queue_size = mkOption {
                  type = lib.types.int;
                  default = 5000;
                  description = "Maximum number of events to buffer locally before sending to manager.";
                };
                events_per_second = mkOption {
                  type = lib.types.int;
                  default = 500;
                  description = "Maximum number of events to send to the manager per second.";
                };
              };
            };
            default = { };
            description = "Agent event buffer settings.";
          };

          syscheck = mkOption {
            type = lib.types.submodule {
              freeformType = lib.types.attrsOf lib.types.anything;
              options = {
                disabled = mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = "Whether to disable file integrity monitoring (FIM/syscheck).";
                };
                frequency = mkOption {
                  type = lib.types.int;
                  default = 43200;
                  description = "File integrity scan frequency in seconds (default: 43200 = 12 hours).";
                };
              };
            };
            default = { };
            description = "File integrity monitoring (syscheck) settings.";
          };

          rootcheck = mkOption {
            type = lib.types.submodule {
              freeformType = lib.types.attrsOf lib.types.anything;
              options = {
                disabled = mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = "Whether to disable rootkit detection (rootcheck).";
                };
                frequency = mkOption {
                  type = lib.types.int;
                  default = 43200;
                  description = "Rootkit detection scan frequency in seconds (default: 43200 = 12 hours).";
                };
              };
            };
            default = { };
            description = "Rootkit detection (rootcheck) settings.";
          };

          localfile = mkOption {
            type = lib.types.listOf (
              lib.types.submodule {
                options = {
                  log_format = mkOption {
                    type = lib.types.str;
                    default = "syslog";
                    description = "Log format type: syslog, journald, json, apache, nginx, etc.";
                  };
                  location = mkOption {
                    type = lib.types.str;
                    description = ''
                      Path to the log file to monitor, or "journald" to read from the
                      systemd journal (recommended default on NixOS).
                    '';
                    example = "/var/log/nginx/access.log";
                  };
                };
              }
            );
            default = [
              {
                log_format = "journald";
                location = "journald";
              }
            ];
            description = ''
              Log file sources for the log collector daemon. Each entry becomes a
              <localfile> block in ossec.conf. Defaults to reading the systemd journal,
              which is the standard log mechanism on NixOS.
            '';
          };

          wodle = mkOption {
            type = lib.types.listOf (
              lib.types.submodule {
                freeformType = lib.types.attrsOf lib.types.anything;
                options = {
                  name = mkOption {
                    type = lib.types.str;
                    description = ''
                      Wodle (Wazuh module) name. Common values: "syscollector",
                      "vulnerability-detector", "osquery", "aws-s3".
                    '';
                    example = "syscollector";
                  };
                };
              }
            );
            default = [ ];
            description = ''
              Wodle module configurations. Each entry becomes a <wodle name="..."> block
              in ossec.conf. The "name" attribute is rendered as an XML attribute, not
              a child element.
            '';
          };
        };
      };
      default = { };
      description = ''
        Structured settings converted to ossec.conf XML. Attribute names map 1:1 to
        Wazuh XML element names — underscores and hyphens are preserved as-is.
        Booleans render as "yes"/"no", integers as numbers, nested attrsets as nested
        elements, lists as repeated elements.
        Use {option}`extraConfig` to append raw XML for settings not covered here.
      '';
    };

    environmentFile = mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Path to a file providing environment variables to all Wazuh agent daemons.
        Use this to inject secrets such as WAZUH_REGISTRATION_PASSWORD without
        storing them in the Nix store. The file must be owned by root with mode 0400.
        Format: one KEY=VALUE pair per line (shell variable assignment syntax).
      '';
      example = "/run/secrets/wazuh-env";
    };

    extraConfig = mkOption {
      type = lib.types.lines;
      default = "";
      description = ''
        Raw XML to append inside the <ossec_config> root element of ossec.conf.
        Use this for Wazuh configuration sections not covered by the structured options.
      '';
      example = ''
        <active-response>
          <disabled>yes</disabled>
        </active-response>
      '';
    };
  };

  # Config: all system effects, guarded by mkIf cfg.enable
  config = mkIf cfg.enable {

    assertions = [
      {
        assertion =
          cfg.settings ? client
          && cfg.settings.client ? server
          && cfg.settings.client.server ? address
          && cfg.settings.client.server.address != "";
        message = ''
          services.wazuh-agent.settings.client.server.address must be set when the
          agent is enabled. Set it to the IP or hostname of your Wazuh manager.
          Example: services.wazuh-agent.settings.client.server.address = "10.0.0.1";
        '';
      }
    ];

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = stateDir;
      description = "Wazuh agent daemon user";
    };

    users.groups.${cfg.group} = { };

    systemd.tmpfiles.rules = [
      # Base state directory (further populated by wazuh-agent-setup.service)
      "d ${stateDir}      0750 ${cfg.user} ${cfg.group} -"
      # Temp dir — contents auto-cleaned after 1 day
      "d ${stateDir}/tmp  0750 ${cfg.user} ${cfg.group} 1d"
    ];

    systemd.targets.wazuh-agent = {
      description = "Wazuh Agent";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
    };

    systemd.services.wazuh-agent-setup = {
      description = "Wazuh Agent State Directory Setup";
      wantedBy = [ "wazuh-agent.target" ];
      # Must complete before any daemon starts
      before = daemonServices;

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # Root is required for chown/chmod operations.
        # ProtectSystem/ProtectHome are intentionally NOT set here.
        User = "root";
      };

      script = ''
        set -euo pipefail

        STATE="${stateDir}"
        USR="${cfg.user}"
        GRP="${cfg.group}"
        PKG="${pkg}"

        # Helper: create directory with correct ownership/permissions.
        # Idempotent — safe to run multiple times.
        mkd() {
          [ -d "$1" ] || mkdir -p "$1"
          chown "$USR:$GRP" "$1"
          chmod 0750 "$1"
        }

        # Create the full Wazuh runtime directory structure.
        # All directories are owned by wazuh:wazuh.
        mkd "$STATE"
        mkd "$STATE/bin"
        mkd "$STATE/etc"
        mkd "$STATE/etc/shared"
        mkd "$STATE/var"
        mkd "$STATE/var/run"
        mkd "$STATE/var/db"
        mkd "$STATE/logs"
        mkd "$STATE/queue"
        mkd "$STATE/queue/alerts"
        mkd "$STATE/queue/sockets"
        mkd "$STATE/queue/db"
        mkd "$STATE/queue/diff"
        mkd "$STATE/queue/fim"
        mkd "$STATE/queue/fim/db"
        mkd "$STATE/queue/syscollector"
        mkd "$STATE/queue/logcollector"
        mkd "$STATE/tmp"
        mkd "$STATE/wodles"
        mkd "$STATE/active-response"
        mkd "$STATE/active-response/bin"

        # Copy daemon binaries to ${stateDir}/bin/.
        # Wazuh's w_homedir() reads /proc/self/exe and strips "/bin/<name>" to
        # find the home directory. By running from ${stateDir}/bin/, the daemon
        # correctly computes WAZUH_HOME = ${stateDir}. This makes all relative
        # file paths (etc/, logs/, queue/, var/) resolve to the state directory.
        # Binaries are re-copied on each nixos-rebuild switch so package updates
        # always take effect.
        for bin in wazuh-execd wazuh-agentd wazuh-modulesd wazuh-syscheckd wazuh-logcollector; do
          cp -f "$PKG/bin/$bin" "$STATE/bin/$bin"
          chown "root:$GRP" "$STATE/bin/$bin"
          chmod 0750 "$STATE/bin/$bin"
        done

        # Copy shared libraries needed by the daemon binaries.
        # The binaries use an RPATH that includes ${stateDir}/lib (via $ORIGIN/../lib),
        # so libraries must be present alongside the copied binaries.
        if [ -d "$PKG/lib" ]; then
          mkd "$STATE/lib"
          cp -rL "$PKG/lib/." "$STATE/lib/"
          chown -R "root:root" "$STATE/lib"
          chmod -R 0755 "$STATE/lib"
        fi

        # Symlink ossec.conf → generated config (updated each nixos-rebuild switch).
        ln -sfn "${configFile}" "$STATE/etc/ossec.conf"

        # Copy internal_options.conf from the package (not a symlink).
        # Remove any existing file/symlink first to avoid "same file" errors from cp.
        rm -f "$STATE/etc/internal_options.conf"
        cp "$PKG/etc/internal_options.conf" "$STATE/etc/internal_options.conf"
        chown "$USR:$GRP" "$STATE/etc/internal_options.conf"
        chmod 0640 "$STATE/etc/internal_options.conf"

        # Symlink active-response scripts → package-provided scripts.
        # -sfn updates the symlink target on package upgrades.
        ln -sfn "$PKG/share/wazuh-agent/active-response/bin" "$STATE/active-response/bin"

        # Create local_internal_options.conf from the package example if absent.
        # This file is intentionally mutable — users can edit it manually.
        if [ ! -f "$STATE/etc/local_internal_options.conf" ]; then
          cp "$PKG/etc/local_internal_options.conf.example" \
             "$STATE/etc/local_internal_options.conf"
          chown "$USR:$GRP" "$STATE/etc/local_internal_options.conf"
          chmod 0640 "$STATE/etc/local_internal_options.conf"
        fi

        # Fix permissions on client.keys if it already exists (e.g., after rebuild).
        # Never overwrite or delete it — it contains the agent registration key.
        if [ -f "$STATE/etc/client.keys" ]; then
          chown "$USR:$GRP" "$STATE/etc/client.keys"
          chmod 0640 "$STATE/etc/client.keys"
        fi
      '';
    };

    # wazuh-execd: Active response execution daemon.
    # Must start before agentd so active responses can fire immediately.
    # Needs AF_INET/AF_INET6 in addition to AF_UNIX because active responses
    # may trigger network-based actions.
    systemd.services.wazuh-execd = {
      description = "Wazuh Execution Daemon";
      partOf = [ "wazuh-agent.target" ];
      wantedBy = [ "wazuh-agent.target" ];
      after = [ "wazuh-agent-setup.service" ];
      requires = [ "wazuh-agent-setup.service" ];

      path = commonPath;
      environment = commonEnvironment;

      serviceConfig = commonServiceConfig // {
        Type = "simple";
        # Run from the stateDir bin/ so /proc/self/exe resolves to stateDir
        ExecStart = "${stateDir}/bin/wazuh-execd -f";
        # Active responses may trigger network actions (e.g., firewall rules via iproute2)
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
      };
    };

    # wazuh-agentd: Main agent daemon — connects to manager.
    # Depends on execd being up so active response infrastructure is ready.
    # Needs AF_INET/AF_INET6 for TCP connection to the Wazuh manager (port 1514/1515).
    systemd.services.wazuh-agentd = {
      description = "Wazuh Agent Daemon";
      partOf = [ "wazuh-agent.target" ];
      wantedBy = [ "wazuh-agent.target" ];
      after = [
        "wazuh-agent-setup.service"
        "wazuh-execd.service"
      ];
      requires = [ "wazuh-agent-setup.service" ];

      path = commonPath;
      environment = commonEnvironment;

      serviceConfig = commonServiceConfig // {
        Type = "simple";
        ExecStart = "${stateDir}/bin/wazuh-agentd -f";
        # Connects to manager via TCP (port 1514) and enrollment via TCP (port 1515)
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
      };
    };

    # wazuh-modulesd: Modules daemon (rootcheck, syscollector, vulnerability-detector, etc.)
    # Starts after agentd so it can report findings immediately.
    # Uses only AF_UNIX for IPC with other daemons via queue/sockets.
    systemd.services.wazuh-modulesd = {
      description = "Wazuh Modules Daemon";
      partOf = [ "wazuh-agent.target" ];
      wantedBy = [ "wazuh-agent.target" ];
      after = [
        "wazuh-agent-setup.service"
        "wazuh-agentd.service"
      ];
      requires = [ "wazuh-agent-setup.service" ];

      path = commonPath;
      environment = commonEnvironment;

      serviceConfig = commonServiceConfig // {
        Type = "simple";
        ExecStart = "${stateDir}/bin/wazuh-modulesd -f";
      };
    };

    # wazuh-syscheckd: File integrity monitoring daemon.
    # Starts after agentd so FIM events are forwarded immediately.
    # Uses only AF_UNIX for IPC; FIM uses inotify (kernel API, not a socket).
    systemd.services.wazuh-syscheckd = {
      description = "Wazuh File Integrity Monitoring Daemon";
      partOf = [ "wazuh-agent.target" ];
      wantedBy = [ "wazuh-agent.target" ];
      after = [
        "wazuh-agent-setup.service"
        "wazuh-agentd.service"
      ];
      requires = [ "wazuh-agent-setup.service" ];

      path = commonPath;
      environment = commonEnvironment;

      serviceConfig = commonServiceConfig // {
        Type = "simple";
        ExecStart = "${stateDir}/bin/wazuh-syscheckd -f";
      };
    };

    # wazuh-logcollector: Log collection daemon (journald, files, etc.)
    # Starts after agentd so collected logs are forwarded immediately.
    # Needs read access to /var/log/journal for systemd journal collection.
    # Uses AF_UNIX only: communicates with agentd via queue/sockets/logcollector socket.
    systemd.services.wazuh-logcollector = {
      description = "Wazuh Log Collector Daemon";
      partOf = [ "wazuh-agent.target" ];
      wantedBy = [ "wazuh-agent.target" ];
      after = [
        "wazuh-agent-setup.service"
        "wazuh-agentd.service"
      ];
      requires = [ "wazuh-agent-setup.service" ];

      path = commonPath;
      environment = commonEnvironment;

      serviceConfig = commonServiceConfig // {
        Type = "simple";
        ExecStart = "${stateDir}/bin/wazuh-logcollector -f";
        # Journal files are under /var/log/journal — read access required when
        # localfile log_format = "journald" is configured (the NixOS default).
        # ProtectSystem=strict makes the filesystem read-only except ReadWritePaths,
        # so we must explicitly allow read access to the journal directory.
        ReadOnlyPaths = [ "/var/log/journal" ];
      };
    };
  };

  meta.maintainers = [ lib.maintainers.dehumanizer77 ];
}
