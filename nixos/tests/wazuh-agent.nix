{ pkgs, ... }:
{
  name = "wazuh-agent";
  meta.maintainers = with pkgs.lib.maintainers; [ dehumanizer77 ];

  nodes.agent =
    { ... }:
    {
      # Use minimal memory for the test VM (no KVM — QEMU emulation only)
      virtualisation.memorySize = 512;

      services.wazuh-agent = {
        enable = true;
        settings = {
          client.server = {
            address = "192.168.1.1"; # Unreachable — test only verifies startup
            port = 1514;
          };
          syscheck.disabled = true; # Speed up test — no filesystem scans
          rootcheck.disabled = true; # Speed up test — no rootkit scans
          localfile = [
            {
              log_format = "journald";
              location = "journald";
            }
          ];
        };
      };
    };

  testScript = ''
    agent.start()

    with subtest("wazuh-agent.target becomes active"):
        agent.wait_for_unit("wazuh-agent.target")

    with subtest("directory structure exists"):
        agent.succeed("test -d /var/lib/wazuh/etc")
        agent.succeed("test -d /var/lib/wazuh/logs")
        agent.succeed("test -d /var/lib/wazuh/var/run")
        agent.succeed("test -d /var/lib/wazuh/queue/sockets")

    with subtest("ossec.conf generated with manager address"):
        agent.succeed("test -f /var/lib/wazuh/etc/ossec.conf")
        agent.succeed("grep '192.168.1.1' /var/lib/wazuh/etc/ossec.conf")

    with subtest("wazuh-agentd daemon is running"):
        agent.succeed("pgrep wazuh-agentd")

    with subtest("log file created"):
        agent.wait_until_succeeds("test -f /var/lib/wazuh/logs/ossec.log")
  '';
}
