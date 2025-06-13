"""Module to enumerate outgoing remote management connections via SMB."""

from datetime import datetime
from typing import Dict, Set

from nxc.helpers.logger import write_log
from nxc.paths import NXC_PATH
import re


class NXCModule:
    """Enumerate outbound connections to remote management services."""

    name = "enum_lateral_movement"
    description = (
        "List active outbound connections to RDP, FTP, Telnet, SSH and WinRM"
    )
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    PORT_MAP: Dict[int, str] = {
        3389: "RDP",
        21: "FTP",
        23: "Telnet",
        22: "SSH",
        5985: "WinRM (HTTP)",
        5986: "WinRM (HTTPS)",
    }

    def options(self, context, module_options):
        """No options available."""

    def on_admin_login(self, context, connection):
        command = "netstat -ano | findstr ESTABLISHED"
        output = connection.execute(command, True)

        if not output:
            context.log.display("No active outgoing sessions found")
            return

        hosts_by_port: Dict[int, Set[str]] = {p: set() for p in self.PORT_MAP}

        for line in output.splitlines():
            parts = [p for p in re.split(r"\s+", line.strip()) if p]
            if len(parts) < 3:
                continue
            remote = parts[2]
            if ":" not in remote:
                continue
            host, port_str = remote.rsplit(":", 1)
            if not port_str.isdigit():
                continue
            port = int(port_str)
            if port in hosts_by_port:
                hosts_by_port[port].add(host)

        any_found = False
        for port, hosts in hosts_by_port.items():
            if not hosts:
                continue
            any_found = True
            context.log.success(
                f"Active outgoing {self.PORT_MAP[port]} connections detected:"
            )
            for host in sorted(hosts):
                context.log.highlight(f"{host}:{port}")

        if not any_found:
            context.log.display("No active outgoing sessions found")

        log_name = (
            f"enum-lateral-movement-{connection.host}-"
            f"{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.log"
        )
        write_log(output, log_name)
        context.log.display(f"Saved raw output to {NXC_PATH}/logs/{log_name}")

