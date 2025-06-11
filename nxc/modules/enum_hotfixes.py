from datetime import datetime
from nxc.helpers.logger import write_log


class NXCModule:
    """Enumerate installed Windows hotfixes."""

    name = "enum_hotfixes"
    description = "List installed hotfixes via WMIC or PowerShell"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.method = "wmic"

    def options(self, context, module_options):
        """METHOD  Enumeration method (wmic or ps, default: wmic)"""
        if module_options and "METHOD" in module_options:
            selected = module_options["METHOD"].lower()
            if selected in ["wmic", "ps"]:
                self.method = selected
            else:
                context.log.fail("METHOD must be either 'wmic' or 'ps'")

    def on_login(self, context, connection):
        if self.method == "ps":
            command = (
                "$ProgressPreference='SilentlyContinue'; "
                "Get-HotFix | Select-Object HotFixID,InstalledOn"
            )
            context.log.debug(f"Executing PowerShell command: {command}")
            output = connection.ps_execute(command, get_output=True)[0]
        else:
            command = "wmic qfe get HotFixID,InstalledOn /format:table"
            context.log.debug(f"Executing command: {command}")
            output = connection.execute(command, True)

        # WMIC may introduce carriage returns and blank lines
        if output:
            output = (
                output.replace("\r\r\n", "\n")
                .replace("\r\n", "\n")
                .replace("\r", "")
            )
            lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
            output = "\n".join(lines)

        if not output:
            context.log.fail("Failed to retrieve hotfix information")
            return

        for line in output.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("hotfixid"):
                continue
            context.log.highlight(line)

        log_name = (
            f"hotfixes-{connection.host}-{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.log"
        )
        write_log(output, log_name)
        context.log.display(f"Saved raw output to ~/.nxc/logs/{log_name}")
