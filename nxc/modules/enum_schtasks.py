from datetime import datetime
from nxc.helpers.logger import write_log
from typing import Dict


class NXCModule:
    """Enumerate scheduled tasks on remote hosts."""

    name = "enum_schtasks"
    description = "List scheduled tasks via schtasks"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self):
        self.method = "schtasks"

    def options(self, context, module_options: Dict[str, str]):
        """METHOD  Enumeration method: schtasks or wmic (default: schtasks)"""
        if module_options and "METHOD" in module_options:
            selected = module_options["METHOD"].lower()
            if selected in ["schtasks", "wmic"]:
                self.method = selected
            else:
                context.log.fail("METHOD must be 'schtasks' or 'wmic'")

    def on_login(self, context, connection):
        if self.method == "wmic":
            command = (
                "wmic /namespace:\\root\\cimv2 path Win32_ScheduledJob get Name,Command /format:table"
            )
            output = connection.execute(command, True)
        else:
            command = "schtasks /query /fo LIST /v"
            output = connection.execute(command, True)

        if not output:
            context.log.fail("Failed to retrieve scheduled tasks")
            return

        tasks = []
        current_task = ""
        for line in output.splitlines():
            line = line.strip()
            if line.lower().startswith("taskname:"):
                current_task = line.split(":", 1)[1].strip()
                tasks.append(current_task)
        for task in tasks:
            context.log.highlight(task)

        log_name = f"schtasks-{connection.host}-{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.log"
        write_log(output, log_name)
        context.log.display(f"Saved raw output to ~/.nxc/logs/{log_name}")
