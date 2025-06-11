class NXCModule:
    """List Windows Defender exclusion rules using PowerShell."""

    name = "defender_exceptions_stealthy"
    description = "Returns all configured Windows Defender exclusions using PowerShell"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """No options available"""

    def on_admin_login(self, context, connection):
        categories = {
            "Paths": "ExclusionPath",
            "Extensions": "ExclusionExtension",
            "Processes": "ExclusionProcess",
            "IPs": "ExclusionIpAddress",
        }
        found = False
        for desc, prop in categories.items():
            cmd = (
                "powershell -NoLogo -NonInteractive -Command "
                f"\"(Get-MpPreference).{prop}\""
            )
            output = connection.execute(cmd, True)
            if not output:
                continue
            for line in output.splitlines():
                line = line.strip()
                if line:
                    context.log.highlight(f"{desc}: {line}")
                    found = True
        if not found:
            context.log.display("No Windows Defender exclusions found")

