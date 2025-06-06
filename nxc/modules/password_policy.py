from dateutil.relativedelta import relativedelta as rd
from nxc.parsers.ldap_results import parse_result_attributes
from typing import Dict


class NXCModule:
    """Retrieve the domain password policy via LDAP."""

    name = "password_policy"
    description = "Display the default domain password policy"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options: Dict[str, str]):
        """No options available."""

    def _format_time(self, value: str) -> str:
        return f"{rd(seconds=int(abs(int(value)) / 10000000)).days} days" if value else "N/A"

    def on_login(self, context, connection):
        base_dn = connection.args.base_dn if connection.args.base_dn else connection.ldap_connection._baseDN
        attrs = [
            "minPwdLength",
            "minPwdAge",
            "maxPwdAge",
            "pwdHistoryLength",
            "lockoutDuration",
            "lockoutThreshold",
            "lockoutObservationWindow",
            "pwdProperties",
        ]
        resp = connection.ldap_connection.search(
            searchBase=base_dn,
            searchFilter="(objectClass=domain)",
            attributes=attrs,
            sizeLimit=1,
        )
        parsed = parse_result_attributes(resp)
        if not parsed:
            context.log.fail("Failed to retrieve password policy")
            return
        policy = parsed[0]
        context.log.highlight(f"Minimum password length: {policy.get('minPwdLength')}")
        if "minPwdAge" in policy:
            context.log.highlight(f"Minimum password age: {self._format_time(policy['minPwdAge'])}")
        if "maxPwdAge" in policy:
            context.log.highlight(f"Maximum password age: {self._format_time(policy['maxPwdAge'])}")
        if "lockoutDuration" in policy:
            context.log.highlight(f"Lockout duration: {self._format_time(policy['lockoutDuration'])}")
        if "lockoutObservationWindow" in policy:
            context.log.highlight(
                f"Lockout observation window: {self._format_time(policy['lockoutObservationWindow'])}"
            )
        if "lockoutThreshold" in policy:
            context.log.highlight(f"Lockout threshold: {policy['lockoutThreshold']}")
        if "pwdHistoryLength" in policy:
            context.log.highlight(f"Password history length: {policy['pwdHistoryLength']}")
        if "pwdProperties" in policy:
            context.log.highlight(f"Password properties: {policy['pwdProperties']}")
