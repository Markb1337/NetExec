from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """Check pre-created computer accounts for default passwords."""

    name = "pre2k_checker"
    description = "Authenticate to precreated computer accounts using the default password"
    supported_protocols = ["ldap"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        search_filter = "(&(objectClass=computer)(userAccountControl=4128))"
        attributes = ["sAMAccountName"]
        try:
            resp = connection.search(search_filter, attributes)
            results = parse_result_attributes(resp)
        except Exception as e:
            context.log.fail(f"LDAP search failed: {e}")
            return

        if not results:
            context.log.info("No pre-created computer accounts found")
            return

        for comp in results:
            sam = comp.get("sAMAccountName")
            if not sam:
                continue
            username = sam[:-1] if sam.endswith("$") else sam
            password = username.lower()[:14]
            principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            try:
                getKerberosTGT(
                    clientName=principal,
                    password=password,
                    domain=connection.domain,
                    lmhash="",
                    nthash="",
                    aesKey="",
                    kdcHost=connection.kdcHost,
                    serverName=None,
                )
            except Exception as e:
                context.log.debug(f"{username}$ authentication failed: {e}")
            else:
                context.log.highlight(f"{username}$ still uses the default password")
