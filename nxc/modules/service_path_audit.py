from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5 import scmr
import re


class NXCModule:
    """Enumerate services for common misconfigurations.

    This module lists all services on the target and checks if the
    service binary path is unquoted with spaces or located on a
    writable share.
    """

    name = "service_path_audit"
    description = "Check for unquoted or writable service binary paths"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """No options available"""

    def on_login(self, context, connection):
        try:
            shares = connection.shares()
            writable_shares = {
                share["name"] for share in shares if "WRITE" in share["access"]
            }
        except Exception:
            writable_shares = set()

        remote_ops = None
        try:
            remote_ops = RemoteOperations(smbConnection=connection.conn, doKerberos=connection.kerberos)
            remote_ops._RemoteOperations__connectSvcCtl()
            dce = remote_ops._RemoteOperations__scmr
            machine, _ = remote_ops.getMachineNameAndDomain()
            scm_handle = scmr.hROpenSCManagerW(dce, machine)["lpScHandle"]
            resp = scmr.hREnumServicesStatusW(dce, scm_handle)
            for svc in resp["lpBuffer"]:
                service_name = svc["lpServiceName"]
                try:
                    handle = scmr.hROpenServiceW(dce, scm_handle, service_name)["lpServiceHandle"]
                    config = scmr.hRQueryServiceConfigW(dce, handle)["lpServiceConfig"]
                    binary_path = config["lpBinaryPathName"]
                    if isinstance(binary_path, bytes):
                        binary_path = binary_path.decode("utf-8", errors="ignore")
                    unquoted = False
                    path_no_args = binary_path.split()[0]
                    if " " in path_no_args and not binary_path.strip().startswith('"'):
                        unquoted = True
                    writable = False
                    m = re.match(r"^([A-Za-z]):\\\\(.+)$", path_no_args)
                    if m:
                        share = m.group(1).upper() + "$"
                        if share in writable_shares:
                            writable = True
                    if unquoted or writable:
                        context.log.highlight(
                            f"{service_name}: {binary_path} (unquoted: {unquoted}, writable share: {writable})"
                        )
                except Exception as e:
                    context.log.debug(f"Error processing service {service_name}: {e}")
        except Exception as e:
            context.log.fail(f"Service enumeration failed: {e}")
        finally:
            if remote_ops:
                remote_ops.finish()
