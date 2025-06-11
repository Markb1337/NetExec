from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.rrp import DCERPCSessionError
from impacket.examples.secretsdump import RemoteOperations
from impacket.system_errors import ERROR_NO_MORE_ITEMS, ERROR_FILE_NOT_FOUND


class NXCModule:
    """List Windows Defender exclusion rules."""

    name = "defender_exceptions"
    description = "Returns all configured Windows Defender exclusions"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """No options available"""

    def _enum_values(self, dce, reg_handle, key_path, context, connection):
        exclusions = []
        try:
            key_handle = rrp.hBaseRegOpenKey(dce, reg_handle, key_path)["phkResult"]
        except DCERPCSessionError as e:
            if e.error_code != ERROR_FILE_NOT_FOUND:
                context.log.debug(f"Error opening {key_path} on {connection.host}: {e}")
            return exclusions

        index = 0
        while True:
            try:
                ans = rrp.hBaseRegEnumValue(dce, key_handle, index)
                exclusions.append(ans["lpValueNameOut"][:-1])
                index += 1
            except DCERPCSessionError as e:
                if e.error_code == ERROR_NO_MORE_ITEMS:
                    break
                context.log.debug(f"Error enumerating {key_path} on {connection.host}: {e}")
                break

        rrp.hBaseRegCloseKey(dce, key_handle)
        return exclusions

    def on_admin_login(self, context, connection):
        try:
            remote_ops = RemoteOperations(connection.conn, connection.kerberos)
            remote_ops.enableRegistry()

            if not remote_ops._RemoteOperations__rrp:
                context.log.fail("Unable to access remote registry")
                return

            reg_handle = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)["phKey"]

            keys = {
                "Policy Paths": "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths",
                "Policy Extensions": "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Extensions",
                "Policy Processes": "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Processes",
                "Paths": "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
                "Extensions": "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions",
                "Processes": "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes",
            }

            results = []
            for desc, key in keys.items():
                values = self._enum_values(remote_ops._RemoteOperations__rrp, reg_handle, key, context, connection)
                for val in values:
                    context.log.highlight(f"{desc}: {val}")
                results.extend(values)

            if not results:
                context.log.display("No Windows Defender exclusions found")
        except DCERPCSessionError as e:
            context.log.debug(f"Remote registry error {e} on host {connection.host}")
        finally:
            remote_ops.finish()
