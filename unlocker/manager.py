#!/usr/bin/env python
#
# Copyright 2018 Alexandru Catrina
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from re import compile, UNICODE
from os import path
from sys import stdin, stdout
from base64 import b64encode
from getpass import getpass

from unlocker.authority import Authority
from unlocker.keychain import Keychain
from unlocker.service import Service
from unlocker.migrate import Migrate
from unlocker.display import Display

from unlocker.util.log import Log


class Manager(object):
    """Authority secrets manager.

    The Manager is a dispatcher for various call options, such as saving
    passkeys and removing them or lookup.

    A saved passkey is prefixed with the passkey's type in a "storage key"
    where a storage key is a known prefixed authority.

        let "storage_key" be "storage_prefix" + "authority"

        storage_key = passkey_type + actual_passkey

    Additional information about hostnames are saved in hostnames keys. For
    example, a hostname for an authority is saved as:

        let "hostname_key" be "hostname_prefix" + "scheme?user@host:port"

        hostname_key = storage_key

    Saved "storage_key" can have a jump key for tunneling or bouncing. For
    example, a database behind a server can be saved as:

        let "jump_key" be "jump_prefix" + "authority"

        jump_key = storage_key

    Arguments:
        __secrets (Keychain): Authority and passwords database.

    Args:
        option     (str): Manager operation to handle.
        args      (dict): Arguments provided to manager.
        auth (Authority): Current authority working with.
    """

    __secrets = None

    C_PASSWORD, C_PRIVATE_KEY = "password", "privatekey"
    PK_PASSWORD, PK_PRIV_KEY = ".", ">"
    K_HOSTNAME = "{scheme}?{user}@{host}:{port}"
    STORAGE_PREFIX, JUMP_PREFIX, HOSTNAME_PREFIX = "$!", "j!", "h!"

    OR_LIST, OR_LOOKUP, OR_RECALL = "list", "lookup", "recall"
    OW_APPEND, OW_UPDATE, OW_REMOVE = "append", "update", "remove"
    OW_FORGET, OW_MIGRATE = "forget", "migrate"
    OR_DEBUG_DUMP, OW_DEBUG_PURGE = "dump", "purge"

    MAX_ITER_LIST = 2**16
    HOSTNAME_REGEX = compile(
        r"(?P<scheme>.+)\?(?P<user>.+)@(?P<host>.+):(?P<port>\d+)", UNICODE)

    def __init__(self, option, args):
        self.option = option
        self.args = args
        self.auth = None

    def make_auth(self):
        """Generate current authority.

        Tries to find port if not provided by known services schemas
        and vice-versa.

        It saves authority into self.auth

        Returns:
            self: Manager instance.
        """

        host, user = self.args.get("host"), self.args.get("user")
        port, scheme = self.args.get("port"), self.args.get("scheme")
        if port is None and scheme is not None:
            port = Service.find_port(scheme)
        if port is not None and scheme is None:
            scheme = Service.find_scheme(port)
        self.auth = Authority.new(host, port, user, scheme)
        return self

    def call(self):
        """Call dispatcher.

        Handlers option if is identified and supported.

        Raises:
            Exception: If unsupported option is provided.
        """

        if self.option == self.OR_LIST:
            self.call_list()
        elif self.option == self.OR_RECALL:
            self.call_recall(self.args.get("signature"))
        elif self.option == self.OW_FORGET:
            self.call_forget(self.args.get("signature"))
        elif self.option == self.OR_LOOKUP:
            if stdin.isatty():
                self.make_auth().call_lookup()
            else:
                self.make_auth().dump_lookup()
        elif self.option == self.OW_APPEND:
            self.make_auth().call_update(update_duplicate=False)
        elif self.option == self.OW_UPDATE:
            self.make_auth().call_update(update_duplicate=True)
        elif self.option == self.OW_REMOVE:
            self.make_auth().call_remove()
        elif self.option == self.OW_MIGRATE:
            self.call_migrate()
        elif self.option == self.OR_DEBUG_DUMP:
            self.debug_dump()
        elif self.option == self.OW_DEBUG_PURGE:
            self.debug_purge()
        else:
            Log.fatal("Unsupported option: {o}", o=self.option)

    def call_migrate(self):
        """Migration wrapper.

        Determine if action is to import or to export and launch process.

        Raises:
            Exception: If something goes terrible wrong.

        Inputs:
            stdin: Compressed import-ready secrets.

        Outputs:
            stdout: Compressed exported stored secrets.
        """

        Migrate.discover(self)

    def get_secrets(self):
        """Keychain getter.

        Returns:
            Keychain: Passkeys storage.
        """

        return self.__secrets

    def get_storage_key(self, storage_key=None):
        """Storage key generator and getter.

        Args:
            storage_key (str): Combine key to generate storage key.

        Returns:
            str: Storage key formatted with key or current authority.
        """

        if storage_key is None:
            storage_key = self.auth.read()
        return "{}{}".format(self.STORAGE_PREFIX, storage_key)

    def get_hostname_key(self, host):
        """Hostname key generator and getter.

        Args:
            host (str): Combine host key to generate hostname key.

        Returns:
            str: Hostname key formatted with host.
        """

        return self.HOSTNAME_PREFIX + self.K_HOSTNAME.format(
                host=host, user=self.auth.get_user(),
                port=self.auth.get_port(), scheme=self.auth.get_scheme())

    def get_jump_key(self, jump=None):
        """Jump server key generator and getter.

        Args:
            jump (str): Combine jump key to generate jumpserver key.

        Returns:
            str: Jump server key formatted with authority.
        """

        if jump is None:
            jump = self.auth.read()
        return "{}{}".format(self.JUMP_PREFIX, jump)

    def get_password_passkey(self, passkey):
        """Password passkey getter.

        Args:
            passkey (str): Passkey to mask.

        Returns:
            str: Masked passkey with password identifier.
        """

        return self.PK_PASSWORD + passkey

    def get_priv_key_passkey(self, passkey):
        """Private key passkey getter.

        Args:
            passkey (str): Passkey to mask.

        Returns:
            str: Masked passkey with private key identifier.
        """

        return self.PK_PRIV_KEY + passkey

    def fetch_stored_passkey(self, storage_key=None):
        """Stored passkey getter.

        Raises:
            Exception: If passkey is invalid.

        Returns:
            tuple: Passkey type and vulnerable passkey.
        """

        if storage_key is None:
            storage_key = self.get_storage_key()
        passkey = self.get_secrets().get_value(storage_key)
        if not isinstance(passkey, (str, unicode)):
            Log.fatal("Unexpected {t} passkey, needs string", t=type(passkey))
        if len(passkey) == 0:
            Log.fatal("Zero-length passkey found: corrupted secrets?")
        return passkey[0], passkey[1:]

    def check_passkey_type(self, passkey, pass_type):
        """Passkey type checker.

        Args:
            passkey   (str): Uncompressed passkey.
            pass_type (str): Passkey identifier.

        Returns:
            bool: True if passkey is pass_type, otherwise False.
        """

        if len(passkey) > 0:
            return passkey[0] == pass_type
        return False

    def is_password(self, passkey):
        """Password type validator.

        Args:
            passkey (str): Uncompressed passkey.

        Returns:
            bool: True if passkey is password.
        """

        return self.check_passkey_type(passkey, self.PK_PASSWORD)

    def is_private_key(self, passkey):
        """Private key type validator.

        Args:
            passkey (str): Uncompressed passkey.

        Returns:
            bool: True if passkey is private key.
        """

        return self.check_passkey_type(passkey, self.PK_PRIV_KEY)

    def dump_lookup(self):
        """Vulnerable passkey dump.

        Outputs:
            stdout: Plain string if passkey is private key.
            stdout: Base64 encoded string if passkey is password.

        Raises:
            Exception: If unsupported passkey is found.
        """

        pk, passkey = self.fetch_stored_passkey()
        if pk == self.PK_PASSWORD:
            stdout.write(self.get_password_passkey(b64encode(passkey)))
        elif pk == self.PK_PRIV_KEY:
            stdout.write(self.get_priv_key_passkey(b64encode(passkey)))
        else:
            Log.fatal("Error: passkey is neither password, nor private key")

    def make_auth_from_signature(self, signature):
        """Recover authority from signature.

        Args:
            signature (str): Possible authority to recover.

        Returns:
            Authority: Recovered authority if signature found in keychain.
        """

        for each in self.get_secrets().lookup(self.STORAGE_PREFIX):
            auth = Authority.recover(each[len(self.STORAGE_PREFIX):])
            if signature == auth.signature():
                self.auth = auth
                break
        return self.auth

    def call_recall(self, signature):
        """Lookup wrapper without explicit authority.

        Finds authority by signature and calls "lookup" for passkey.

        Args:
            signature (str): Possible authority signature to match.
        """

        self.make_auth_from_signature(signature)
        if self.auth is None:
            Log.fatal("Cannot find passkey for signature {s}", s=signature)
        self.call_lookup()

    def call_forget(self, signature):
        """Remove wrapper without explicit authority.

        Finds authority by signature and calls "remove" for passkey.

        Args:
            signature (str): Possible authority signature to match.
        """

        self.make_auth_from_signature(signature)
        if self.auth is None:
            Log.fatal("Signature {s} does not exist in keychain", s=signature)
        self.call_remove()

    def call_lookup(self):
        """Lookup handler.

        Outputs:
            stdout: Pager with lookup results and masked passkey.
        """

        pass_type, passkey = self.fetch_stored_passkey()
        auth_type = "unsupported auth type"
        if self.is_password(pass_type):
            auth_type = "password (select mask and copy)"
        elif self.is_private_key(pass_type):
            auth_type = "private key (select and save it)"
            passkey = "\n{}".format(passkey)
        Display.show_lookup(self.auth, auth_type, passkey)

    def save_passkey(self, value, update=False):
        """Passkey saver wrapper.

        Saves passkey either by appending or by updating exist storage key.

        Args:
            value   (str): Encoded compressed passkey.
            update (bool): Whether keychain should update or append.

        Raises:
            Exception: If update is False and storage key is duplicated.
        """

        key = self.get_storage_key()
        if not isinstance(value, (str, unicode)):
            Log.fatal("Cannot save non-string passkey: {t}", t=type(value))
        if update:
            self.get_secrets().update(key, value)
        else:
            self.get_secrets().add(key, value)

    def save_password(self, passkey, update=False):
        """Save passkey as password.

        Args:
            value   (str): Encoded compressed passkey.
            update (bool): Whether keychain should update or append.

        Raises:
            Exception: If update is False and storage key is duplicated.
        """

        self.save_passkey(self.get_password_passkey(passkey), update)

    def save_privatekey(self, passkey, update=False):
        """Save passkey as private key.

        Args:
            value   (str): Encoded compressed passkey.
            update (bool): Whether keychain should update or append.

        Raises:
            Exception: If update is False and storage key is duplicated.
        """

        self.save_passkey(self.get_priv_key_passkey(passkey), update)

    def read_password(self, password_prompt="Password: "):
        """Get password from user input.

        Args:
            password_prompt (str): Prompt message to display.
        """

        return getpass(password_prompt)

    def read_pkfile(self, pk_prompt="Path to private key: "):
        """Get private key from user input.

        Args:
            pk_prompt (str): Prompt message to display.

        Raises:
            Exception: If path to private key does not exist or cannot open.
        """

        filepath = raw_input(pk_prompt)
        if not path.exists(filepath):
            Log.fatal("Path to private key does not exists")
        try:
            with open(filepath, "rb") as fd:
                return fd.read()
        except Exception as e:
            Log.fatal("Cannot read private key: {e}", e=str(e))

    def save_hostname(self, host=None):
        """Add host to keychain.

        Args:
            host (str): Hostname to save.

        Raises:
            Exception: If host is not provided.
        """

        if host is None:
            host = self.args.get("host")
        if host is None:
            return Log.warn("Hostname is missing (not set)")
        self.get_secrets().update(
            self.get_hostname_key(host), self.get_storage_key())

    def remove_hostname(self, storage_key, hostname=None):
        """Remove host from keychain.

        Args:
            storage_key (str): Storage key to identify hostame.

        Raises:
            Exception: If host is not provided.
        """

        host = self.args.get("host")
        if host is None or host == "":
            Log.debug("Hostname is missing (not set)")
        else:
            hostname = self.get_hostname_key(host)
        remove_list = []
        for each in self.get_secrets().lookup(self.HOSTNAME_PREFIX):
            if hostname is not None and each == hostname:
                remove_list.append(each)
            elif storage_key == self.get_secrets().get_value(each):
                remove_list.append(each)
        for each in remove_list:
            self.get_secrets().remove(each)

    def save_jump_server(self, jump_signature):
        """Add jump server to keychain.

        Args:
            jump_signature (str): Signature to lookup.

        Raises:
            Exception: If signature is not provided or not found.
        """

        if jump_signature is None:
            return Log.debug("Skipping invalid jump signature...")
        jump_auth = None
        for _, _, auth, _ in self.query_storage():
            if jump_signature == auth.signature():
                jump_auth = auth
                break
        if jump_auth is None:
            return Log.fatal(
                "Cannot find jump server for signature {server}\nClosing...",
                server=jump_signature)
        self.get_secrets().update(self.get_jump_key(), jump_auth.read())

    def remove_jump_server(self, storage_key):
        """Remove jump server from keychain.

        Args:
            storage_key (str): Signature to lookup.
        """

        if storage_key.startswith(self.STORAGE_PREFIX):
            storage_key = storage_key[len(self.STORAGE_PREFIX):]
        jump_servers = []
        for each in self.get_secrets().lookup(self.JUMP_PREFIX):
            if self.get_secrets().get_value(each) == storage_key:
                jump_servers.append(each)
        jump_key = self.get_jump_key(storage_key)
        if len(jump_servers) > 0 and jump_key not in jump_servers:
            error = "Remove all servers bouncing from this one before " \
                    "trying to delete again\nClosing..."
            Log.fatal(error)
        self.get_secrets().remove(jump_key)

    def call_update(self, update_duplicate):
        """Update handler.

        Args:
            update_duplicate (bool): Whether to update or append keys.

        Outputs:
            stdout: Pager with update message.

        Raises:
            Exception: If auth methos is not supported.
        """

        jump = self.args.get("jump_server")
        if jump is not None and jump != "":
            self.save_jump_server(jump)
        auth = self.args.get("auth", "")
        if auth == self.C_PASSWORD:
            self.save_password(self.read_password(), update=update_duplicate)
        elif auth == self.C_PRIVATE_KEY:
            self.save_privatekey(self.read_pkfile(), update=update_duplicate)
        else:
            Log.fatal("Unsupported auth method...")
        self.save_hostname()
        Display.show_update(self.auth)

    def call_remove(self):
        """Remove handler.

        Outputs:
            stdout: Pager with remove message and masked passkey.
        """

        key = self.get_storage_key()
        gen = self.get_secrets().lookup(key)
        pass_type, passkey = self.fetch_stored_passkey()
        auth_type = "unsupported auth type"
        if self.is_password(pass_type):
            auth_type = "password"
        elif self.is_private_key(pass_type):
            auth_type = "private key"
        for each in gen:
            self.remove_jump_server(each)
            self.get_secrets().remove(each)
            self.remove_hostname(each)
            break  # let the user be aware of each item to remove if choosen
        Display.show_remove(self.auth, auth_type, passkey)

    def build_jump_key(self, key):
        """Jump generator.

        Args:
            key (str): Key to lookup for jump server.

        Returns:
            str: Jump key formatted with key.
        """

        return "{}{}".format(self.JUMP_PREFIX, key)

    def find_jump_auth(self, key):
        """Jump server authority getter.

        Finds an authority jump server for a given authority key.

        Args:
            key (str): Authority key to lookup for jump server attached.

        Raises:
            Exception: On corrupted authority recovery.

        Returns:
            Authority: Returns an authority as a jump server if found.
        """

        jump_key = self.build_jump_key(key)
        if not self.get_secrets().has(jump_key):
            return None
        jump_auth = Authority.recover(self.get_secrets().get_value(jump_key))
        if jump_auth is None:
            return None
        return jump_auth

    def find_authority_from_host_key(self, host_key):
        """Recover authority from host key.

        Args:
            host_key (str): Hostname key to lookup for storage_key.

        Raises:
            Exception: If authority is corrupted.

        Returns:
            tuple[str, Authority]: Recovered authority instance.
        """

        authority = self.get_secrets().get_value(host_key)
        auth_key = authority[len(self.STORAGE_PREFIX):]
        return auth_key, Authority.recover(auth_key)

    def find_hostname_from_host_key(self, host_key):
        """Find hostname from stored host key.

        Args:
            host_key (str): Hostname key to match agains regular expression.

        Returns:
            str: Hostname for an authority.
        """

        key = host_key[len(self.HOSTNAME_PREFIX):]
        host, finder = "", self.HOSTNAME_REGEX.match(key)
        if finder is not None:
            host = finder.groupdict().get("host", "")
        return host

    def query_storage(self):
        """Query secrets from keychain storage.
        """

        for each in self.get_secrets().lookup(self.HOSTNAME_PREFIX):
            auth_key, auth = self.find_authority_from_host_key(each)
            host = self.find_hostname_from_host_key(each)
            jump = self.find_jump_auth(auth_key)
            yield (each, host, auth, jump)

    def call_list(self):
        """List handler.

        Outputs:
            stdout: Pager with table-like view of all hostnames.
        """

        known_hosts = [(h, a, j) for _, h, a, j in self.query_storage()]
        counter = -1
        indexes = {}
        sorted_hosts = []
        while len(known_hosts) > 0:
            if counter >= self.MAX_ITER_LIST:
                Log.fatal("Max. iteration over list display reached...")
            host, auth, jump = known_hosts[0]
            counter += 1
            if auth.signature() not in indexes:
                indexes.update({auth.signature(): counter})
            if jump is None:
                sorted_hosts.append(known_hosts.pop(0))
                continue
            jump_index = indexes.get(jump.signature(), -1)
            if jump_index > -1:
                sorted_hosts.insert(jump_index+1, known_hosts.pop(0))
                continue
            known_hosts.insert(len(known_hosts), known_hosts.pop(0))
        Display.show_list_view(sorted_hosts, **self.args)

    def debug_dump(self):
        """Dump all keys from keychain in debug mode.
        """

        for kt, prefix in self.debug_scan(self.args.get("keys")):
            for key in self.get_secrets().lookup(prefix):
                Log.debug("Found {kt} key: {k}", k=key[len(prefix):], kt=kt)

    def debug_purge(self):
        """Permanently unsafe remove keys from keychain. Can corrupt keychain!
        """

        for kt, key in self.debug_scan(self.args.get("keys")):
            Log.debug("Force drop {key_type} key {k} ...", key_type=kt, k=key)
            self.get_secrets().remove(key)

    def debug_scan(self, keys):
        """Scan debug parameters and return appropriate arguments.
        """

        if not isinstance(keys, list):
            error = "Invalid usage of debug option: expected keys to be " \
                    "list of strings, got {t}"
            Log.fatal(error, t=type(keys))
        for key in keys:
            key = "{}!".format(key)
            kt = "unsupported"
            if key.startswith(self.STORAGE_PREFIX):
                kt = "storage"
            elif key.startswith(self.HOSTNAME_PREFIX):
                kt = "host"
            elif key.startswith(self.JUMP_PREFIX):
                kt = "jump"
            yield (kt, key)

    @classmethod
    def use(cls, secrets):
        """Register keychain to manager.

        Args:
            secrets (object): Dict-like object storage.
        """

        cls.__secrets = Keychain(secrets)
