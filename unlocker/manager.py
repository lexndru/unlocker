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

from __future__ import print_function

from re import compile, UNICODE
from os import path
from sys import stdin
from base64 import b64encode
from getpass import getpass
from click import echo_via_pager as print_page

from unlocker.authority import Authority
from unlocker.keychain import Keychain
from unlocker.service import Service

from unlocker.util.log import Log


class Manager(object):
    """Authority secrets manager.

    Arguments:
        __secrets (Keychain): Authority and passwords database.

    Args:
        option     (str): Manager operation to handle.
        args      (dict): Arguments provided to manager.
        auth (Authority): Current authority working with.
    """

    __secrets = None

    C_PASSWORD, C_PRIVATE_KEY = "password", "privatekey"
    K_STORAGE, K_HOSTNAME = "$!{key}", "h!{scheme}?{user}@{host}:{port}"
    PK_PASSWORD, PK_PRIV_KEY = ".", ">"
    STORAGE_PREFIX, HOSTNAME_PREFIX = "$!", "h!"

    OR_LIST, OR_LOOKUP = "list", "lookup"
    OW_APPEND, OW_UPDATE, OW_REMOVE = "append", "update", "remove"

    UPDATE_TTY_TEMPLATE = u"""
    Secrets successfully updated!

    {user}@{host}:{port}

    """

    REMOVE_TTY_TEMPLATE = u"""
    Permanently removed secret {auth}!

    \033[91mThis is the last chance to save this secret.\033[0m

    {user}@{host}:{port}    \x1b[0;37;47m{passkey}\x1b[0m

    """

    LOOKUP_TTY_TEMPLATE = u"""
    Secret {auth}

    {user}@{host}:{port}    \x1b[0;37;47m{passkey}\x1b[0m

    """

    LIST_TTY_COLUMNS = (7 + 63 + 21 + 31 + 9)
    LIST_TTY_ROW = u"{scheme:>7} | {host:^63} | {addr:^21} | {user:^31}"

    HOSTNAME_REGEX = compile(
        r"(?P<scheme>.+)\?(?P<user>.+)@(?P<host>.+):(?P<port>\d+)",
        UNICODE)

    def __init__(self, option, args):
        self.option = option
        self.args = args
        self.auth = None

    def make_auth(self):
        """Generate current authority.

        Tries to find port if not provided by known services schemas
        and vice-versa.

        It saves authority into self.auth
        """

        host, user = self.args.get("host"), self.args.get("user")
        port, scheme = self.args.get("port"), self.args.get("scheme")
        if port is None and scheme is not None:
            port = Service.find_port(scheme)
        if port is not None and scheme is None:
            scheme = Service.find_scheme(port)
        self.auth = Authority.new(host, port, user, scheme)

    def call(self):
        """Call dispatcher.

        Handlers option if is identified and supported.

        Raises:
            Exception: If unsupported option is provided.
        """

        if self.option == self.OR_LIST:
            self.call_list()
        elif self.option == self.OR_LOOKUP:
            self.make_auth()
            if stdin.isatty():
                self.call_lookup()
            else:
                self.dump_lookup()
        elif self.option == self.OW_APPEND:
            self.make_auth()
            self.call_update(update_duplicate=False)
        elif self.option == self.OW_UPDATE:
            self.make_auth()
            self.call_update(update_duplicate=True)
        elif self.option == self.OW_REMOVE:
            self.make_auth()
            self.call_remove()
        else:
            Log.fatal("Unsupported option: {o}", o=self.option)

    def get_secrets(self):
        """Keychain getter.

        Returns:
            Keychain: Passkeys storage.
        """

        return self.__secrets

    def get_storage_key(self):
        """Storage key generator and getter.

        Returns:
            str: Storage key formatted with current authority.
        """

        return self.K_STORAGE.format(key=self.auth.read())

    def get_hostname_key(self, host):
        """Hostname key generator and getter.

        Args:
            host (str): Combine host key to generate hostname key.

        Returns:
            str: Hostname key formatted with host.
        """

        return self.K_HOSTNAME.format(
                host=host, user=self.auth.get_user(),
                port=self.auth.get_port(), scheme=self.auth.get_scheme())

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

    def fetch_stored_passkey(self):
        """Stored passkey getter.

        Raises:
            Exception: If passkey is invalid.

        Returns:
            tuple: Passkey type and vulnerable passkey.
        """

        passkey = self.get_secrets().get_value(self.get_storage_key())
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
            print(self.get_password_passkey(b64encode(passkey)))
        elif pk == self.PK_PRIV_KEY:
            print(self.get_priv_key_passkey(b64encode(passkey)))
        else:
            Log.fatal("Error: passkey is neither password, nor private key")

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
        display = self.LOOKUP_TTY_TEMPLATE.format(
                    host=self.auth.get_host_ip4(), port=self.auth.get_port(),
                    user=self.auth.get_user(), auth=auth_type, passkey=passkey)
        print_page(display)

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

    def save_hostname(self):
        """Add host to keychain.

        Raises:
            Exception: If host is not provided.
        """

        host = self.args.get("host")
        if host is None:
            return Log.warn("Hostname is missing (not set)")
        self.get_secrets().update(
            self.get_hostname_key(host), self.get_storage_key())

    def remove_hostname(self, storage_key):
        """Remove host from keychain.

        Args:
            storage_key (str): Storage key to identify hostame.

        Raises:
            Exception: If host is not provided.
        """

        host = self.args.get("host")
        if host is None:
            return Log.warn("Hostname is missing (not set)")
        gen = self.get_secrets().lookup(self.HOSTNAME_PREFIX)
        hostname = self.get_hostname_key(host)
        remove_list = []
        for each in gen:
            if each == hostname:
                remove_list.append(each)
            elif storage_key == self.get_secrets().get_value(each):
                remove_list.append(each)
        for each in remove_list:
            self.get_secrets().remove(each)

    def call_update(self, update_duplicate):
        """Update handler.

        Args:
            update_duplicate (bool): Whether to update or append keys.

        Outputs:
            stdout: Pager with update message.

        Raises:
            Exception: If auth methos is not supported.
        """

        auth = self.args.get("auth", "")
        if auth == self.C_PASSWORD:
            self.save_password(self.read_password(), update=update_duplicate)
        elif auth == self.C_PRIVATE_KEY:
            self.save_privatekey(self.read_pkfile(), update=update_duplicate)
        else:
            Log.fatal("Unsupported auth method...")
        self.save_hostname()
        display = self.UPDATE_TTY_TEMPLATE.format(
                    host=self.auth.get_host_ip4(), port=self.auth.get_port(),
                    user=self.auth.get_user(), auth=auth)
        print_page(display)

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
            self.get_secrets().remove(each)
            self.remove_hostname(each)
            break  # let the user be aware of each item to remove if choosen
        display = self.REMOVE_TTY_TEMPLATE.format(
                    host=self.auth.get_host_ip4(), port=self.auth.get_port(),
                    user=self.auth.get_user(), auth=auth_type, passkey=passkey)
        print_page(display)

    def call_list(self):
        """List handler.

        Outputs:
            stdout: Pager with table-like view of all hostnames.
        """

        gen = self.get_secrets().lookup(self.HOSTNAME_PREFIX)
        shift_host = len(self.HOSTNAME_PREFIX)
        shift_auth = len(self.STORAGE_PREFIX)
        rows = []
        headers = [self.LIST_TTY_ROW.format(scheme="scheme", addr="address",
                                            host="hostname", user="user")]
        for each in gen:
            authority_dump = self.get_secrets().get_value(each)
            auth = Authority.recover(authority_dump[shift_auth:])
            ipv4 = auth.get_host_ip4()
            port = auth.get_port()
            user = auth.get_user()
            scheme = auth.get_scheme()
            hostname = "n/a"
            finder = self.HOSTNAME_REGEX.match(each[shift_host:])
            if finder is not None:
                hostname = finder.groupdict().get("host")
            row = self.LIST_TTY_ROW.format(
                    host=hostname, addr="{}:{}".format(ipv4, port),
                    scheme=scheme, user=user)
            rows.append(row)
        if len(rows) == 0:
            rows.append("Nothing here... try \"unlocker append\"")
        else:
            headers.append("-" * self.LIST_TTY_COLUMNS)
            rows[0:0] = headers
        rows.append("\n")
        return print_page("\n".join(rows))

    @classmethod
    def use(cls, secrets):
        """Register keychain to manager.

        Args:
            secrets (object): Dict-like object storage.
        """

        cls.__secrets = Keychain(secrets)
