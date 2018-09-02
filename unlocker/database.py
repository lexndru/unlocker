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

from unlocker.keychain import Keychain
from unlocker.authority import Authority

from unlocker.util.secret import Secret
from unlocker.util.log import Log


class Database(object):
    """Database common interface.

    Supports high-level and quick access to keychain.
    """

    # used by version key
    VERSION = Secret.VERSION

    # used as second character after a key type prefix
    SEPARATOR = "!"

    # key type prefix (storage, auth, host, jump)
    PASS, AUTH, HOST, JUMP = "$", "A", "h", "j"

    # minimum length of a prefix with separator
    PREFIX_FIXED_LEN = 2

    def __init__(self, storage):
        if not isinstance(storage, Keychain):
            Log.fatal("Unexpected database storage {t}", t=type(storage))
        self.storage = storage
        Log.debug("Database initialized...")
        Log.debug("Storage status: {k}", k=str(storage))

    def exists(self, name):
        """Tests whether a named authority exists in keychain.

        Args:
            name (str): Full name of the authority to test.

        Returns:
            bool: True if named authority exists, otherwise False.
        """

        return self.storage.has(self.get_pass_key(name))

    def add_passkey(self, name, passkey):
        """Create new passkey for a named authority.

        Args:
            name    (str): Full name of the authority to add.
            passkey (str): Processed passkey to save to keychain.

        Raises:
            Exception: If named authority already exists in keychain.
        """

        if self.exists(name):
            Log.fatal("Cannot add passkey on a duplicate entry")
        self.update_passkey(name, passkey)

    def add_auth(self, name, auth):
        """Create new authority for self named authority.

        Args:
            name       (str): Full name of the authority to add.
            auth (Authority): Authority instance to save to keychain.

        Raises:
            Exception: If named authority already exists in keychain.
        """

        if self.storage.has(self.get_auth_key(name)):
            Log.fatal("Cannot add authority on a duplicate entry")
        if not isinstance(auth, Authority):
            Log.fatal("Expected auth to be authority, got {t}", t=type(auth))
        self.storage.add(self.get_auth_key(name), auth.read())

    def add_host(self, name, host):
        """Create new hostname for named authority.

        Args:
            name (str): Full name of the authority to add.
            host (str): Hostname to save to keychain.

        Raises:
            Exception: If named authority already exists in keychain.
        """

        if self.storage.has(self.get_host_key(name)):
            Log.fatal("Cannot add hostname on a duplicate entry")
        self.storage.add(self.get_host_key(name), host)

    def add_jump(self, name, auth):
        """Create new jump authority for named authority.

        Args:
            name       (str): Full name of the authority to add.
            auth (Authority): Jump authority instance to save to keychain.

        Raises:
            Exception: If named authority already exists in keychain.
        """

        if self.storage.has(self.get_jump_key(name)):
            Log.fatal("Cannot add jump server on a duplicate entry")
        if not isinstance(auth, Authority):
            Log.fatal("Expected jump to be authority, got {t}", t=type(auth))
        self.storage.add(self.get_jump_key(name), auth.read())

    def update_passkey(self, name, passkey):
        """Update passkey for existing named authority.

        Args:
            name    (str): Full name of the authority to add.
            passkey (str): New processed passkey to replace the old passkey.

        Raises:
            Exception: If passkey is zero-length.
        """

        if len(passkey) == 0:
            Log.fatal("Passkey cannot be empty")
        self.storage.update(self.get_pass_key(name), passkey)

    def update_jump_auth(self, name, auth):
        """Update passkey for existing named authority.

        Args:
            name       (str): Full name of the authority to add.
            auth (Authority): New authority as jump server.

        Raises:
            Exception: If provided argument is not Authority.
        """

        if not isinstance(auth, Authority):
            Log.fatal("Expected authority instance, got {t}", t=type(auth))
        self.storage.update(self.get_jump_key(name), auth.read())

    def add(self, name, passkey, auth, host=None, jump_auth=None):
        """Create entry for named authority.

        Args:
            name            (str): Full name of the authority to add.
            passkey         (str): Processed passkey to save to keychain.
            auth      (Authority): Authority instance to save to keychain.
            host            (str): Hostname to save to keychain.
            jump_auth (Authority): Jump authority instance to save to keychain.

        Raises:
            Exception: If any of the methods raise an exception.
        """

        self.add_passkey(name, passkey)
        self.add_auth(name, auth)
        if host is not None:
            self.add_host(name, host)
        if jump_auth is not None:
            self.add_jump(name, jump_auth)

    def remove_passkey(self, name):
        """Remove storage key containing passkey from keychain.

        Args:
            name (str): Full name of the authority to remove.

        Outputs:
            stdout: Prints a warning if the storage key is not found.

        Returns:
            mixt: The passkey just removed (if found) or None.
        """

        return self.storage.remove(self.get_pass_key(name))

    def remove_auth(self, name):
        """Remove authority key containing authority from keychain.

        Args:
            name (str): Full name of the authority to remove.

        Outputs:
            stdout: Prints a warning if the authority key is not found.

        Returns:
            mixt: The authority just removed (if found) or None.
        """

        return self.storage.remove(self.get_auth_key(name))

    def remove_host(self, name):
        """Remove hostname key containing hostname from keychain.

        Args:
            name (str): Full name of the authority to remove.

        Outputs:
            stdout: Prints a warning if the hostname key is not found.

        Returns:
            mixt: The hostname just removed (if found) or None.
        """

        return self.storage.remove(self.get_host_key(name))

    def remove_jump(self, name):
        """Remove jump authority key containing authority from keychain.

        Args:
            name (str): Full name of the authority to remove.

        Outputs:
            stdout: Prints a warning if the jump authority key is not found.

        Returns:
            mixt: The jump authority just removed (if found) or None.
        """

        return self.storage.remove(self.get_jump_key(name))

    def remove(self, name):
        """Remove all keys from keychain for a named authority.

        Args:
            name (str): Full name of the authority to remove.

        Outputs:
            stdout: Prints a warning if a key is not found.

        Raises:
            Exception: If any of the methods used raise an exception.
        """

        if self.storage.has(self.get_jump_key(name)):
            self.remove_jump(name)
        self.remove_host(name)
        self.remove_auth(name)
        self.remove_passkey(name)

    def fetch(self, name, query, key_name="name"):
        """Retieve entry from keychain for a named authority.

        Args:
            name       (str): Full name of the authority to fetch.
            query (callable): Query callable to filter for `name`.
            key_name   (str): Placeholder key for message to output.

        Raises:
            Exception: If entry is not found or query is not callable.

        Returns:
            mixt: Entry to retrieve.
        """

        if not callable(query):
            Log.fatal("Cannot fetch with an invalid query")
        for each, name_ in query():
            if name_ == name:
                return each
        Log.fatal("Cannot fetch unexisting {k}: {n}", n=name, k=key_name)

    def fetch_auth(self, name):
        """Retieve authority from keychain for a named authority.

        Args:
            name (str): Full name of the authority to fetch.

        Raises:
            Exception: If entry is not found or query is not callable.

        Returns:
            Authority: Authority to retrieve.
        """

        return self.fetch(name, self.query_auth, "authority")

    def fetch_host(self, name):
        """Retieve hostname from keychain for a named authority.

        Args:
            name (str): Full name of the authority to fetch.

        Raises:
            Exception: If entry is not found or query is not callable.

        Returns:
            str: Hostname to retrieve.
        """

        return self.fetch(name, self.query_host, "hostname")

    def fetch_jump(self, name):
        """Retieve jump authority from keychain for a named authority.

        Args:
            name (str): Full name of the authority to fetch.

        Raises:
            Exception: If entry is not found or query is not callable.

        Returns:
            Authority: Jump authority to retrieve.
        """

        return self.fetch(name, self.query_jump, "jump server")

    def query(self, key_type_prefix):
        """Query secrets from keychain storage.

        Args:
            key_type_prefix (str): Prefix to partial match in lookup.

        Yields:
            mixt: Entry for each matched found.
        """

        for each in self.storage.lookup(key_type_prefix):
            if each == self.VERSION:
                continue
            if self.storage.get_value(each).strip() == "":
                Log.fatal("Storage contains empty value for key {k}", k=each)
            yield each

    def query_auth(self):
        """Query authorities from keychain storage.

        Yields:
            tuple: Authority instance and the named key.
        """

        for each in self.query(self.get_auth_prefix()):
            name = self.shift(each)
            yield Authority.recover(self.storage.get_value(each)), name

    def query_host(self):
        """Query hostnames from keychain storage.

        Yields:
            tuple: Hostname and the named key.
        """

        for each in self.query(self.get_host_prefix()):
            name = self.shift(each)
            yield self.storage.get_value(each), name

    def query_jump(self):
        """Query jump authorities from keychain storage.

        Yields:
            tuple: Jump authority instance and the named key.
        """

        for each in self.query(self.get_jump_prefix()):
            name = self.shift(each)
            yield Authority.recover(self.storage.get_value(each)), name

    def query_all(self):
        """Query everything in relation to authority from keychain storage.

        Yields:
            tuple: The named key, authority instance, hostname and jump auth.
        """

        for each in self.query(self.get_pass_prefix()):
            if len(each) <= self.PREFIX_FIXED_LEN:
                continue
            name = self.shift(each)
            auth = self.storage.get_value(self.get_auth_key(name))
            authority = Authority.recover(auth)
            host = None
            if self.storage.has(self.get_host_key(name)):
                host = self.storage.get_value(self.get_host_key(name))
            jump_auth = None
            if self.storage.has(self.get_jump_key(name)):
                jump = self.storage.get_value(self.get_jump_key(name))
                jump_auth = Authority.recover(jump)
            yield name, authority, host, jump_auth

    def lookup(self, lookup_name):
        """Lookup a named authority and return self, hostname and secret.

        Args:
            lookup_name (str): The name of the authority to find.

        Raises:
            Exception: If authority is not found.

        Returns:
            tuple: Authority instance, hostname and secret passkey.
        """

        for name, auth, host, jump in self.query_all():
            if name == lookup_name:
                secret = self.storage.get_value(self.get_pass_key(name))
                return auth, host, secret
        Log.fatal("Nothing found for name {n}", n=lookup_name)

    def shift(self, string):
        """Shift to the right a sting to remove any prefix.

        Args:
            string (str): String to be shifted.

        Raises:
            Exeption: If provided argument is not a string.

        Returns:
            str: New shifted string without prefix.
        """

        if isinstance(string, (str, unicode)):
            return string[self.PREFIX_FIXED_LEN:]
        Log.fatal("Unsupported shift operation on {t}", t=type(string))

    def get_prefix(self, prefix):
        """Prefix getter. Appends a separator and returns prefix.

        Args:
            prefix (str): The prefix to return.

        Raises:
            Exception: If size of prefix exceeds.

        Returns:
            str: New string of prefix with separator.
        """

        key = prefix + self.SEPARATOR
        if len(key) != self.PREFIX_FIXED_LEN:
            Log.fatal("Invalid prefixed key length, got {v}", v=len(key))
        return key

    def get_pass_key(self, key):
        """Passkey generator and getter.

        Args:
            key (str): Key to format and return with prefix.

        Returns:
            str: Prefixed passkey with storage key prefix.
        """

        return "{}{}".format(self.get_pass_prefix(), key)

    def get_pass_prefix(self):
        """Passkey prefix getter.

        Returns:
            str: Prefix for storage key.
        """

        return self.get_prefix(self.PASS)

    def get_host_key(self, key):
        """Hostname generator and getter.

        Args:
            key (str): Key to format and return with prefix.

        Returns:
            str: Prefixed hostname with host key prefix.
        """

        return "{}{}".format(self.get_host_prefix(), key)

    def get_host_prefix(self):
        """Hostname prefix getter.

        Returns:
            str: Prefix for hostname key.
        """

        return self.get_prefix(self.HOST)

    def get_jump_key(self, key):
        """Jump generator and getter.

        Args:
            key (str): Key to format and return with prefix.

        Returns:
            str: Prefixed jump authority with jump key prefix.
        """

        return "{}{}".format(self.get_jump_prefix(), key)

    def get_jump_prefix(self):
        """Jump prefix getter.

        Returns:
            str: Prefix for jump key.
        """

        return self.get_prefix(self.JUMP)

    def get_auth_key(self, key):
        """Authority generator and getter.

        Args:
            key (str): Key to format and return with prefix.

        Returns:
            str: Prefixed authority with auth key prefix.
        """

        return "{}{}".format(self.get_auth_prefix(), key)

    def get_auth_prefix(self):
        """Authority prefix getter.

        Returns:
            str: Prefix for authority key.
        """

        return self.get_prefix(self.AUTH)

    def which(self, key):
        """Determine the type of a key.

        Args:
            key (str): Key to determine type.

        Returns:
            str: Type of key if supported, otherwise "unsupported".
        """

        if key.startswith(self.PASS):
            return "storage"
        elif key.startswith(self.AUTH):
            return "authority"
        elif key.startswith(self.HOST):
            return "hostname"
        elif key.startswith(self.JUMP):
            return "jump server"
        return "unsupported"
