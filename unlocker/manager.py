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

from uuid import uuid4

from unlocker.authority import Authority
from unlocker.keychain import Keychain
from unlocker.database import Database
from unlocker.migrate import Migrate
from unlocker.display import Display

from unlocker.util.service import Service
from unlocker.util.passkey import Passkey
from unlocker.util.log import Log


class Manager(object):
    """Authority secrets manager.

    The Manager is a dispatcher for various call options, such as saving
    passkeys and removing them or lookup.

    There are four possible keys to be accessed by the manager:
      1) storage keys: used to store passkeys (passwords or private keys);
      2) authority keys: used to save authority instances;
      3) host keys: used to keep track of the hostname of an authority;
      4) jump keys: used to keep track of relationships between authorities.

    It's mandatory for the manager to always orchestrate storage, authority and
    host keys. Without there three, the keychain is considered to be corrupted.

    A saved passkey is prefixed with the passkey's type in a "storage key"
    where a storage key is a known named authority.
      let "storage_key" be "storage_prefix" + "named authority"
      e.g. storage_key = passkey_type + actual_passkey

    Authority keys are similar to storage_key, except the content stored is
    compacted by the Authority layer.
      let "auth_key" be "auth_prefix" + "named authority"
      e.g. auth_key = component_authority_formatted_string

    Hostnames are saved in hostnames keys as plain strings.
      let "hostname_key" be "hostname_prefix" + "named authority"
      e.g. hostname_key = localhost

    The optional jump authority keys are saved in jump keys pointing to another
    authority from the keychain. These jump authorities are used for tunneling
    or bouncing.
      let "jump_key" be "jump_prefix" + "named authority"
      e.g. jump_key = another_component_authority_formatted_string

    Arguments:
        __secrets (Keychain): Authority and passwords database.

    Args:
        option     (str): Manager operation to handle.
        args      (dict): Arguments provided to manager.
        auth (Authority): Current authority working with.
    """

    __secrets, __database = None, None

    supported_options = {
        # option        access level
        "migrate":      "read_write",
        "append":       "read_write",
        "update":       "read_write",
        "remove":       "read_write",
        "forget":       "read_write",
        "lookup":       "read_only",
        "recall":       "read_only",
        "list":         "read_only",
        "dump":         "debug_read",
        "purge":        "debug_write",
        "stdout_dump":  "secret_read",
    }

    MAX_ITER_LIST = 2**16
    MIN_NAME_LEN, MAX_NAME_LEN = 10, 42  # meaning of life

    def __init__(self, option, args):
        self.option = option
        self.args = args
        self.auth = None

    @classmethod
    def initialize(cls, secrets):
        """Register keychain to manager's database.

        Args:
            secrets (object): Dict-like object storage.
        """

        cls.__secrets = Keychain(secrets)
        cls.__database = Database(cls.__secrets)
        Log.debug("Manager initialized...")

    def get_secrets(self):
        """Keychain getter.

        Returns:
            Keychain: Passkeys storage.
        """

        if isinstance(self.__secrets, Keychain):
            return self.__secrets
        Log.fatal("Missing keychain: manager not initialized?")

    def get_db(self):
        """Database getter.

        Returns:
            Database: Database storage.
        """

        if isinstance(self.__database, Database):
            return self.__database
        Log.fatal("Missing database: manager not initialized?")

    def build_authority_from_args(self, user, host, port=None, scheme=None):
        """Generate authority from a arguments.

        Args:
            user   (str): The username to attach to authority.
            host   (str): The hostname to resolve and attach to authority.
            port   (int): The port number to attach to authority.
            scheme (str): The connection scheme.

        Raises:
            Exception: If arguments are invalid.

        Returns:
            Authority: The generated authority instance.
        """

        if port is None and scheme is not None:
            port = Service.find_port(scheme)
        if port is not None and scheme is None:
            scheme = Service.find_scheme(port)
        return Authority.new(host, port, user, scheme)

    def build_authority_from_signature(self, signature):
        """Generate authority from a signature.

        Args:
            signature (str): The signature to generate the authority.

        Raises:
            Exception: If no authority matches the signature provided.

        Returns:
            Authority: The authority with the signature provided.
        """

        for each, _ in self.get_db().query_auth():
            if each.signature() == signature:
                return each
        Log.fatal("Cannot find authority for signature {s}", s=signature)

    def build_random_name(self):
        """Generate a random name with 16 characters.

        Returns:
            str: Random 16 characters.
        """

        name = uuid4().hex[:16]
        Log.debug("Generating new random name: {n}", n=name)
        return name

    def call(self):
        """Call dispatcher.

        Handlers option if is identified and supported.

        Raises:
            Exception: If unsupported option is provided.
        """

        if self.option not in self.supported_options:
            Log.fatal("Unsupported option {o}", o=self.option)
        access = self.supported_options[self.option]
        debug_message = "Calling option {opt} with access level {acc}"
        Log.debug(debug_message, opt=self.option, acc=access)
        method = "call_{}_{}_option".format(access, self.option)
        if not hasattr(self, method):
            error = "Unsupported method {option} or access rights {access}"
            Log.fatal(error, option=self.option, access=access)
        return getattr(self, method)(**self.args)

    def call_read_only_recall_option(self, signature, **kwargs):
        """Lookup wrapper without explicit authority.

        Finds authority by signature and calls "lookup" for passkey.

        Args:
            key (str): Possible authority signature to match or name.

        Raises:
            Exception: If named authority does not exists.

        Outputs:
            stdout: Human-readable passkey with authority details and hostname.
        """

        Log.debug("Searching secret passkey for key {s}", s=signature)
        if len(signature) < self.MIN_NAME_LEN:
            Log.debug("Trying key as authority signature...")
            for name, auth, _, _ in self.get_db().query_all():
                if auth.signature() == signature:
                    Log.debug("Got authority with signature {s}", s=signature)
                    signature = name
                    break
        Log.debug("Running a lookup for named authority: {n}", n=signature)
        self.call_read_only_lookup_option(signature)

    def call_read_write_forget_option(self, signature, **kwargs):
        """Remove wrapper without explicit authority.

        Finds authority by signature and calls "remove" for passkey.

        Args:
            key (str): Possible authority signature to match or name.

        Raises:
            Exception: If named authority does not exists.

        Outputs:
            stdout: Human-readable passkey with authority details and hostname.
        """

        Log.debug("Testing if key {s} exists", s=signature)
        if len(signature) < self.MIN_NAME_LEN:
            Log.debug("Trying key as authority signature...")
            for name, auth, _, _ in self.get_db().query_all():
                if auth.signature() == signature:
                    Log.debug("Got authority with signature {s}", s=signature)
                    signature = name
                    break
        Log.debug("Running cleanup after named authority: {n}", n=signature)
        self.call_read_write_remove_option(signature)

    def call_read_write_update_option(self, name, auth, jump_server=None,
                                      **kwargs):
        """Update secrets for an existing named authority.

        Args:
            name (str): The name of the authority to lookup.
            auth (str): Authentification method.

        Raises:
            Exception: If named authority does not exists.

        Outputs:
            stdout: Confirm message with human-readable authority details.
        """

        Log.debug("Incoming update request for named authority {n}", n=name)
        if not self.get_db().exists(name):
            Log.debug("Named authority is not found...")
            error = "Cannot update entry: \"{name}\" not found in " \
                    "keychain (missing key)"
            Log.fatal(error, name=name)
        if jump_server is not None:
            Log.debug("Update requests to change jump server...")
            jump_auth = self.build_authority_from_signature(jump_server)
            self.get_db().update_jump_auth(name, jump_auth)
            Log.debug("New jump set to authority: {a}", a=str(jump_auth))
        passkey = Passkey.resolve(auth)
        self.get_db().update_passkey(name, passkey)
        Log.debug("New passkey set ... ")
        Display.show_update(self.get_db().fetch_auth(name))

    def call_read_write_append_option(self, name, host, port, user, auth,
                                      scheme, jump_server, **kwargs):
        """Append secrets to a named authority.

        Args:
            name        (str): The name of the authority to lookup.
            host        (str): Hostname to attach to authority.
            port        (int): Port number to attach to authority.
            user        (str): Username to attach to authority.
            auth        (str): Authentification method.
            scheme      (str): Scheme of the connection.
            jump_server (str): Name or signature of another authority.

        Raises:
            Exception: If named authority already exists.

        Outputs:
            stdout: Confirm message with human-readable authority details.
        """

        Log.debug("Incoming append request...")
        if name is None:
            name = self.build_random_name()
            Log.warn("Named authority is known as: {n}", n=name)
        elif len(name) < self.MIN_NAME_LEN:
            error = "Possible lookup collision: entry name is too short " \
                    "(name must be at least {size} characters)"
            Log.fatal(error, size=self.MIN_NAME_LEN)
        elif len(name) > self.MAX_NAME_LEN:
            error = "Possible bad naming: entry name is too long " \
                    "(name must be at most {size} characters)"
            Log.fatal(error, size=self.MAX_NAME_LEN)
        elif self.get_db().exists(name):
            error = "Another entry with the same name exists: {name} " \
                    "(name must be unique)"
            Log.fatal(error, name=name)
        data = {
            "name": name,
            "host": host,
            "auth": self.build_authority_from_args(user, host, port, scheme),
        }
        if jump_server is not None:
            data.update({
                "jump_auth": self.build_authority_from_signature(jump_server)
            })
        Log.debug("Preparing to add {args}", args=data)
        self.get_db().add(passkey=Passkey.resolve(auth), **data)
        Log.debug("New named authority is saved...")
        Display.show_append(data.get("auth"))

    def call_read_write_remove_option(self, name, **kwargs):
        """Lookup and remove secrets for a named authority.

        Args:
            name (str): The name of the authority to lookup.

        Raises:
            Exception: If named authority does not exists.

        Outputs:
            stdout: Human-readable passkey with authority details and hostname.
        """

        Log.debug("Incoming remove request for named authority {n}", n=name)
        if not self.get_db().exists(name):
            Log.debug("Nothing to remove...")
            error = "Cannot remove entry: \"{name}\" not found in " \
                    "keychain (missing key)"
            Log.fatal(error, name=name)
        Log.debug("Fetching data for named authority...")
        auth, host, secret = self.get_db().lookup(name)
        dependents = []
        for jump, dep_name in self.get_db().query_jump():
            if jump.signature() == auth.signature():
                debug_message = "Found another authority {a} " \
                                "depending on this... "
                Log.debug(debug_message, a=str(jump))
                dependents.append(dep_name)
        if len(dependents) > 0:
            error = "Not removing entry because {n} other servers bounce of " \
                    "\"{name}\": remove all before trying again (safe mode)"
            Log.fatal(error, n=len(dependents), name=name)
        passtype, passkey = Passkey.copy(secret, True)
        Log.debug("Removing named authority...")
        self.get_db().remove(name)  # remove all keys for named auth
        Log.debug("Permanently removed named authority {n}", n=name)
        Display.show_remove(auth, host, passtype, passkey)

    def call_read_only_lookup_option(self, name, **kwargs):
        """Lookup secrets for a named authority.

        Args:
            name (str): The name of the authority to lookup.

        Raises:
            Exception: If named authority does not exists.

        Outputs:
            stdout: Human-readable passkey with authority details and hostname.
        """

        Log.debug("Incoming lookup request for named authority {n}", n=name)
        if not self.get_db().exists(name):
            Log.debug("Nothing to lookup...")
            error = "Cannot lookup entry: \"{name}\" not found in " \
                    "keychain (missing key)"
            Log.fatal(error, name=name)
        Log.debug("Fetching data for named authority...")
        auth, host, secret = self.get_db().lookup(name)
        passtype, passkey = Passkey.copy(secret, True)
        Log.debug("Printing as safe as possible {n}'s secrets...", n=name)
        Display.show_lookup(auth, host, passtype, passkey)

    def call_read_only_list_option(self, *args, **kwargs):
        """List handler.

        Outputs:
            stdout: Pager with table-like view of all hostnames.
        """

        Log.debug("Incoming list request...")
        known_hosts = [e for e in self.get_db().query_all()]
        counter = -1
        indexes = {}
        sorted_hosts = []
        Log.debug("Found {n} hosts to list...", n=len(known_hosts))
        while len(known_hosts) > 0:
            if counter >= self.MAX_ITER_LIST:
                Log.fatal("Max. iteration over list display reached...")
            name, auth, host, jump = known_hosts[0]
            counter += 1
            if auth.signature() not in indexes:
                indexes.update({auth.signature(): counter})
            if jump is None:
                sorted_hosts.append(known_hosts.pop(0))
                continue
            jump_index = indexes.get(jump.signature(), -1)
            if jump_index > -1:
                if jump_index == 0:
                    jump_index += 1
                sorted_hosts.insert(jump_index, known_hosts.pop(0))
                continue
            known_hosts.insert(len(known_hosts), known_hosts.pop(0))
        Log.debug("Sorted all known hosts and now preparing to print out...")
        Display.show_list_view(sorted_hosts, **self.args)

    def call_read_write_migrate_option(self, *args, **kwargs):
        """Migration wrapper.

        Determine if action is to import or to export and launch process.

        Raises:
            Exception: If something goes terrible wrong.

        Inputs:
            stdin: Compressed import-ready secrets.

        Outputs:
            stdout: Compressed exported stored secrets.
        """

        Log.debug("Incoming migrate request...")
        Migrate.discover(self)
        Log.debug("Migrated data...")

    def call_debug_read_dump_option(self, keys):
        """Dump all keys from keychain in debug mode.
        """

        Log.debug("Incoming debug dump request...")
        for key in keys:
            for k in self.get_secrets().lookup(key):
                key_type = self.get_db().which(k)
                Log.debug(" [{t}] {k}", k=self.get_db().shift(k), t=key_type)
        Log.debug("Closing...")

    def call_debug_write_purge_option(self, keys):
        """Permanently remove keys from keychain in debug mode.

        Can corrupt keychain! (Very unsafe)
        """

        Log.debug("Incoming debug purge request...")
        for key in keys:
            Log.debug("Attempt to remove {k} ...", k=key)
            removed_key = self.get_secrets().remove(key)
            if removed_key is not None:
                Log.debug("Removed {k} ...", k=key)
        Log.debug("Closing...")

    def call_secret_read_stdout_dump_option(self, name, signature, **kwargs):
        """Vulnerable passkey dump to stdout.

        Args:
            name      (str): The name of the authority to lookup.
            signature (str): The signature for an authority to find its name.

        Outputs:
            stdout: Base64 encoded passkey.

        Raises:
            Exception: If unsupported passkey is found.
        """

        def print_passkey(auth_name):
            _, _, secret = self.get_db().lookup(auth_name)
            return "{}\n{}".format(*Passkey.copy(secret))

        passkey = ""  # dummy passkey
        Log.debug("Incoming secret dump request...")
        if len(name) > 0:
            Log.debug("Got named authority {n}...", n=name)
            passkey = print_passkey(name)
        elif len(signature) > 0:
            for each, name in self.get_db().query_auth():
                if each.signature() != signature:
                    continue
                Log.debug("Records matched authority, got passkey...")
                passkey = print_passkey(name)
                break  # exit on first match
        Log.debug("Printing passkey..." if passkey else "Nothing to print...")
        Display.show_dump(passkey)
