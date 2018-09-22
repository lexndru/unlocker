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

from os import path, makedirs, remove
from sys import stdin, stdout
from shutil import rmtree, make_archive
from base64 import b64encode, b64decode
from uuid import uuid4
from zipfile import ZipFile

from unlocker.util.passkey import Passkey
from unlocker.util.log import Log


class Migrate(object):
    """Secrets migration in and out.

    Arguments:
        migrate_format  (str): The temporary file format of archive.
        migrate_tmpdir  (str): Temporary directory to unpack and pack secrets.
        migrate_tmpfile (str): Name of temporary file to unpack and pack.

    Raises:
        Exception: If manager raises any exceptions.
    """

    COLUMNS = 9  # +1 (starts from 0) number of exported/imported columns

    migrate_format = "zip"
    migrate_tmpdir = "/tmp/.x-unlocker"
    migrate_tmpfile = "secrets.list"

    def __init__(self, manager):
        self.manager = manager

    def import_secrets(self):
        """Import secrets wrapper.

        Read and decode from stdin and import authority and passkeys.
        """

        filename = self.get_tmp_filename()
        filepath = self.get_tmp_path(filename)
        with open(filepath, "wb") as fd:
            fd.write(b64decode(stdin.read()))
        with ZipFile(filepath, "r") as zf:
            self.read_tmp_secrets(zf)

    def read_tmp_secrets(self, zf_secrets):
        """Read temporary secrets.

        Args:
            zf_secrets (ZipFile): ZipFile instance with secrets and passkeys.

        Raises:
            SystemExit: If manager crashes or corrupted data are found.
        """

        for each in zf_secrets.read(self.migrate_tmpfile).split("\n"):
            line = each.split("\t", self.COLUMNS)
            if len(line) == 0:
                continue
            _, _, host, ipv4, port, user, scheme, name, ptype, passkey = line
            if ptype not in Passkey.SUPPORTED_TYPES:
                Log.fatal("Unsupported passkey storage {x}", x=ptype)
            authority_args = user, host, port, scheme
            auth = self.manager.build_authority_from_args(*authority_args)
            if ptype == "privatekey":
                passkey = zf_secrets.read(passkey)
            data = {
                "name": name,
                "host": host,
                "auth": auth,
                "passkey": Passkey.SUPPORTED_TYPES.get(ptype) + passkey
            }
            self.manager.get_db().add(**data)
        Log.warn("Unsupported import for jump server, yet")

    def export_secrets(self, records=[]):
        """Export secrets wrapper.

        Loop through all secrets and export authority and passkeys.

        Args:
            records (list): Optional list of named servers to filter on export.

        Raises:
            SystemExit: If there's nothing to export.
        """

        rows = []
        for name, auth, host, jump in self.manager.get_db().query_all():
            if len(records) > 0 and name not in records:
                continue
            ipv4, port = auth.get_host_ip4(), str(auth.get_port())
            user, scheme = auth.get_user(), auth.get_scheme()
            _, _, secret = self.manager.get_db().lookup(name)
            passtype, passkey = Passkey.copy(secret, True)
            if passtype == "privatekey":
                passkey = self.dump_pk_file(passkey, user, host, scheme)
            jump_auth = "."
            if jump is not None:
                jump_auth = jump.signature()
            rows.append((
                auth.signature(),  # auth signature
                jump_auth,         # jump signature if any
                host,              # hostname
                ipv4,              # IPv4 address
                port,              # port number
                user,              # username
                scheme,            # connection scheme
                name,              # authority name
                passtype,          # passkey type
                passkey            # actual passkey or path to passkey
            ))
        if len(rows) == 0:
            Log.fatal("Nothing to export...")
        self.flush_secrets(rows)

    def flush_secrets(self, content):
        """Flush secrets to stdout.

        It creates additional files for private keys whenever needed. Files
        are deleted after they are flushed to stdout.

        Args:
            content (str): Content with secrets to write to file.
        """

        # write all secrets to file...
        with open(self.get_tmp_path(self.migrate_tmpfile), "wb") as fd:
            safe_content = []
            for ctx in content:
                line = []
                for each in ctx:
                    if isinstance(each, str):
                        each = each.decode("utf-8")
                    line.append(each)
                safe_content.append("\t".join(line))
            fd.write("\n".join(safe_content).encode("utf-8"))

        # create temporary archive and flush it's content to stdout
        exp_pkg = "/tmp/{}".format(self.get_tmp_filename())
        make_archive(exp_pkg, self.migrate_format, self.migrate_tmpdir)
        with open("{}.{}".format(exp_pkg, self.migrate_format), "rb") as fd:
            stdout.write(b64encode(fd.read()))

        # cleanup
        remove("{}.{}".format(exp_pkg, self.migrate_format))

    def get_tmp_filename(self):
        """Temporary filename getter.

        Generates a filename for temporary storage.

        Returns:
            str: Temporary filename.
        """

        return str(uuid4().hex.upper())

    def get_tmp_path(self, filename):
        """Temporary path getter.

        Returns path to migration temporary directory.

        Args:
            filename (str): Name of file from temp directory.

        Returns:
            str: Path to file from temporary directory.
        """

        return "{}/{}".format(self.migrate_tmpdir, filename)

    def create_pk_file(self, user, hostname, scheme):
        """Create a private key filename.

        Args:
            user   (str): Username from Authority.
            host   (str): Hostname from Authority.
            scheme (str): Scheme from Authority.

        Returns:
            str: Filename for private key.
        """

        return "{}_{}_{}.pk".format(user, hostname, scheme)

    def dump_pk_file(self, passkey, user, host, scheme):
        """Write private key to file and return file name.

        Args:
            passkey (str): Passkey as private key to write to file.
            user    (str): Username from Authority.
            host    (str): Hostname from Authority.
            scheme  (str): Scheme from Authority.

        Returns:
            str: Name of file with private key.

        """

        filename = self.create_pk_file(user, host, scheme)
        with open(self.get_tmp_path(filename), "wb") as fd:
            fd.write(passkey)
        return filename

    @classmethod
    def discover(cls, manager):
        """
        Args:
            manager (Manager): Manager instance.

        Raises:
            SystemExit: If invalid options are provided.
        """

        import_secrets = manager.args.get("import_secrets")
        export_secrets = manager.args.get("export_secrets")

        # fail fast if no options is provided...
        if import_secrets is not True and not isinstance(export_secrets, list):
            Log.fatal("Unexpected migrate request...")

        # create tmp dir if not eixsts...
        if not path.exists(cls.migrate_tmpdir):
            makedirs(cls.migrate_tmpdir)

        # run migration
        mig = cls(manager)
        if import_secrets is True:
            if stdin.isatty():
                Log.fatal("Migration failed: stdin is empty")
            mig.import_secrets()
        elif isinstance(export_secrets, list) and len(export_secrets) >= 0:
            if stdout.isatty():
                Log.fatal("Migration failed: stdout is empty")
            mig.export_secrets(records=export_secrets)

        # cleanup
        rmtree(cls.migrate_tmpdir)
