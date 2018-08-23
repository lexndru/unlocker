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
            line = each.split("\t")
            if len(line) == 0:
                continue
            scheme, host, ipv4, port, user, atype, passkey = line
            self.manager.args = {
                "scheme": scheme, "host": ipv4, "port": port, "user": user
            }
            self.manager.make_auth()
            if atype == self.manager.C_PASSWORD:
                method = "save_password"
            elif atype == self.manager.C_PRIVATE_KEY:
                method = "save_privatekey"
                passkey = zf_secrets.read(passkey)
            else:
                Log.fatal("Unsupported passkey storage {x}", x=atype)
            if not hasattr(self.manager, method):
                Log.fatal("Unsupported passkey method")
            getattr(self.manager, method)(passkey)
            self.manager.save_hostname(host)

    def export_secrets(self):
        """Export secrets wrapper.

        Loop through all secrets and export authority and passkeys.

        Raises:
            SystemExit: If there's nothing to export.
        """

        rows = []
        for key, auth, host in self.manager.query_storage():
            authority_dump = self.manager.get_secrets().get_value(key)
            ptype, passkey = self.manager.fetch_stored_passkey(authority_dump)
            ipv4 = auth.get_host_ip4()
            port = str(auth.get_port())
            user = auth.get_user()
            scheme = auth.get_scheme()
            atype = "unsupported"
            if self.manager.is_password(ptype):
                atype = self.manager.C_PASSWORD
            elif self.manager.is_private_key(ptype):
                atype = self.manager.C_PRIVATE_KEY
                passkey = self.dump_pk_file(passkey, user, host, scheme)
            rows.append((scheme, host, ipv4, port, user, atype, passkey))
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
            fd.write("\n".join(["\t".join(r) for r in content]))

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
        if not import_secrets and not export_secrets:
            Log.fatal("Unexpected migrate request...")

        # create tmp dir if not eixsts...
        if not path.exists(cls.migrate_tmpdir):
            makedirs(cls.migrate_tmpdir)

        # run migration
        mig = cls(manager)
        if import_secrets:
            if stdin.isatty():
                Log.fatal("Migration failed: stdin is empty")
            mig.import_secrets()
        elif manager.args.get("export_secrets"):
            if stdout.isatty():
                Log.fatal("Migration failed: stdout is empty")
            mig.export_secrets()

        # cleanup
        rmtree(cls.migrate_tmpdir)
