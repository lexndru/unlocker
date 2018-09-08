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

try:
    from gdbm import open as read_secrets
except ImportError:
    raise SystemExit("Missing dependency: gdbm module")

from os import path, makedirs, environ, chmod
from os.path import expanduser

from unlocker.util.log import Log

from unlocker import __version__


def confidential(func):
    """Adds confidentiality to as arguments.

    Args:
        func (callable): Function or class to pass secrets to.

    Returns:
        callable: Wrapper on top of func.
    """

    def wrapper(**kwargs):

        # Initialize secrets
        db = Secret.get_secret_file()

        # Launch callable with secret arguments
        try:
            if "DEBUG" not in environ:
                try:
                    func(db, **kwargs)
                except Exception as e:
                    raise SystemExit("\nCrashing... {}".format(e))
            else:
                func(db, **kwargs)

        # capture ^C and clean close...
        except KeyboardInterrupt:
            raise SystemExit("\nClosing...")

        # Finally close secret files
        db.close()

    return wrapper


class Secret(object):
    """Unlocker key holder wrapper.

    Arguments:
        unlocker_dir (str): Unlocker directory inside user's home directory.
        secrets_file (str): Key holder filename.
    """

    VERSION = "?"
    UNLOCKER_DIR = ".unlocker"
    SECRETS_FILE = ".secrets"
    SECRETS_LOCK = ".secrets.lock"

    @classmethod
    def get_secret_dir(cls):
        """Used to store keys credentials and configuration files.

        Raises:
            Exception: If application cannot create directory.

        Return:
            unicode: Application secret directory.
        """

        secret_dir = path.join(expanduser("~"), cls.UNLOCKER_DIR)
        Log.debug("Secret directory located at {path}", path=secret_dir)
        try:
            if not path.exists(secret_dir):
                Log.debug("Secret directory does not exist. Creating...")
                makedirs(secret_dir)
                Log.debug("Secret directory successfully created!")
            else:
                Log.debug("Found secret directory...")
        except Exception as e:
            Log.fatal("Failed to create secret directory: {err}", err=str(e))
        return unicode(secret_dir)

    @classmethod
    def get_secret_file(cls):
        """Return or make a sample keys holder.

        Raises:
            Exception: If application cannot read or write file.

        Returns:
            object: Instance of opened secrets file.
        """

        secret_dir = cls.get_secret_dir()
        lockpath = "{}/{}".format(secret_dir, cls.SECRETS_LOCK)
        if path.exists(lockpath):
            Log.fatal("Secrets are locked!\nClosing...")
        fullpath = "{}/{}".format(secret_dir, cls.SECRETS_FILE)
        try:
            secret_file = read_secrets(fullpath, "c")
            chmod(fullpath, 0600)
        except Exception as e:
            Log.fatal("Cannot create secret storage file: {e}", e=str(e))
        try:
            assert secret_file[cls.VERSION]
        except KeyError:
            secret_file[cls.VERSION] = __version__
        except Exception as e:
            Log.fatal("Unsupported secrets driver or {e}", e=str(e))
        if secret_file[cls.VERSION] != __version__:
            error = "Secrets have been stored with a different version " \
                    "of Unlocker (current version {cv}; secrets {vs})\n" \
                    "Closing..."
            Log.fatal(error, cv=__version__, vs=secret_file[cls.VERSION])
        return secret_file

    @classmethod
    def migrate_secrets(cls):
        """Migrate stored secrets from another version to current version.

        Raises:
            Exception: If secrets cannot be migrated.
        """

        fullpath = "{}/{}".format(cls.get_secret_dir(), cls.SECRETS_FILE)
        try:
            secret_file = read_secrets(fullpath, "c")
            secret_file[cls.VERSION] = __version__
            secret_file.close()
        except Exception as e:
            Log.fatal("Cannot migrate secrets because {e}", e=str(e))
