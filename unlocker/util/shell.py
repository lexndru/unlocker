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

from os import environ
from sys import argv
from argparse import ArgumentParser

from unlocker.util.log import Log
from unlocker.util.secret import Secret
from unlocker.util.helper import deploy_unlock_script, deploy_lock_script

from unlocker import __version__


OKAY_MESSAGE = "OK"
HELP_MESSAGE = """
              _            _
  _   _ _ __ | | ___   ___| | _____ _ __
 | | | | '_ \| |/ _ \ / __| |/ / _ \ '__|
 | |_| | | | | | (_) | (__|   <  __/ |
  \__,_|_| |_|_|\___/ \___|_|\_\___|_|

Unlocker v{} - CLI credentials manager

Usage:
  init          Create local keychain
  list          List known hosts from keychain
  recall        Retrieve secrets by name or signature (slower than lookup)
  forget        Forget secrets by name or signature (slower than remove)
  append        Add new set of credentials to keychain
  update        Update password or private key to keychain
  remove        Remove credentials from keychain
  lookup        Find password for provided host, port and user
  install       Install helper scripts
  migrate       Migrate secrets to current unlocker version
""".format(__version__)

SCRIPTS_CREATED = """OK
The following commands are now available:
  unlock  - Establish connection to known servers
  lock    - Encrypt secrets storage"""


class ShellArgumnets(object):

    name = ("-n", "--name"), {
        "help": "A name to recognize it later",
        "dest": "name",
        "action": "store"
    }

    host = ("-h", "--host"), {
        "help": "The hostname or IP address",
        "dest": "host",
        "action": "store"
    }

    port = ("-p", "--port"), {
        "help": "The port number to use for the connection",
        "dest": "port",
        "action": "store",
        "type": int
    }

    user = ("-u", "--user"), {
        "help": "The username to use for the connection",
        "dest": "user",
        "action": "store"
    }

    auth = ("-a", "--auth"), {
        "help": "The authentication method used",
        "dest": "auth",
        "action": "store",
        "choices": ["password", "privatekey"]
    }

    service = ("-s", "--scheme"), {
        "help": "The scheme service name to display (e.g. ssh, http, mysql)",
        "dest": "scheme",
        "action": "store",
    }

    jump_server = ("-j", "--jump-server"), {
        "help": "Optional jump server (or tunnel server) for connections",
        "dest": "jump_server",
        "action": "store",
    }


def get_append_shell(self, header="Add new set of credentials"):
    """Shell getter for "append" option.

    Args:
        header (str): Description header to display on help message.

    Returns:
        Namespace: Parsed arguments namespace for "append" option.
    """

    arguments = self.build_args([
        ShellArgumnets.host, ShellArgumnets.port,
        ShellArgumnets.user, ShellArgumnets.auth
    ], True)
    optional_arguments = self.build_args([
        ShellArgumnets.name, ShellArgumnets.service, ShellArgumnets.jump_server
    ])
    arguments.update(optional_arguments)
    return self.get_parser(arguments, header).parse_args(argv[2:])


def get_update_shell(self, header="Update set of credentials"):
    """Shell getter for "update" option.

    Args:
        header (str): Description header to display on help message.

    Returns:
        Namespace: Parsed arguments namespace for "update" option.
    """

    arguments = self.build_args([
        ShellArgumnets.name, ShellArgumnets.auth
    ], True)
    optional_arguments = self.build_args([
        ShellArgumnets.jump_server
    ])
    arguments.update(optional_arguments)
    return self.get_parser(arguments, header).parse_args(argv[2:])


def get_remove_shell(self, header="Remove credentials from keys database"):
    """Shell getter for "remove" option.

    Args:
        header (str): Description header to display on help message.

    Returns:
        Namespace: Parsed arguments namespace for "remove" option.
    """

    arguments = self.build_args([ShellArgumnets.name], True)
    return self.get_parser(arguments, header).parse_args(argv[2:])


def get_lookup_shell(self, header="Find key for provided user@host:port"):
    """Shell getter for "lookup" option.

    Args:
        header (str): Description header to display on help message.

    Returns:
        Namespace: Parsed arguments namespace for "lookup" option.
    """

    arguments = self.build_args([ShellArgumnets.name], True)
    return self.get_parser(arguments, header).parse_args(argv[2:])


def get_recall_shell(self, header="Retrieve passkey from keychain"):
    """Shell getter for "recall" option.

    Args:
        header (str): Description header to display on help message.

    Returns:
        Namespace: Parsed arguments namespace for "recall" option.
    """

    psr = ArgumentParser(description=header)
    psr.add_argument("signature", help="Authority signature to lookup")
    return psr.parse_args(argv[2:])


def get_forget_shell(self, header="Permanently forget passkey"):
    """Shell getter for "forget" option.

    Args:
        header (str): Description header to display on help message.

    Returns:
        Namespace: Parsed arguments namespace for "forget" option.
    """

    psr = ArgumentParser(description=header)
    psr.add_argument("signature", help="Authority signature to remove")
    return psr.parse_args(argv[2:])


def get_list_shell(self, header="List known hosts from keychain"):
    """Shell getter for "list" option.

    Args:
        header (str): Description header to display on help message.

    Returns:
        Namespace: Parsed arguments namespace for "list" option.
    """

    psr = ArgumentParser(description=header)
    psr.add_argument(
        "-v", "--vertical", action="store_true", dest="vertical",
        help="Display list of hosts vertically (80 columns compatibility)")
    return psr.parse_args(argv[2:])


def get_init_shell(self):
    """Shell getter for "init" option.
    """

    try:
        Secret.get_secret_file()
        print(OKAY_MESSAGE)
    except Exception as e:
        Log.fatal("Aborting due to an error: {e}", e=str(e))
    raise SystemExit


def get_install_shell(self):
    """Shell getter for "install" option.
    """

    try:
        deploy_unlock_script() and deploy_lock_script()
        print(SCRIPTS_CREATED)
    except Exception as e:
        Log.fatal("Aborting due to an error: {e}", e=str(e))
    raise SystemExit


def get_migrate_shell(self):
    """Shell getter for "migrate" option.
    """

    if len(argv[2:]) > 0:
        psr = ArgumentParser(description="Migrate stored secrets")
        grp = psr.add_mutually_exclusive_group()
        grp.add_argument("--import",
                         action="store_true",
                         dest="import_secrets",
                         help="Import secrets from STDIN")
        grp.add_argument("--export",
                         action="store",
                         dest="export_secrets",
                         help="Export secrets to STDOUT",
                         nargs="*")
        return psr.parse_args(argv[2:])
    try:
        Secret.migrate_secrets()
        print(OKAY_MESSAGE)
    except Exception as e:
        Log.fatal("Aborting due to an error: {e}", e=str(e))
    raise SystemExit


def get_dump_shell(self):
    """Shell getter for "dump" option.

    Option available only in debug mode.
    """

    psr = ArgumentParser(description="Dump list of keys (debug mode)")
    psr.add_argument("keys", help="Keys to debug (e.g. host)")
    return psr.parse_args(argv[2:])


def get_purge_shell(self):
    """Shell getter for "purge" option.

    Option available only in debug mode.
    """

    psr = ArgumentParser(description="Drop keys from storage (debug mode)")
    psr.add_argument("keys", help="Keys to drop from keychain", nargs="+")
    return psr.parse_args(argv[2:])


methods = {
    "get_init_shell": get_init_shell,
    "get_list_shell": get_list_shell,
    "get_recall_shell": get_recall_shell,
    "get_forget_shell": get_forget_shell,
    "get_append_shell": get_append_shell,
    "get_update_shell": get_update_shell,
    "get_remove_shell": get_remove_shell,
    "get_lookup_shell": get_lookup_shell,
    "get_install_shell": get_install_shell,
    "get_migrate_shell": get_migrate_shell,
}

if "DEBUG" in environ:
    methods.update({
        "get_dump_shell": get_dump_shell,
        "get_purge_shell": get_purge_shell
    })
    HELP_MESSAGE += """
Debug:
  dump          Dump all entries from keychain
  purge         Force delete key from keychain (can corrupt entire keychain!)
"""

OptionParser = type("OptionParser", (object,), methods)


class ShellParser(OptionParser):
    """Command line arguments wrapper.

    Arguments:
        option (str): Given option to parse (append, remove, lookup).

    Raises:
        SystemExit: If unsupported option is provided.
    """

    def __init__(self):
        self.option = argv[1] if len(argv) > 1 else self.get_help()

    def get_help(self):
        """Print a help message and exit.

        Raises:
            SystemExit: After message is printed.
        """

        print(HELP_MESSAGE)
        raise SystemExit

    def get_args(self):
        """Call supported shell based on given option.

        Raises:
            SystemExit: If an unsupported option is given or not implemented.

        Returns:
            tuple: Option name and mamespace from the called shell.
        """

        try:
            shell = getattr(self, "get_{}_shell".format(self.option))
        except AttributeError:
            return self.get_help()
        if not callable(shell):
            return self.get_help()
        return self.option, shell()

    def get_parser(self, arguments, description="n/a"):
        """Parsed builder and getter based on given option.

        Args:
            arguments  (dict): Dictionary of supported optional arguments.
            description (str): Description to display on help message.

        Returns:
            Parser: Argument parser build for given option with arguments.
        """

        psr = ArgumentParser(description=description, add_help=False)
        for keys, vals in arguments.iteritems():
            short, long_ = keys
            if short is None:
                psr.add_argument(long_, **vals)
            else:
                psr.add_argument(short, long_, **vals)
        psr.add_argument("--help", action="help",
                         help="show this help message and exit")
        return psr

    def build_args(self, args=(), required=False):
        """Arguments builder helper.

        Args:
            args     (iter): Iterable arguments to build.
            required (bool): Whether fields are reqired or not.

        Returns:
            dict: Dictionary of arguments.
        """

        return {k: v.update({"required": required}) or v for k, v in args}
