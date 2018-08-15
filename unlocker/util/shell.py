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

from sys import argv
from argparse import ArgumentParser

from unlocker.util.log import Log
from unlocker.util.secret import Secret
from unlocker.util.helper import deploy_unlock_script, deploy_lock_script

from unlocker import __version__


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
  append        Add new set of credentials to keychain
  update        Update or add set of credentials to keychain
  remove        Remove credentials from keychain
  lookup        Find password for provided host, port and user
  addons        Install helper scripts
  migrate       Migrate secrets to current unlocker version
""".format(__version__)


class ShellArgumnets(object):

    host = ("-H", "--host"), {
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

    service = (None, "--scheme"), {
        "help": "The scheme service name to display (e.g. ssh, http, mysql)",
        "dest": "scheme",
        "action": "store",
    }


class ShellParser(object):
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

        psr = ArgumentParser(description=description)
        for keys, vals in arguments.iteritems():
            short, long_ = keys
            if short is None:
                psr.add_argument(long_, **vals)
            else:
                psr.add_argument(short, long_, **vals)
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
        arguments.update(self.build_args([ShellArgumnets.service]))
        return self.get_parser(arguments, header).parse_args(argv[2:])

    def get_update_shell(self, header="Update set of credentials"):
        """Shell getter for "update" option.

        Args:
            header (str): Description header to display on help message.

        Returns:
            Namespace: Parsed arguments namespace for "update" option.
        """

        arguments = self.build_args([
            ShellArgumnets.host, ShellArgumnets.port,
            ShellArgumnets.user, ShellArgumnets.auth
        ], True)
        arguments.update(self.build_args([ShellArgumnets.service]))
        return self.get_parser(arguments, header).parse_args(argv[2:])

    def get_remove_shell(self, header="Remove credentials from keys database"):
        """Shell getter for "remove" option.

        Args:
            header (str): Description header to display on help message.

        Returns:
            Namespace: Parsed arguments namespace for "remove" option.
        """

        arguments = self.build_args([
            ShellArgumnets.host, ShellArgumnets.port, ShellArgumnets.user
        ], True)
        arguments.update(self.build_args([ShellArgumnets.service]))
        return self.get_parser(arguments, header).parse_args(argv[2:])

    def get_lookup_shell(self, header="Find key for provided user@host:port"):
        """Shell getter for "lookup" option.

        Args:
            header (str): Description header to display on help message.

        Returns:
            Namespace: Parsed arguments namespace for "lookup" option.
        """

        arguments = self.build_args([
            ShellArgumnets.host, ShellArgumnets.port, ShellArgumnets.user
        ], True)
        arguments.update(self.build_args([ShellArgumnets.service]))
        return self.get_parser(arguments, header).parse_args(argv[2:])

    def get_list_shell(self, header="List known hosts from keychain"):
        """Shell getter for "list" option.

        Args:
            header (str): Description header to display on help message.

        Returns:
            Namespace: Parsed arguments namespace for "list" option.
        """

        arguments = self.build_args([
            ShellArgumnets.host, ShellArgumnets.service
        ])
        return self.get_parser(arguments, header).parse_args(argv[2:])

    def get_init_shell(self):
        """Shell getter for "init" option.
        """

        try:
            Secret.get_secret_file()
        except Exception as e:
            Log.fatal("Aborting due to an error: {e}", e=str(e))
        raise SystemExit

    def get_addons_shell(self):
        """Shell getter for "addons" option.
        """

        try:
            deploy_unlock_script() and deploy_lock_script()
        except Exception as e:
            Log.fatal("Aborting due to an error: {e}", e=str(e))
        raise SystemExit

    def get_migrate_shell(self):
        """Shell getter for "migrate" option.
        """

        try:
            Secret.migrate_secrets()
        except Exception as e:
            Log.fatal("Aborting due to an error: {e}", e=str(e))
        raise SystemExit
