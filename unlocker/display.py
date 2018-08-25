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

try:
    from click import echo_via_pager as print_page
except ImportError:
    def print_page(content): print(content)

from unlocker.util.log import Log


UPDATE_TEMPLATE = u"""
  Secrets successfully updated!

  {user}@{host}:{port}

"""

REMOVE_TEMPLATE = u"""
  Permanently removed secret {auth_type}!

  \033[91mThis is the last chance to save this secret.\033[0m

  {user}@{host}:{port}    \x1b[0;37;47m{passkey}\x1b[0m

"""

LOOKUP_TEMPLATE = u"""
  Secret {auth_type}

  {user}@{host}:{port}    \x1b[0;37;47m{passkey}\x1b[0m

"""

VERTICAL_LIST_TEMPLATE = u"""
{nr:>4}) {sig} {jump_server}
      Hostname: {host}
      IPv4: {ip}
      Port: {port} ({proto})
      User: {user}
"""


class Display(object):
    """Pretty display manager.

    Used to display messages on read/write actions triggered by Manager.
    """

    DEFAULT_MESSAGE = "Nothing to show..."
    LINE_SEPARATOR = "\n"

    @classmethod
    def show(cls, content=None):
        """Display content in pager or flush to stdout.

        Args:
            content (mixt): Content to output.

        Raises:
            Exception: If unsupported content is provided.

        Output:
            stdout: Content via pager if supported.
        """

        if content is None:
            content = cls.DEFAULT_MESSAGE
        if isinstance(content, (list, tuple, set)):
            content = cls.LINE_SEPARATOR.join(content)
        if not isinstance(content, (str, unicode)):
            Log.fatal("Cannot display non-string content")
        print_page(content)

    @classmethod
    def show_lookup(cls, auth, auth_type, passkey):
        """Display passkey for lookup message.

        Args:
            auth (Authority): Matched authority.
            auth_type  (str): Authentification method.
            passkey    (str): Password or private key.
        """

        content = LOOKUP_TEMPLATE.format(
            host=auth.get_host_ip4(), port=auth.get_port(),
            user=auth.get_user(), auth_type=auth_type, passkey=passkey)
        cls.show(content)

    @classmethod
    def show_remove(cls, auth, auth_type, passkey):
        """Display passkey for last time in remove message.

        Args:
            auth (Authority): Matched authority.
            auth_type  (str): Authentification method.
            passkey    (str): Password or private key.
        """

        content = REMOVE_TEMPLATE.format(
            host=auth.get_host_ip4(), port=auth.get_port(),
            user=auth.get_user(), auth_type=auth_type, passkey=passkey)
        cls.show(content)

    @classmethod
    def show_update(cls, auth):
        """Display confirmation on update message.

        Args:
            auth (Authority): Matched authority.
        """

        content = UPDATE_TEMPLATE.format(
            host=auth.get_host_ip4(), port=auth.get_port(),
            user=auth.get_user())
        cls.show(content)

    @classmethod
    def show_list_view_vertical(cls, rows, **kwargs):
        """Display records from keychain in less than 80 chars per line.

        Args:
            rows (list): Records from keychain.
        """

        content = []
        for host, auth, jump in rows:
            jump_server = ""
            if jump is not None:
                jump_server = "=> {}".format(jump.signature())
            record = VERTICAL_LIST_TEMPLATE.format(
                       sig=auth.signature(), host=host, ip=auth.get_host_ip4(),
                       port=auth.get_port(), proto=auth.get_scheme(),
                       user=auth.get_user(), nr=len(content) + 1,
                       jump_server=jump_server)
            content.append(record)
        cls.show(content)

    @classmethod
    def show_list_view(cls, rows, column, exclude, vertical, **kwargs):
        """Display records from keychain in a table-like view.

        Args:
            rows     (list): Records from keychain.
            columns  (list): Columns to display.
            exclude  (bool): Whether to exclude columns or not.
            vertical (bool): Whether to display in compatibility mode or not.
        """

        if vertical:
            ignore_message = "Ignoring {} options in compatibility mode"
            ignore_items = []
            if len(column) > 0:
                ignore_items.append("columns")
            if exclude:
                ignore_items.append("exclude")
            if len(ignore_items) > 0:
                Log.warn(ignore_message.format("/".join(ignore_items)))
            return cls.show_list_view_vertical(rows)
        headers = {
            "sig": "hash",
            "ip4": "ipv4",
            "port": "port",
            "user": "user",
            "proto": "protocol",
            "host": "hostname"
        }
        records = []
        max_host_len, max_user_len = len(headers["host"]), len(headers["user"])
        for host, auth, jump in rows:
            if len(host) > max_host_len:
                max_host_len = len(host)
            if len(auth.get_user()) > max_user_len:
                max_user_len = len(auth.get_user())
            records.append({
                "sig": auth.signature(),
                "ip4": auth.get_host_ip4(),
                "port": auth.get_port(),
                "user": auth.get_user(),
                "proto": auth.get_scheme(),
                "host": host,
                "jump": jump is not None
            })
        line = ["{proto:^8}", "{ip4:^15}", "{port:^5}"]
        line.append("{host:^%s}" % max_host_len)
        line.append("{user:^%s}" % max_user_len)
        line_template = u" {sig:^10} %s " + u" | ".join(line)
        content = [cls.bind_params(line_template).format(**headers)]
        separator = {
            "sig": 10,
            "ip4": 15,
            "port": 5,
            "user": max_user_len,
            "proto": 8,
            "host": max_host_len
        }
        for k, v in separator.iteritems():
            separator[k] = str(v * "=")
        content.append(cls.bind_params(line_template).format(**separator))
        for record in records:
            row = cls.bind_params(line_template, record.get("jump"))
            content.append(row.format(**record))
        content.append(cls.LINE_SEPARATOR)
        if len(records) == 0:
            content = ["Nothing to display... try \"append\" or \"update\""]
        cls.show(content)

    @classmethod
    def bind_params(cls, line_template, subparam=False):
        """Helper function to draw a special char for servers using tunnels.

        Args:
            line_template (str): Template string to format.
            subparam     (bool): Whether to draw special char or not.

        Returns:
            str: Template string to be formated.
        """

        return line_template % (u"\u2514" if subparam else "|")
