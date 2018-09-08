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

from os import environ
from sys import stdout

try:
    if environ.get("NOPAGER", "") == "true":
        raise ImportError("NOPAGER is set")
    from click import echo_via_pager as print_page
except ImportError:
    def print_page(content): stdout.write(content.encode("utf-8"))

from unlocker.util.log import Log


APPEND_TEMPLATE = u"""
  Secrets successfully added!

  {user}@{host}:{port}

""".encode("utf-8")

UPDATE_TEMPLATE = u"""
  Secrets successfully updated!

  {user}@{host}:{port}

""".encode("utf-8")

REMOVE_TEMPLATE = u"""
  Permanently removed secret {auth_type} for {host}!

  \033[91mThis is the last chance to save this secret.\033[0m

  {user}@{ipv4}:{port}    \x1b[0;37;47m{passkey}\x1b[0m

""".encode("utf-8")

LOOKUP_TEMPLATE = u"""
  Secret {auth_type} for {host}

  {user}@{ipv4}:{port}    \x1b[0;37;47m{passkey}\x1b[0m

""".encode("utf-8")

VERTICAL_LIST_TEMPLATE = u"""
{nr:>4}) {name} ({sig}{jump_server})
      Hostname: {host}
      IPv4: {ip}
      Port: {port} ({proto})
      User: {user}
""".encode("utf-8")


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
    def show_lookup(cls, auth, host, pass_type, passkey):
        """Display passkey for lookup message.

        Args:
            auth (Authority): Matched authority.
            host       (str): Matched hostname.
            pass_type  (str): Authentification method.
            passkey    (str): Password or private key.
        """

        if pass_type == "privatekey":
            passkey = "\n" + passkey
        content = LOOKUP_TEMPLATE.format(
            ipv4=auth.get_host_ip4(), port=auth.get_port(), host=host,
            user=auth.get_user(), auth_type=pass_type, passkey=passkey)
        cls.show(content)

    @classmethod
    def show_remove(cls, auth, host, pass_type, passkey):
        """Display passkey for last time in remove message.

        Args:
            auth (Authority): Matched authority.
            host       (str): Matched hostname.
            pass_type  (str): Authentification method.
            passkey    (str): Password or private key.
        """

        content = REMOVE_TEMPLATE.format(
            ipv4=auth.get_host_ip4(), port=auth.get_port(), host=host,
            user=auth.get_user(), auth_type=pass_type, passkey=passkey)
        cls.show(content)

    @classmethod
    def show_append(cls, auth):
        """Display confirmation on append message.

        Args:
            auth (Authority): Matched authority.
        """

        content = APPEND_TEMPLATE.format(
            host=auth.get_host_ip4(), port=auth.get_port(),
            user=auth.get_user())
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
        for name, auth, host, jump in rows:
            jump_server = ""
            if jump is not None:
                jump_server = " => {}".format(jump.signature())
            record = VERTICAL_LIST_TEMPLATE.format(
                       sig=auth.signature(), host=host, ip=auth.get_host_ip4(),
                       port=auth.get_port(), proto=auth.get_scheme(),
                       user=auth.get_user(), nr=len(content) + 1,
                       name=name, jump_server=jump_server)
            if isinstance(record, str):
                record = record.decode("utf-8")
            content.append(record)
        cls.show(content)

    @classmethod
    def show_list_view(cls, rows, vertical, **kwargs):
        """Display records from keychain in a table-like view.

        Args:
            rows     (list): Records from keychain.
            vertical (bool): Whether to display in compatibility mode or not.
        """

        if vertical:
            return cls.show_list_view_vertical(rows)
        if len(rows) == 0:
            return cls.show("Nothing to display...")
        headers = {
            "auth_sig": "hash",
            "jump_sig": "bounce",
            "ip4": "ipv4",
            "port": "port",
            "user": "user",
            "proto": "protocol",
            "host": "hostname",
            "name": "friendly name",
        }
        records = []
        max_host_len = len(headers["host"])
        max_user_len = len(headers["user"])
        max_name_len = len(headers["name"])
        for name, auth, host, jump in rows:
            if len(name) > max_name_len:
                max_name_len = len(name)
            if len(host) > max_host_len:
                max_host_len = len(host)
            if len(auth.get_user()) > max_user_len:
                max_user_len = len(auth.get_user())
            if isinstance(host, str):
                host = host.decode("utf-8")
            if isinstance(name, str):
                name = name.decode("utf-8")
            records.append({
                "auth_sig": auth.signature(),
                "jump_sig": jump.signature() if jump is not None else "~",
                "ip4": auth.get_host_ip4(),
                "port": auth.get_port(),
                "user": auth.get_user(),
                "proto": auth.get_scheme(),
                "host": unicode(host),
                "name": unicode(name),
                "jump": jump is not None
            })
        line = ["{proto:^8}", "{ip4:^15}", "{port:^5}"]
        line.append("{host:^%s}" % max_host_len)
        line.append("{user:^%s}" % max_user_len)
        line.append("{name:^%s}" % max_name_len)
        line_tpl = u" {auth_sig:^10} | {jump_sig:^10} | " + u" | ".join(line)
        content = [line_tpl.format(**headers)]
        separator = {}
        counters = {
            "auth_sig": 10,
            "jump_sig": 10,
            "ip4": 15,
            "port": 5,
            "user": max_user_len,
            "proto": 8,
            "name": max_name_len,
            "host": max_host_len
        }
        for k, v in counters.iteritems():
            separator[k] = unicode(v * "=")
        content.append(line_tpl.format(**separator))
        for record in records:
            row = line_tpl.format(**record)
            if isinstance(row, str):
                row = row.decode("utf-8")
            content.append(row)
        content.append(cls.LINE_SEPARATOR)
        cls.show(content)

    @classmethod
    def show_dump(cls, passkey_dump):
        """Vulnerable passkey dump to stdout.

        Args:
            passkey_dump (str): Base64 passkey dump with type as prefix.

        Outputs:
            stdout: Base64 encoded passkey.
        """

        stdout.write(passkey_dump.strip())
