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

from unlocker.util.log import Log


class Service(object):
    """Services helper class.

    Useful to map missing ports on some services with default known ports.
    """

    services = (
        # scheme    port
        ("http",    80),
        ("https",   443),
        ("kafka",   9092),
        ("mongo",   27017),
        ("mysql",   3306),
        ("neo4j",   7474),
        ("pgql",    5432),
        ("redis",   6379),
        ("rsync",   873),
        ("smtp",    25),
        ("ssh",     22),
        ("ftp",     21),
    )

    @classmethod
    def find_port(cls, service):
        """Find port number for service.

        Args:
            service (str): Service scheme name.

        Raises:
            Exception: If service is not supported.

        Return:
            int: Port number for service.
        """

        for srv, port in cls.services:
            if srv == service:
                return port
        Log.fatal("Unsupported service {s}", s=service)

    @classmethod
    def find_scheme(cls, port):
        """Find scheme for service by port number.

        Args:
            port (int): Service port number.

        Return:
            str: Scheme for service or None.
        """

        for scheme, srv_port in cls.services:
            if int(port) == int(srv_port):
                return scheme
        return None
