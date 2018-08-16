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

from socket import gethostbyname
from ipaddress import ip_address, IPv4Address, IPv6Address

from unlocker.util.log import Log


class Authority(object):
    """Object authority holder.

    Defined by https://tools.ietf.org/html/rfc3986#section-3.2

    Arguments:
        MIN_PORT     (int): min supported port number.
        MAX_PORT     (int): max supported port number.
        MAX_USER_LEN (int): max string length for username.
        DELIMITER    (str): authority delimiter used in string representation.
        COMPONENTS   (int): total number of components in a representation.
    """

    MIN_PORT, MAX_PORT = 1, (2**16)-1
    MAX_USER_LEN = 32
    DELIMITER, COMPONENTS = ":", 3

    def __init__(self):
        self.host, self.port, self.user = None, None, None
        self.scheme = "tcp"
        self.ip_addr = u"0.0.0.0"

    def get_host(self):
        """Authority host getter.

        Returns:
            int: Hostname as integer.
        """

        return self.host

    def get_host_ip4(self):
        """Authority IPv4 host getter.

        Returns:
            unicode: Hostname as IPv4 address.
        """

        return unicode(IPv4Address(self.host))

    def get_host_ip6(self):
        """Authority IPv6 host getter.

        Returns:
            unicode: Hostname as IPv6 address.
        """

        return unicode(IPv6Address(self.host))

    def set_host(self, host):
        """Authority host setter.

        Args:
            host (str): Hostname or IP address to store.

        Raises:
            Exception: if an invalid hostname is provided.
        """

        if not isinstance(host, (str, unicode)):
            Log.fatal("Invalid host: expected string, got {x}", x=type(host))
        try:
            self.ip_addr = unicode(gethostbyname(host))
            Log.debug("Resolved hostname to IP {ip}", ip=self.ip_addr)
        except Exception as e:
            Log.warn("Cannot resolve hostname: {e}", e=str(e))
        try:
            self.host = int(ip_address(self.ip_addr))
            Log.debug("Parsing host as {ip}", ip=self.host)
        except Exception as e:
            Log.fatal("Invalid host: {e}", e=str(e))

    def get_port(self):
        """Authority port getter.

        Returns:
            int: Port number.
        """

        return self.port

    def set_port(self, port):
        """Authority port setter.

        Args:
            port (int): Port number of connection.

        Raises:
            Exception: if an invalid port is provided.
        """

        if isinstance(port, (str, unicode)):
            port = int(port)
        if not isinstance(port, int):
            Log.fatal("Invalid port: expected integer, got {x}", x=type(port))
        if port < self.MIN_PORT or port > self.MAX_PORT:
            Log.fatal("Invalid port: out of range {port}", port=port)
        self.port = port
        Log.debug("Parsing port as {port}", port=port)

    def get_user(self):
        """Authority user getter.

        Returns:
            str: Connection username.
        """

        return self.user

    def set_user(self, user):
        """Authority user setter.

        Args:
            user (str): Username assigned to hostname.

        Raises:
            Exception: if an invalid user is provided.
        """

        if not isinstance(user, (str, unicode)):
            Log.fatal("Invalid user: expected string, got {x}", x=type(user))
        if len(user) == 0:
            Log.fatal("Invalid user: zero-length string not allowed")
        if len(user) > self.MAX_USER_LEN:
            Log.fatal("Invalid user: max length exceeded {v}", v=len(user))
        self.user = user
        Log.debug("Parsing user as {user}", user=user)

    def get_scheme(self):
        """Authority scheme getter.

        Returns:
            str: Connection scheme.
        """

        return self.scheme

    def set_scheme(self, scheme):
        """Authority scheme setter.

        Args:
            scheme (str): Connection service scheme.

        Raises:
            Exception: if an invalid scheme is provided.
        """

        if not isinstance(scheme, (str, unicode)):
            Log.fatal("Invalid scheme: expected string, got {x}",
                      x=type(scheme))
        if len(scheme) == 0:
            Log.fatal("Invalid scheme: zero-length string not allowed")
        self.scheme = scheme
        Log.debug("Parsing scheme as {scheme}", scheme=scheme)

    def read(self, human_readable=False):
        """Read authority representation.

        Returns:
            str: Representation of authority.
        """

        if human_readable:
            return "{}@{}:{}".format(self.user, self.get_host_ip4(), self.port)
        return "{}:{}:{}:{}".format(self.host, self.port, self.user,
                                    self.scheme)

    def __repr__(self):
        return self.read()

    @classmethod
    def new(cls, host, port, user, scheme=None):
        """Create new authority instance.

        Args:
            host   (str): Hostname or IP address as an integer.
            port   (int): Port number of hostname.
            user   (str): Username assigned to hostname.
            scheme (str): Connection service scheme (optional).

        Raises:
            Exception: If required fields are invalid.

        Returns:
            Authority: An authority instance.
        """

        auth = cls()
        auth.set_host(host)
        auth.set_port(port)
        auth.set_user(user)
        if scheme is not None:
            auth.set_scheme(scheme)
        Log.debug("Created new authority... {this}", this=auth)
        return auth

    @classmethod
    def recover(cls, authority):
        """Reconstruct an authority instance from a string representation.

        Args:
            authority (str): A string representation of a stored authority.

        Raises:
            Exception: If required fields are invalid.

        Returns:
            Authority: An authority instance.
        """

        if authority.count(cls.DELIMITER) != cls.COMPONENTS:
            Log.fatal("Cannot recover from an invalid authority")
        host, port, user, srv = authority.split(cls.DELIMITER, cls.COMPONENTS)
        return cls.new(host, port, user, srv)
