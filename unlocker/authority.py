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
from ipaddress import ip_address, IPv4Address, IPv6Address, AddressValueError
from zlib import crc32

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

    Args:
        host    (int): IP address stored as an integer.
        port    (int): Port number of hostname.
        user    (str): Username assigned to hostname.
        scheme  (str): Connection service scheme (has default; optional).
        ip_addr (str): Resolved hostname to IP address (has default value).

    """

    MIN_PORT, MAX_PORT = 1, (2**16)-1
    MAX_USER_LEN = 32
    DELIMITER, COMPONENTS = ":", 3
    HUMAN_READABLE_FORMAT = u"{scheme}://{user}@{ipv4}:{port}"
    COMPONENTS_FORMAT = u"{host}:{port}:{user}:{scheme}"

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
        except Exception as e:
            Log.warn("Cannot resolve hostname {h}: {e}", e=str(e), h=host)
        try:
            self.host = int(ip_address(self.ip_addr))
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

    def get_user(self):
        """Authority user getter.

        Returns:
            unicode: Connection username.
        """

        if self.user is None:
            Log.fatal("Authority has not set a valid user: unset user")
        return unicode(self.user)

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

    def get_scheme(self):
        """Authority scheme getter.

        Returns:
            unicode: Connection scheme.
        """

        if self.scheme is None:
            Log.fatal("Authority has not set a valid scheme: unset scheme")
        return unicode(self.scheme)

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

    def read(self, human_readable=False):
        """Read authority representation.

        Returns:
            str: Representation of authority.
        """

        if human_readable:
            return self.HUMAN_READABLE_FORMAT.format(
                user=self.user, ipv4=self.get_host_ip4(), port=self.port,
                scheme=self.scheme)
        return self.COMPONENTS_FORMAT.format(
                host=self.host, port=self.port, user=self.user,
                scheme=self.scheme)

    def signature(self):
        """Find the CRC32 hash of current authority.

        Returns:
            str: Calculated CRC for current authority.
        """

        return self.__class__.sign(self.read())

    def __repr__(self):
        return "[{} {}]".format(self.signature(), self.read(True))

    @classmethod
    def sign(cls, data):
        """Calculate CRC32 hash of given data.

        Args:
            data (str): String data to calculate CRC.

        Returns:
            str: Hex value without 0x of the calculated CRC32.
        """

        if not isinstance(data, (str, unicode)):
            Log.fatal("Cannot calculate CRC for non-string data")
        return hex(crc32(data) & 0xFFFFFFFF)[2:]  # skip 0x

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
        try:
            if scheme is not None:
                auth.set_scheme(scheme)
            auth.set_host(host)
            auth.set_port(port)
            auth.set_user(user)
        except Exception as e:
            Log.fatal("Cannot create new authority: {e}", e=str(e))
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
        try:  # fix for non-linux platforms
            host = str(IPv4Address(int(host, 10)))
        except ValueError as e:
            Log.warn("Cannot convert to IP4: {e}", e=str(e))
        except AddressValueError as e:
            Log.fatal("Invalid host address: {e}", e=str(e))
        return cls.new(host, port, user, srv)
