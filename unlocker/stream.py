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

from sys import argv, stdin
from re import compile, UNICODE

from unlocker.util.log import Log


AUTHORITY_REGEXPR = "(?:(?P<scheme>.+)://)?" \
                    "(?:(?P<user>.+?)@)?" \
                    "(?P<host>[\da-zA-Z\-\.]+)" \
                    "(?:\:(?P<port>\d+))?"


class StreamData(object):
    """Standard stream data wrapper.

    Arguments:
        buf_in (str): Input buffer used to store piped stdin.
    """

    buf_in = None
    OPTION = "stdout_dump"

    @classmethod
    def read(cls):
        """Check if authority is piped.

        Returns:
            bool: True if data is piped, otherwise False.
        """

        if len(argv) > 1:
            return False
        if not stdin.isatty():
            cls.buf_in = stdin.read()
            return len(cls.buf_in) > 0
        return False

    @classmethod
    def parse(cls, service):
        """Parse input buffer.

        Args:
            service (Service): Service instance.

        Returns:
            dict: Dictionary of parsed authority.
        """

        exp = compile(AUTHORITY_REGEXPR, UNICODE)
        matches = exp.match(cls.buf_in)
        if matches is None:
            error = "Unsupported authority, must be complied with " \
                    "https://tools.ietf.org/html/rfc3986#section-3.2"
            Log.fatal(error)
        args = matches.groupdict()
        if args.get("scheme") is None:
            Log.fatal("Missing scheme from authority")
        if args.get("port") is None:
            args["port"] = service.find_port(args.get("scheme"))
        return args
