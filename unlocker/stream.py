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

from unlocker.authority import Authority

from unlocker.util.service import Service


AUTHORITY_REGEXPR = "(?:(?P<scheme>.+)://)" \
                    "(?:(?P<user>.+?)@)" \
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
            cls.buf_in = unicode(stdin.read()).strip()
            return len(cls.buf_in) > 0
        return False

    @classmethod
    def parse(cls):
        """Parse input buffer.

        Returns:
            dict: Dictionary with arguments.
        """

        args = {"name": "", "signature": ""}
        exp = compile(AUTHORITY_REGEXPR, UNICODE)
        matches = exp.match(cls.buf_in)
        if matches is None:
            args.update({"name": cls.buf_in})
        else:
            params = matches.groupdict()
            if params.get("port") is None:
                params["port"] = Service.find_port(params.get("scheme"))
            auth = Authority.new(**params)
            args.update({"signature": auth.signature()})
        return args
