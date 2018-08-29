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

import os
import logging


class Log(object):
    """Log wrapper. That's it...
    """

    config = {
        r"format": r"%(message)s"
    }

    @classmethod
    def configure(cls, verbose=False):
        if "DEBUG" in os.environ or verbose:
            cls.config["level"] = logging.DEBUG
        else:
            cls.config["level"] = logging.WARNING
        logging.basicConfig(**cls.config)

    @classmethod
    def text_fmt(cls, message, params=None):
        if isinstance(params, dict):
            for k in params.iterkeys():
                if "{" + k + "}" not in message:
                    raise SystemExit("Unused key {} in text format".format(k))
            return message.format(**params)
        return message

    @classmethod
    def info(cls, message, **kwargs):
        logging.info(cls.text_fmt(message, kwargs))

    @classmethod
    def debug(cls, message, **kwargs):
        logging.debug(cls.text_fmt(message, kwargs))

    @classmethod
    def warn(cls, message, **kwargs):
        logging.warning(cls.text_fmt(message, kwargs))

    @classmethod
    def error(cls, message, **kwargs):
        logging.error(cls.text_fmt(message, kwargs))

    @classmethod
    def fatal(cls, message, **kwargs):
        error = cls.text_fmt(message, kwargs)
        if os.environ.get("DEBUG") == "true":
            throw = Exception
        else:
            throw = SystemExit
        raise throw(error)
