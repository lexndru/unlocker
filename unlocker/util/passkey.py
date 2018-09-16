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

from os import path
from getpass import getpass
from base64 import b64encode

from unlocker.util.log import Log


class Passkey(object):
    """Higher-level secrets manager.

    Handlers passkeys from secrets formats and converts between them.

    Arguments:
        passkey (str): The passkey to save or convert.
        passfix (str): The prefix of the supported convertion passkey.
    """

    SUPPORTED_TYPES = {"password": ".", "privatekey": ">"}
    MIN_LEN = 2

    passkey = None

    def __init__(self, auth_type):
        if auth_type not in self.SUPPORTED_TYPES:
            Log.fatal("Unsupported auth type for passkey: {t}", t=auth_type)
        self.__read_method = "read_{}".format(auth_type)
        self.passfix = self.SUPPORTED_TYPES.get(auth_type)

    @classmethod
    def resolve(cls, auth):
        """Returns the final version of a passkey with its appropriate type.

        Args:
            auth (str): Authentification method.

        Raises:
            Exception: If unsupported authentification or cannot resolve pin.

        Returns:
            str: Prefixed passkey to store it later.
        """

        pk = cls(auth)
        pk.read()
        return pk.pin()

    @classmethod
    def copy(cls, secret, unsafe=False):
        """Creates an in-memory copy a passkey.

        Args:
            secret  (str): The secret to unpack and create a copy of it.
            unsafe (bool): Whether to return the copy as unsafe or not.

        Raises:
            Exception: If unsupported secret passkey type found.

        Returns:
            tuple: Passkey type and copy of unsolved (raw) secret.
        """

        if len(secret) < cls.MIN_LEN:
            Log.fatal("Secret size too small")
        for ptype, prefix in cls.SUPPORTED_TYPES.iteritems():
            if secret[0] == prefix:
                passkey = b64encode(secret[1:]) if not unsafe else secret[1:]
                return ptype, passkey
        Log.fatal("Cannot copy secret: unsupported resolve method")

    def pin(self):
        """Return the prefixed secret with its appropriate type.

        Raises:
            Exception: If unsupported passkey is provided.

        Returns:
            str: Prefixed passkey.
        """

        if self.passkey is None:
            Log.fatal("Passkey has not been read yet")
        return self.passfix + self.passkey

    def save(self, passkey):
        """Save raw passkey "AS IS".

        Args:
            passkey (str): Passkey to save.
        """

        self.passkey = passkey

    def read(self):
        """Autodetect read method and retrieve passkey.

        Raises:
            Exception: If cannot autodetect read method.
        """

        if not hasattr(self, self.__read_method):
            Log.fatal("Unsupported read method: {m}", m=self.read_method)
        self.passkey = getattr(self, self.__read_method)()

    def read_password(self, prompt="Password: "):
        """Get password from user input.

        Args:
            password_prompt (str): Prompt message to display.
        """

        return getpass(prompt)

    def read_privatekey(self, prompt="Path to private key: "):
        """Get private key from user input.

        Args:
            pk_prompt (str): Prompt message to display.

        Raises:
            Exception: If path to private key does not exist or cannot open.
        """

        filepath = raw_input(prompt)
        if not path.exists(filepath):
            Log.fatal("Path to private key does not exists")
        try:
            with open(filepath, "rb") as fd:
                return fd.read()
        except Exception as e:
            Log.fatal("Cannot read private key: {e}", e=str(e))
