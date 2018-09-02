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

from zlib import compress, decompress
from base64 import b64encode, b64decode

from unlocker.util.log import Log


class Keychain(object):
    """Credentials storage wrapper.

    Arguments:
        keychain (object): Storage dict-like object.

    Args:
        holder   (object): Storage instance or object.
    """

    def __init__(self, holder):
        self.keychain = holder
        Log.debug("Keychain initialized...")

    def add(self, key, value):
        """Append key to keychain.

        Args:
            key   (str): Key to append.
            value (str): Value to save for given key.
        """

        if self.has(key):
            Log.fatal("Cannot add duplicates in keychain")
        self.update(key, value)

    def has(self, key):
        """Check if keychain has given key.

        Args:
            key (str): Key to lookup

        Returns:
            bool: True if keychain has key, otherwise False.
        """

        for k in self.lookup(key, partial=False):
            return True
        return False

    def get_value(self, key):
        """Returns real value for given key.

        Args:
            key (str): Key to lookup and retrieve value.

        Raises:
            Exception: If value is None or keychain does not have key.

        Returns:
            str: Uncompressed and decoded stored value for key.
        """

        value = self.get(key)
        if value is None:
            Log.fatal("Keychain does not have requested key")
        return decompress(b64decode(value))

    def get(self, key):
        """Returns "as is" value for given key.

        Args:
            key (str): Key to lookup and retrieve value.

        Raises:
            Exception: If value is not string or keychain does not have key.

        Returns:
            str: Raw "as is" base64 stored value for key.
        """

        if not self.has(key):
            return None
        return self.keychain[key]

    def update(self, key, value):
        """Update key in keychain.

        Args:
            key   (str): Key to update.
            value (str): Value to save for given key.
        """

        self.keychain[key] = b64encode(compress(value))

    def remove(self, key):
        """Remove key from keychain.

        Args:
            key (str): Key to remove.

        Returns:
            str: Raw "as is" removed value for given key.
        """

        value = self.get(key)
        if value is None:
            Log.warn("Keychain can not remove an unset key")
        else:
            del self.keychain[key]
        return value

    def lookup(self, key, partial=True):
        """Lookup key in keychain.

        Args:
            key (str): Key to lookup.

        Yields:
            str: Yields exact key(s) if found.
        """

        if hasattr(self.keychain, "iterkeys"):
            iterator = self.keychain.iterkeys
        else:
            iterator = self.keychain.keys
        for k in iterator():
            if key == k or (partial and k.startswith(key)):
                yield k

    def __repr__(self):
        return "[{} key(s) stored]".format(len(self.keychain))
