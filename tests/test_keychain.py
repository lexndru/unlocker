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

from unittest import TestCase
from zlib import compress
from base64 import b64encode

from unlocker.keychain import Keychain


class TestKeychain(TestCase):

    def setUp(self):
        self.keychain = Keychain(holder={})

    def test_add_unique(self):
        if not self.keychain.has("key1"):
            self.keychain.add("key1", "val1")
        with self.assertRaises(SystemExit) as context:
            self.keychain.add("key1", "val2")
            self.assertTrue("Cannot add duplicates in keychain" in context.exception)

    def test_update(self):
        self.keychain.update("key1", "val1")
        self.assertEqual("val1", self.keychain.get_value("key1"))
        self.keychain.update("key1", "val2")
        self.assertNotEqual("val1", self.keychain.get_value("key1"))
        self.keychain.update("key1", "val9")
        self.assertEqual("val9", self.keychain.get_value("key1"))

    def test_remove(self):
        self.keychain.update("key1", "val1")
        self.assertTrue(self.keychain.has("key1"))
        self.keychain.remove("key1")
        self.assertFalse(self.keychain.has("key1"))

    def test_exists(self):
        self.assertFalse(self.keychain.has("new_key"))
        self.keychain.update("new_key", "new_value")
        self.assertTrue(self.keychain.has("new_key"))

    def test_value(self):
        self.keychain.update("key1", "val1")
        self.assertNotEqual(self.keychain.get("key1"), "val1")
        self.assertEqual(self.keychain.get_value("key1"), "val1")
        self.assertEqual(self.keychain.get("key1"), b64encode(compress("val1")))

    def test_generator(self):
        for i in xrange(10):
            key = "secret_key{}" if i < 3 else "key{}"
            self.keychain.update(key.format(i), "value")
        gen = self.keychain.lookup("secret")
        counter = 0
        for i in gen:
            self.assertTrue(i.startswith("secret"))
            counter += 1
        self.assertEqual(counter, 3)
