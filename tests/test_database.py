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

from unlocker.database import Database
from unlocker.keychain import Keychain
from unlocker.authority import Authority

from unlocker.util.passkey import Passkey


class TestService(TestCase):

    def setUp(self):
        self.database = Database(storage=Keychain(holder={}))
        self.test_key = "test_key_123"

    def test_add_passkey(self):
        self.assertFalse(self.database.exists(self.test_key))
        self.database.add_passkey(self.test_key, "password")
        self.assertTrue(self.database.exists(self.test_key))

    def test_update_passkey(self):
        auth = Authority.new("127.0.0.1", 22, "root", "ssh")
        first_password = "password1"
        passkey = Passkey("password")
        passkey.save(first_password)
        self.database.add_passkey(self.test_key, passkey.pin())
        self.database.add_auth(self.test_key, auth)
        _, _, secret = self.database.lookup(self.test_key)
        _, password = Passkey.copy(secret, True)
        self.assertEqual(first_password, password)
        second_password = "password9999999999999"
        passkey.save(second_password)
        self.database.update_passkey(self.test_key, passkey.pin())
        _, _, secret = self.database.lookup(self.test_key)
        _, password = Passkey.copy(secret, True)
        self.assertNotEqual(first_password, password)
        self.assertEqual(second_password, password)

    def test_update_jump_auth(self):
        auth = Authority.new("127.0.0.1", 22, "root", "ssh")
        with self.assertRaises(SystemExit) as context:
            self.database.update_jump_auth(self.test_key, "bad value")
            self.assertTrue("Expected authority instance, got" in context.exception)
        self.database.update_jump_auth(self.test_key, auth)
        jump = self.database.fetch_jump(self.test_key)
        self.assertEqual(auth.signature(), jump.signature())

    def test_add_auth(self):
        auth = Authority.new("127.0.0.1", 22, "root", "ssh")
        with self.assertRaises(SystemExit) as context:
            self.database.fetch_auth(self.test_key)
            self.assertTrue("Cannot fetch unexisting" in context.exception)
        with self.assertRaises(SystemExit) as context:
            self.database.add_auth(self.test_key, "bad value")
            self.assertTrue("Expected auth to be authority, got" in context.exception)
        self.database.add_auth(self.test_key, auth)
        auth_key = self.database.fetch_auth(self.test_key)
        self.assertEqual(auth_key.signature(), auth.signature())

    def test_add_host(self):
        host = "localhost"
        with self.assertRaises(SystemExit) as context:
            self.database.fetch_host(self.test_key)
            self.assertTrue("Cannot fetch unexisting" in context.exception)
        self.database.add_host(self.test_key, host)
        host_key = self.database.fetch_host(self.test_key)
        self.assertEqual(host_key, host)

    def test_add_jump(self):
        jump = Authority.new("127.0.0.1", 22, "root", "ssh")
        with self.assertRaises(SystemExit) as context:
            self.database.fetch_jump(self.test_key)
            self.assertTrue("Cannot fetch unexisting" in context.exception)
        with self.assertRaises(SystemExit) as context:
            self.database.add_jump(self.test_key, "bad value")
            self.assertTrue("Expected auth to be authority, got" in context.exception)
        self.database.add_jump(self.test_key, jump)
        jump_key = self.database.fetch_jump(self.test_key)
        self.assertEqual(jump_key.signature(), jump.signature())

    def test_remove_jump(self):
        jump = Authority.new("127.0.0.1", 22, "root", "ssh")
        self.database.add_jump(self.test_key, jump)
        jump_key = self.database.fetch_jump(self.test_key)
        self.assertEqual(jump_key.signature(), jump.signature())
        self.database.remove_jump(self.test_key)
        with self.assertRaises(SystemExit) as context:
            self.database.fetch_jump(self.test_key)
            self.assertTrue("Cannot fetch unexisting" in context.exception)

    def test_remove_auth(self):
        auth = Authority.new("127.0.0.1", 22, "root", "ssh")
        self.database.add_auth(self.test_key, auth)
        auth_key = self.database.fetch_auth(self.test_key)
        self.assertEqual(auth_key.signature(), auth.signature())
        self.database.remove_auth(self.test_key)
        with self.assertRaises(SystemExit) as context:
            self.database.fetch_auth(self.test_key)
            self.assertTrue("Cannot fetch unexisting" in context.exception)

    def test_remove_host(self):
        host = "localhost"
        self.database.add_host(self.test_key, host)
        host_key = self.database.fetch_host(self.test_key)
        self.assertEqual(host_key, host)
        self.database.remove_host(self.test_key)
        with self.assertRaises(SystemExit) as context:
            self.database.fetch_host(self.test_key)
            self.assertTrue("Cannot fetch unexisting" in context.exception)
