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
from ipaddress import ip_address

from unlocker.authority import Authority


class TestAuthority(TestCase):

    def setUp(self):
        self.auth = Authority()
        self.localhost_as_int = 2130706433
        self.localhost_signature = Authority.sign("2130706433:22:root:ssh")

    def test_host(self):
        self.assertIsNone(self.auth.get_host())
        with self.assertRaises(SystemExit) as context:
            self.auth.set_host(self.localhost_as_int)
            self.assertTrue("Invalid host" in context.exception)
        self.auth.set_host("127.0.0.1")
        self.assertNotEqual(self.auth.get_host(), u"127.0.0.1")
        self.assertEqual(self.auth.get_host(), self.localhost_as_int)
        self.assertEqual(self.auth.get_host_ip4(), u"127.0.0.1")

    def test_port(self):
        self.assertIsNone(self.auth.get_port())
        with self.assertRaises(SystemExit) as context:
            self.auth.set_port([22])
            self.assertTrue("Invalid port" in context.exception)
        self.auth.set_port("22")
        self.assertNotEqual(self.auth.get_port(), "22")
        self.assertEqual(self.auth.get_port(), 22)
        with self.assertRaises(SystemExit) as context:
            self.auth.set_port([66000])
            self.assertTrue("Invalid port: out of range" in context.exception)

    def test_scheme(self):
        with self.assertRaises(SystemExit) as context:
            self.auth.set_scheme("")
            self.assertTrue("Invalid scheme: zero-length string" in context.exception)
        self.auth.set_scheme("ssh")
        self.assertNotEqual(self.auth.get_scheme(), "tcp")
        self.assertEqual(self.auth.get_scheme(), "ssh")

    def test_user(self):
        with self.assertRaises(SystemExit) as context:
            _ = self.auth.get_user()
            self.assertTrue("Authority has not set a valid" in context.exception)
        self.auth.set_user("unlocker")
        self.assertNotEqual(self.auth.get_user(), "python")
        self.assertEqual(self.auth.get_user(), "unlocker")

    def test_create(self):
        auth = Authority.new("127.0.0.1", 22, "root", "ssh")
        self.assertEqual(auth.read(), "{}:22:root:ssh".format(self.localhost_as_int))

    def test_recover(self):
        dump = "{}:22:root:ssh".format(self.localhost_as_int)
        auth = Authority.recover(dump)
        self.assertEqual(auth.get_host(), self.localhost_as_int)
        self.assertEqual(auth.get_port(), 22)
        self.assertEqual(auth.get_user(), "root")
        self.assertEqual(auth.get_scheme(), "ssh")

    def test_signature(self):
        auth = Authority.new("127.0.0.1", 22, "root", "ssh")
        self.assertEqual(auth.signature(), self.localhost_signature)
