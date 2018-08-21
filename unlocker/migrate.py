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

from sys import stdin, stdout

from unlocker.util.log import Log


class Migrate(object):
    """Secrets migration in and out.
    """

    def __init__(self, manager):
        self.manager = manager

    @classmethod
    def discover(cls, manager):
        if manager.args.get("import_secrets"):
            if stdin.isatty():
                Log.fatal("Migration failed: stdin is empty")
            mig = Migrate(manager)
            mig.import_secrets()
        elif manager.args.get("export_secrets"):
            if stdout.isatty():
                Log.fatal("Migration failed: stdout is empty")
            mig = Migrate(manager)
            mig.export_secrets()
        else:
            Log.fatal("Unexpected migrate request...")

    def import_secrets(self):
        raise NotImplemented("Cannot import data yet")

    def export_secrets(self):
        raise NotImplemented("Cannot export data yet")
