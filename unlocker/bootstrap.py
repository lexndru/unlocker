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

from unlocker.manager import Manager
from unlocker.stream import StreamData

from unlocker.util.secret import confidential
from unlocker.util.shell import ShellParser
from unlocker.util.log import Log


@confidential
def unlocker(secrets, args=()):
    """Manage unlocker's keychain.

    Can add, edit, delete and lookup keys.
    All keys stored are compressed and encoded.
    """

    # register secrets on keychain
    Manager.initialize(secrets)
    Log.debug("Preparing to boot...")

    # initialize manager and parse arguments
    mng = Manager(*args)
    mng.call()
    Log.debug("Preparing to exit...")


def read_input():
    """Read input from stdin or shell.

    Some shell arguments can trigger exit before reaching end of function.
    """

    # check if data is piped to unlocked and dump passkey
    if StreamData.read():
        Log.debug("Reading stdin: {data}", data=StreamData.buf_in)
        return StreamData.OPTION, StreamData.parse()

    # initialize shell
    shell = ShellParser()
    opts, args = shell.get_args()
    Log.debug("Running '{o}' with arguments: {a}", o=opts, a=args)

    # return shell arguments
    return opts, vars(args)


def main():
    """Main callable function.

    Configure logging capabilities, read input from shell or stdin (can exit
    fastly) and run unlocker manager.
    """

    # configure log
    Log.configure()
    Log.debug("Running in debug mode...")

    # read input
    args = read_input()

    # run unlocker with input args
    unlocker(args=args)
