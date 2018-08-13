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

from stat import S_IEXEC
from os import path, makedirs, stat, chmod
from os.path import expanduser

from unlocker.util.log import Log


SCRIPTS_DIR = "bin"
UNLOCK_SCRIPT = """#!/bin/sh

echo Missing lock script...
"""


def make_helper_script():
    """Create executable helper script.

    Raises:
        Exception: If application cannot create directory or file.

    Return:
        bool: True if script was successfully created, otherwise False.
    """

    scripts_dir = path.join(expanduser("~"), "bin")
    Log.debug("Scripts directory located at {path}", path=scripts_dir)
    try:
        if not path.exists(scripts_dir):
            Log.debug("Scripts directory does not exist. Creating...")
            makedirs(scripts_dir)
            Log.debug("Scripts directory successfully created!")
        else:
            Log.debug("Found scripts directory...")
    except Exception as e:
        Log.fatal("Failed to create scripts directory: {err}", err=str(e))
    try:
        filepath = "{}/unlock".format(scripts_dir)
        if path.exists(filepath):
            Log.fatal("A file with this name already exists: {x}", x=filepath)
        with open(filepath, "wb") as fd:
            fd.write(UNLOCK_SCRIPT)
        mod = stat(filepath)
        chmod(filepath, mod.st_mode | S_IEXEC)
        return True
    except Exception as e:
        Log.fatal("Cannot create helper script because: {e}", e=str(e))
    return False
