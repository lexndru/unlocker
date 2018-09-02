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
try:
    from os import geteuid

    def is_root(): return geteuid() == 0
except ImportError:
    def is_root(): return False

from unlocker.util.log import Log

from unlocker import __version__, __project__


SYSTEM_SCRIPTS_DIR = "/usr/local/bin"
SCRIPTS_DIR = "bin"
SCRIPTS_SHEBANG = ur"""#!/bin/sh
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

VERSION={version}
HOMEPAGE={homepage}
""".format(version=__version__, homepage="http://github.com/lexndru/unlocker")


def deploy_lock_script():
    """Install LOCK script on current machine.

    Raises:
        Exception: If script is missing or cannot be accessed.

    Return:
        bool: True if successfully deployed, otherwise False.
    """

    return deploy_script("lock.sh")


def deploy_unlock_script():
    """Install UNLOCK script on current machine.

    Raises:
        Exception: If script is missing or cannot be accessed.

    Return:
        bool: True if successfully deployed, otherwise False.
    """

    return deploy_script("unlock.sh")


def deploy_script(script_name):
    """Install script on current machine.

    Args:
        script_name (str): The name of script to be deployed.

    Raises:
        Exception: If script is missing or cannot be accessed.

    Return:
        bool: True if successfully deployed, otherwise False.
    """

    content = read_helper_script("data/shell/{}".format(script_name))
    if not content:
        Log.fatal("Helper script is missing")
    script = "{}\n{}".format(SCRIPTS_SHEBANG, content)
    try:
        script_name, _ = script_name.split(".", 1)
    except Exception:
        Log.debug("Cannot find file extension for {s}", s=script_name)
    return make_helper_script(script_name, script)


def read_helper_script(filepath):
    """Read helper script

    Args:
        filepath (str): Path to helper script to read.

    Raises:
        Exception: If helper script cannot be accessed.

    Return:
        unicode: Unicode content of helper script.
    """

    try:
        file_script = path.abspath(path.join(__project__, filepath))
        if not path.exists(file_script):
            Log.fatal("Cannot find helper script {file}", file=filepath)
        with open(file_script, "rb") as fd:
            return fd.read()
    except Exception as e:
        Log.fatal("Cannot read helper script: {e}", e=str(e))


def make_helper_script(file_script, script_content):
    """Create executable helper script.

    Args:
        file_script        (str): Script to make.
        script_content (unicode): Script content.

    Raises:
        Exception: If application cannot create directory or file.

    Return:
        bool: True if script was successfully created, otherwise False.
    """

    if is_root():
        scripts_dir = SYSTEM_SCRIPTS_DIR
    else:
        scripts_dir = path.join(expanduser("~"), SCRIPTS_DIR)
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
        filepath = "{}/{}".format(scripts_dir, file_script)
        if path.exists(filepath):
            Log.fatal("A file with this name already exists: {x}", x=filepath)
        with open(filepath, "wb") as fd:
            fd.write(script_content)
        mod = stat(filepath)
        chmod(filepath, mod.st_mode | S_IEXEC)
        return True
    except Exception as e:
        Log.fatal("Cannot create helper script because: {e}", e=str(e))
    return False
