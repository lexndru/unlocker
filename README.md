# Unlocker
[![Build Status](https://travis-ci.org/lexndru/unlocker.svg?branch=master)](https://travis-ci.org/lexndru/unlocker)

Unlocker is a keychain and a CLI credentials manager. Useful when you use a terminal often than GUI applications for remote connections (e.g. databases, SSH, rsync). It can store passwords and private keys. It comes with addons to encrypt keychain and fast connect to servers.

## Install
```
$ pip install unlocker
```

## Important note
This software is in a **beta** phase, it is highly recommended to keep a copy of your credentials in a safe place! Also, please report any faulty runtime or unexpected behavior of Unlocker.

## Getting started
Unlocker is a simple storage for passwords and private keys. The main purpose of *unlocker* is to be a manager for such data and give CRUD-like options to add, update, read and delete sets of credentials.

Stored credentials are kept inside a keychain-type database. In *unlocker* context, the keychain storage is called *secrets* and has a versioning system. Secrets stored in older versions of Unlocker may not be directly compatible, thus it's needed to migrate them before using. All stored sensible credentials are compressed and encoded.

As a side feature, Unlocker has additional helper shell scripts that make it easier to use in day-to-day life. These scripts can be installed directly from unlocker's addons option: `unlocker addons`. The result of this operation are two (2) new scripts in your `~/bin` directory: an `unlock` wrapper script to make passwordless connections to known servers; and a `lock` script to encrypt your *secrets*.

Notice: if for any reasons you have scripts named `lock` and `unlock` in your `~/bin` directory, *unlocker* will abort the installation of these scripts.

```
$ unlocker
              _            _
  _   _ _ __ | | ___   ___| | _____ _ __
 | | | | '_ \| |/ _ \ / __| |/ / _ \ '__|
 | |_| | | | | | (_) | (__|   <  __/ |
  \__,_|_| |_|_|\___/ \___|_|\_\___|_|

Unlocker v0.2.4 - CLI credentials manager

Usage:
  init          Create local keychain
  list          List known hosts from keychain
  append        Add new set of credentials to keychain
  update        Update or add set of credentials to keychain
  remove        Remove credentials from keychain
  lookup        Find password for provided host, port and user
  addons        Install helper scripts
  migrate       Migrate secrets to current unlocker version

```

## Unlocker options

- `init`: create the keychain on the current machine inside your `$HOME` directory. It's not mandatory to `init` before using *unlocker*.

   *Sample usage:*

   ```
   $ unlocker init
   ```


- `append`: append a new set of credentials to keychain. It returns an error if credentials already exist.

   *Sample usage:*

   ```
   $ unlocker append --host localhost --port 22 --user root --auth password --scheme ssh
   ```

- `update`: update an existing set of credentials from keychain. If credentials are not found, the update acts like `append` and adds credentials.

   *Sample usage:*

   ```
   $ unlocker update --host localhost --port 22 --user root --auth privatekey --scheme ssh
   ```

- `remove`: remove existing set of credentials from keychain. An error is returned if credentials are not found.

   *Sample usage:*

   ```
   $ unlocker remove --host localhost --port 22 --user root --scheme ssh
   ```

- `lookup`: lookup paskey from keychain. An error is returned if passkey is not found.

   *Sample usage:*

   ```
   $ unlocker lookup --host localhost --port 22 --user root
   ```

- `list`: displays a table-like list of existing credentials from keychain.

   *Sample usage:*

   ```
   $ unlocker list
   ```

- `migrate`: attempt to migrate secrets to current version of *unlocker*. Returns an error if migration is not possible, otherwise it exits silently.

   *Sample usage:*

   ```
   $ unlocker migrate
   ```

- `addons`: installs two (2) new POSIX shell scripts as *unlocker* wrappers.

   *Sample usage:*

   ```
   $ unlocker addons
   $ unlock   # passwordless connect e.g. unlock ssh root@localhost
   $ lock     # encrypts secrets
   ```

## Next steps
- [x] Additional helper script to unlock servers
- [x] Encrypt secrets file
- [ ] Support database connections through tunnels and jump servers

## License
Copyright 2018 Alexandru Catrina

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
