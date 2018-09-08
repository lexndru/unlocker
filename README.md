# Unlocker
[![Build Status](https://travis-ci.org/lexndru/unlocker.svg?branch=master)](https://travis-ci.org/lexndru/unlocker)

Unlocker is a keychain and a CLI credentials manager. Useful when you use a terminal often than GUI applications for remote connections (e.g. databases, SSH, rsync). It can store passwords and private keys. It comes with additional helper shells to encrypt your secrets and quick connect to servers passwordless.

## System requirements
- cPython >= 2.7.12
- pip >= 9.0.2
- gdbm

## Install
```
$ pip install unlocker
```

## Build from sources
```
$ python setup.py install
```

## Important note
This software is in a **beta** phase, it is highly recommended to keep a copy of your credentials in a safe place! Also, please report any faulty runtime or unexpected behavior of Unlocker. Thank you!

## Getting started
Unlocker is a simple storage for passwords and private keys. The main purpose of *unlocker* is to be a manager for such data and give CRUD-like options to add, update, read and delete sets of credentials.

Stored credentials are kept inside a keychain-type database. In *unlocker* context, the keychain storage is called *secrets* and has a versioning system. Secrets stored in older versions of Unlocker may not be directly compatible, thus it's needed to migrate them before using. All stored sensible credentials are compressed and encoded.

As a side feature, Unlocker has additional helper shell scripts that make it easier to use in day-to-day life. These scripts can be installed directly from unlocker's addons option: `unlocker install`. The result of this operation are two (2) new scripts in your `~/bin` directory: an `unlock` wrapper script to make passwordless connections to known servers; and a `lock` script to encrypt your *secrets*.

Notice: if for any reasons you have scripts named `lock` and `unlock` in your `~/bin` directory, *unlocker* will abort the installation of these scripts.

```
$ unlocker
              _            _
  _   _ _ __ | | ___   ___| | _____ _ __
 | | | | '_ \| |/ _ \ / __| |/ / _ \ '__|
 | |_| | | | | | (_) | (__|   <  __/ |
  \__,_|_| |_|_|\___/ \___|_|\_\___|_|

Unlocker - CLI credentials manager

Usage:
  init          Create local keychain
  list          List known hosts from keychain
  recall        Retrieve secrets by name or signature (slower than lookup)
  forget        Forget secrets by name or signature (slower than remove)
  append        Add new set of credentials to keychain
  update        Update password or private key to keychain
  remove        Remove credentials from keychain
  lookup        Find password for provided host, port and user
  install       Install helper scripts
  migrate       Migrate secrets to current unlocker version

```

## Options table

Option | Meaning
------ | -------
`init` | Create the keychain on the current machine inside your `$HOME` directory (optional)
`list` | Displays table-like list of existing credentials from keychain
`update` | Update *secrets* or bounce server for an existing server
`remove` | Remove set of credentials from keychain
`forget` | Like *remove*, but handles names and signatures
`lookup` | Lookup *secrets* from keychain
`recall` | Like *lookup*, but handles names and signatures
`install` | Installs two (2) new POSIX shell scripts as *unlocker* wrappers
`migrate` | Migrate secrets to current version of *unlocker*


## Features and conventions
Unlocker comes with a few tricks out of the box, it is written with some conventions in mind and tries to make it easier for developers to follow a defined "way of doing things" and work faster, although it's not mandatory and ignoring this section does not affect the usage of *unlocker* in any way.

#### Named servers with tags
Give your server a name otherwise it will receive a random string as name. You know better what's the purpose of each server. Follow this small convention when naming a server: `tag:the_name_you_want` where tag is something *unlocker* recognizes as being part of the name. If you set the tag `live` or `prod` to your server, *unlocker* will warn you before connecting to this server (e.g. in case you made a mistake when typing the name) and requires your direct confirmation to continue (this means you have to press a key to continue).
```
$ unlock ssh live:that_cool_server  # unlocker will recognize the live tag
                                    # and give you a heads up
```

#### Notification on `root` users
*Unlocker* does't make a difference between one user or another, it just keeps your credentials for later use. But for a developer or for a sysadmin there's a huge difference between a `root` user an the next one. Whenever you attempt to connect to a server with a `root` user, *unlocker* will notify you and it requires your direct input as a confirmation (just as the `live` tag on named servers, it means a press of a key). The `root` user be the last option for an ambiguous connection.
```
$ unlock ssh localhost              # you haven't specified what user to use...
                                    # unlocker will query all possible options
                                    # from the known servers and choose the first
                                    # non-root user or fallback to root and alert
```

#### Switching protocols
When connecting through a named server (e.g. `live:that_cool_server`) *unlocker* has a special feature of detecting protocol mistakes. If you, for some whatever reason, type `mysql` instead of `ssh` for your named server and there is no `mysql` known connection for that named server, then *unlocker* can detect other supported protocols and advise you to switch.
```
$ unlock redis live:that_cool_server
You requested redis, but only ssh is available for this server
Switch to ssh? [yN] y
...
```

#### Jump servers
Unlocker can save credentials to a server, but it can also save a jump server for that connection to work. Mostly useful when you have connections on localhost servers (such as databases binded to `localhost` on a VPC) or are behind a firewall and accessible only though SSH tunnels. For e.g. if you have a MySQL server binded to 127.0.0.1 on your my.server.tld, then you have to save the SSH server first, afterwards you'll be able to get the signature of the server and add the MySQL connection as well.
```
$ unlocker append -h my.server.tld -p 22 -u an_user -s ssh -a privatekey -n live:that_cool_server
...
$ unlocker list
   hash    |   bounce   | protocol |      ipv4       | port  |       hostname       |     user      |    friendly name    
========== | ========== | ======== | =============== | ===== | ==================== | ============= | ====================
 fa565262  |     ~      |   ssh    |     0.0.0.0     |  22   |    my.server.tld     |    an_user    | live:that_cool_server
```

```
$ unlocker append -h localhost -p 3306 -u another_user -s mysql -a password -n db:my_mysql_server -j fa565262
...
$ unlocker list
   hash    |   bounce   | protocol |      ipv4       | port  |       hostname       |     user      |    friendly name    
========== | ========== | ======== | =============== | ===== | ==================== | ============= | ====================
 fa565262  |     ~      |   ssh    |     0.0.0.0     |  22   |    my.server.tld     |    an_user    | live:that_cool_server  
 7c2ffc13  |  fa565262  |  mysql   |    127.0.0.1    | 3306  |      localhost       | another_user  |  db:my_mysql_server
```

## Examples

#### Add localhost MySQL server and quick connect
```
$ unlocker install
OK
$ unlocker append -h localhost -p 3306 -u user -s mysql -a password -n dev:mysql_server
Password: <your password>
...

  Secrets successfully added!

  user@127.0.0.1:3306

...
$ unlock mysql dev:mysql_server
  OR
$ unlock mysql user@localhost
  OR
$ unlock mysql localhost
```

#### Save server with private key
```
$ unlocker append -h private.server.tld -p 22 -u root -s ssh -a privatekey -n prod:server
Path to private key: /var/keys/rsa.pk
...

  Secrets successfully added!

  root@10.0.2.1:22

...
```

#### Retrieve password for MySQL server
```
$ unlocker lookup -n dev:mysql_server
  OR
$ unlocker recall dev:mysql_server
...

  Secret password for localhost

  user@127.0.0.1:3306    #############     <-- masked if shell supports, otherwise plain

...
```

#### Permanently remove server
```
$ unlocker remove -n dev:mysql_server
  OR
$ unlocker forget dev:mysql_server
...

  Permanently removed secret password for localhost!

  This is the last chance to save this secret.

  user@127.0.0.1:3306    #############     <-- masked if shell supports, otherwise plain

...
```

#### Update a password or a private key for a server
```
$ unlocker update -n dev:mysql_server -a password
Password: <your password>
...

  Secrets successfully updated!

  user@127.0.0.1:3306

...
```

#### Recreate keychain (only if you know what you're doing!)
```
$ rm -r ~/.unlocker
$ unlocker init
OK
```

#### Migrate secrets over different versions
```
$ unlocker migrate
OK
```

#### Export secrets to unlocker file (.unl)
```
$ unlocker migrate --export > /tmp/secrets.unl
OK
```

#### Import secrets from unlocker file (.unl)
```
$ unlocker migrate --import < /tmp/secrets.unl
OK
```

#### Encrypt your secrets
```
$ unlocker install
OK
$ lock
...
Secrets are now encrypted. Don't forget the password!
```

## Next steps
- [x] Additional helper script to unlock servers
- [x] Encrypt secrets file
- [x] Support secrets with connections through tunnels and jump servers
- [x] Implement named records
- [x] Better support for unicode
- [ ] Create helper scripts for MacOS and Windows

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
