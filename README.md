# Unlocker

## Install
```
$ pip install unlocker
```

## Getting started
```
$ unlocker
              _            _
  _   _ _ __ | | ___   ___| | _____ _ __
 | | | | '_ \| |/ _ \ / __| |/ / _ \ '__|
 | |_| | | | | | (_) | (__|   <  __/ |
  \__,_|_| |_|_|\___/ \___|_|\_\___|_|

Unlocker v0.1.0 - CLI credentials manager

Usage:
  init          Create local keychain
  setup         Create helper scripts
  append        Add new set of credentials to keychain
  update        Update or add set of credentials to keychain
  remove        Remove credentials from keychain
  lookup        Find password for provided host, port and user
  list          List known hosts from keychain

$ unlocker init
$ unlocker setup
$ unlock
             _            _             
 _   _ _ __ | | ___   ___| | _____ _ __
| | | | '_ \| |/ _ \ / __| |/ / _ \ '__|
| |_| | | | | | (_) | (__|   <  __/ |   
 \__,_|_| |_|_|\___/ \___|_|\_\___|_|   

Unlocker v0.1.0 x86_64 GNU/Linux

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

  Please report bugs at http://github.com/lexndru/unlocker

Usage:
  service [user@]hostname[:port]  - Unlock server if credentials are known

Examples:
  redis 127.0.0.1:6379 (connect to local Redis with any available user)
  mysql 127.0.0.1 (connect to MySQL with any available user)
  mysql guest@database:3306 (connect to MySQL on port 3306 with user guest)
  ssh root@yourserver.tld (connect to yourserver.tld with root user)
  ssh yourserver.tld (connect to yourserver.tld with any available user)

```

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
