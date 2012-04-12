# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# The Original Code is ADBFuzz.
#
# The Initial Developer of the Original Code is Christian Holler (decoder).
#
# Contributors:
#  Christian Holler <decoder@mozilla.com> (Original Developer)
#
# ***** END LICENSE BLOCK *****

import sys
from socket import *

if __name__ == "__main__":
  HOST, PORT = sys.argv[1], sys.argv[2]
  s = socket(AF_INET, SOCK_STREAM)
  s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
  s.bind((HOST, int(PORT)))
  s.listen(1)

  while True:
    conn, addr = s.accept()
    print "[WebSockLog - Client Connect] %s" % str(addr)
    fileHandle = open("websock.log", "w")
    sockfile = conn.makefile()
    while True:
        data = sockfile.readline()
        if (len(data) == 0):
          break
        data = data.strip()
        fileHandle.write(data + "\n")
        fileHandle.flush()
