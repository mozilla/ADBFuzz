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

import subprocess
import time
import shutil
import os
import signal
import sys
from ConfigParser import SafeConfigParser

class Triager:
  def __init__(self, cfgFile):
    cfgDefaults = {}
    cfgDefaults['remoteHost'] = None
    cfgDefaults['localPort'] = '8088'
    cfgDefaults['useWebSockets'] = False
    cfgDefaults['localWebSocketPort'] = '8089'
    cfgDefaults['libDir'] = None

    self.cfg = SafeConfigParser(cfgDefaults)
    if (len(self.cfg.read(cfgFile)) == 0):
      raise "Unable to read configuration file: " + cfgFile

    self.fuzzerFile = self.cfg.get('main', 'fuzzer')
    self.runTimeout = self.cfg.getint('main', 'runTimeout')
    self.remoteAddr = self.cfg.get('main', 'remoteHost')
    self.localAddr = self.cfg.get('main', 'localHost')
    self.localPort = self.cfg.get('main', 'localPort')

    self.useWebSockets = self.cfg.getboolean('main', 'useWebSockets')
    self.localWebSocketPort = self.cfg.get('main', 'localWebSocketPort')

    self.libDir = self.cfg.get('main', 'libDir')

    self.HTTPProcess = None
    self.logProcess = None
    self.remoteInitialized = None

  def process(self, miniDump, systemLog, websockLog):
    print "Triager called: "
    print miniDump
    print systemLog
    print websockLog
    return

if __name__ == "__main__":
  raise Exception("This module cannot run standalone, but is used by ADBFuzz")
