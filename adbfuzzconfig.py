#!/usr/bin/env python
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

from ConfigParser import SafeConfigParser

class ADBFuzzConfig:

  def __init__(self, cfgFile):
    cfgDefaults = {}
    cfgDefaults['remoteHost'] = None
    cfgDefaults['localPort'] = '8088'
    cfgDefaults['useWebSockets'] = False
    cfgDefaults['localWebSocketPort'] = '8089'
    cfgDefaults['libDir'] = None
    cfgDefaults['debug'] = str(False)

    cfgDefaults['runTimeout'] = 5
    cfgDefaults['maxLogSize'] = str(1024*1024*10) # Default to 10 kb maximum log

    self.cfg = SafeConfigParser(cfgDefaults)
    if (len(self.cfg.read(cfgFile)) == 0):
      raise Exception("Unable to read configuration file: " + cfgFile)

    self.fuzzerFile = self.cfg.get('main', 'fuzzer')
    self.runTimeout = self.cfg.getint('main', 'runTimeout')
    self.maxLogSize = self.cfg.getint('main', 'maxLogSize')
    self.remoteAddr = self.cfg.get('main', 'remoteHost')
    self.localAddr = self.cfg.get('main', 'localHost')
    self.localPort = self.cfg.get('main', 'localPort')
    self.debug = self.cfg.getboolean('main', 'debug')
    self.knownPath = self.cfg.get('main', 'knownPath')

    self.useWebSockets = self.cfg.getboolean('main', 'useWebSockets')
    self.localWebSocketPort = self.cfg.get('main', 'localWebSocketPort')
    self.libDir = self.cfg.get('main', 'libDir')

if __name__ == "__main__":
  raise Exception("This module cannot run standalone, but is used by ADBFuzz")
