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
import re

from detectors import AssertionDetector, CrashDetector
from mail import Mailer

class Triager:
  def __init__(self, config):
    self.config = config
    
    if self.config.useMail:
      self.mailer = Mailer(config)

    self.assertDetector = AssertionDetector(self.config.knownPath)
    self.crashDetector = CrashDetector(self.config.knownPath)

  def process(self, miniDump, systemLog, websockLog):
    print "Triaging crash..."

    # Read Android system log
    systemLogFile = open(systemLog)
    
    # Check if we got aborted or crashed
    aborted = self.assertDetector.hasFatalAssertion(
        systemLogFile, 
        verbose=True, 
        lineFilter=lambda x: re.sub('^[^:]+: ', '', x)
    )
    
    # Reopen file
    systemLogFile.close()
    systemLogFile = open(systemLog)

    # Check if the syslog file contains an interesting assertion.
    # The lambda removes the Android syslog tags before matching
    assertions = self.assertDetector.scanFileAssertions(
        systemLogFile, 
        verbose=True, 
        ignoreKnownAssertions=True,
        lineFilter=lambda x: re.sub('^[^:]+: ', '', x)
    )
    
    hasNewAssertion = len(assertions) > 0

    systemLogFile.close()
    
    # Obtain symbolized crash trace to check crash signature
    trace = miniDump.getSymbolizedCrashTrace()

    isNewCrash = True
    crashFunction = "Unknown"
    issueDesc = "Unknown"
    
    if (len(trace) > 0):
      crashFunction = trace[0][1]
      issueDesc = "Crashed at " + crashFunction
      isNewCrash = not self.crashDetector.isKnownCrashSignature(crashFunction)
      # Also check first frame (some functions are blacklisted here)
      if (isNewCrash and len(trace) > 1):
        isNewCrash = not self.crashDetector.isKnownCrashSignature(trace[1][1])
      
    # Use the last assertion as issue description
    if hasNewAssertion:
      issueDesc = assertions[len(assertions)-1]
      
    print issueDesc

    if hasNewAssertion or (not aborted and isNewCrash):
      print "Found new issue, check " + websockLog + " to reproduce"
      if self.config.useMail:
        self.mailer.notify(miniDump, issueDesc)
    else:
      # Delete files if not in debug mode
      if not self.config.debug:
        miniDump.cleanup()
        os.remove(systemLog)
        os.remove(websockLog)

    return

if __name__ == "__main__":
  raise Exception("This module cannot run standalone, but is used by ADBFuzz")
