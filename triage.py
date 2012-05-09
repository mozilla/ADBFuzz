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
    
    self.androidLogLinefilter = lambda x: re.sub('^[^:]+: ', '', x)

  def process(self, issueUUID, miniDump, systemLog, websockLog):
    print "Triaging crash..."

    # Read Android system log
    systemLogFile = open(systemLog)
    
    # Check if we got aborted or crashed
    aborted = self.assertDetector.hasFatalAssertion(
        systemLogFile, 
        verbose=True, 
        lineFilter=self.androidLogLinefilter
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
        lineFilter=self.androidLogLinefilter
    )
    
    hasNewAssertion = len(assertions) > 0

    systemLogFile.close()
    
    if miniDump == None and not hasNewAssertion:
      print "Error: No minidump available but also no assertions detected!"
      return
    
    isNewCrash = (miniDump != None)
    crashFunction = "Unknown"
    issueDesc = "Unknown"
    
    if miniDump != None:
      # Obtain symbolized crash trace to check crash signature
      trace = miniDump.getSymbolizedCrashTrace()
      
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
        self.mailer.notify(issueUUID, issueDesc, miniDump)
    else:
      # Delete files if not in debug mode
      if not self.config.debug:
        if miniDump != None:
          miniDump.cleanup()
        os.remove(systemLog)
        os.remove(websockLog)

    return
  
  def checkLine(self, line):
    return self.assertDetector.scanLineAssertions(self.androidLogLinefilter(line))
    

if __name__ == "__main__":
  raise Exception("This module cannot run standalone, but is used by ADBFuzz")
