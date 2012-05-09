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

import threading
import subprocess

class LogFilter(threading.Thread):
  def __init__(self, config, triager, logCmd, logFile):
    self.config = config
    self.triager = triager
    self.logCmd = logCmd
    self.logFile = logFile
    self.eof = False
    
    # Thread initialization stuff
    self.stdout = None
    self.stderr = None
    threading.Thread.__init__(self)
    
    # We need this to know when to terminate
    self._stop = threading.Event()

  def run(self):
    
    if self.logFile == None:
      logFileFd = None
    else:
      logFileFd = open(self.logFile, 'w')
      
    logProcess = subprocess.Popen(self.logCmd, shell=False, stdout=subprocess.PIPE, stderr=None)
    
    # Loop until we get aborted, hit EOF or find something interesting
    while not self._stop.isSet():
      line = logProcess.stdout.readline()
      if (len(line) == 0):
          self.eof = True
          break
      
      if logFileFd == None:
        # Output to stdout
        print line
      else:
        # Store to file first
        logFileFd.write(line)
      
      # Now check if it has something interesting (e.g. assertion)
      line = line.strip()
      if self.triager.checkLine(line):
        break
    
    logProcess.terminate()
    
    if logFileFd != None:
      logFileFd.close()
    
    return
  
  def terminate(self):
    self._stop.set()

if __name__ == "__main__":
  raise Exception("This module cannot run standalone, but is used by ADBFuzz")
