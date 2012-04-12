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
import os
import sys

class Minidump:
  def __init__(self, dumpFile, libDir=None):
    self.dumpFile = dumpFile
    self.libDir = libDir

    self.crashTrace = []
    self.crashType = None
    self.crashThread = None
    self.crashTraceSymbols = []

  def getCrashTrace(self):
    # Return cached result if available
    if (len(self.crashTrace) > 0):
      return self.crashTrace

    proc = subprocess.Popen(["minidump_stackwalk", "-m", self.dumpFile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = proc.communicate()[0].splitlines()

    for line in stdout:
      # Search for Crash|SIGABRT|0x43e0|9
      if line.startswith("Crash|SIG"):
        tok = line.split("|")
        self.crashType = tok[1]
        self.crashThread = tok[3]
        break

    if self.crashThread == None:
      raise Exception("Cannot identify crashing thread from dump")

    for line in stdout:
      tok = line.split("|")
      if ((len(tok) == 7) and (tok[0] == self.crashThread)):
        if (int(tok[1]) < 8):
          self.crashTrace.append((tok[1], tok[2], tok[6]))

    return self.crashTrace

  def getCrashType(self):
    if (self.crashType == None):
      # Will cache the crash type
      self.getCrashTrace()

    return self.crashType

  def getCrashingThread(self):
    if (self.crashThread == None):
      # Will cache the crashing thread
      self.getCrashTrace()

    return self.crashThread

  def getSymbolizedCrashTrace(self):
    # Return cached result if available
    if (len(self.crashTraceSymbols) > 0):
      return self.crashTraceSymbols

    dumpTrace = self.getCrashTrace()

    for frame in dumpTrace:
      frameNum = frame[0]
      frameFile = frame[1]
      frameAddr = frame[2]
      frameFileResolved = None
      for path, dirs, files in os.walk(os.path.abspath(self.libDir)):
        for filename in files:
          if filename == frameFile:
            frameFileResolved = os.path.join(path, filename)
            break

      if frameFileResolved != None:
        addr2line = subprocess.Popen(["addr2line", "-f", "-C", "-e", frameFileResolved, frameAddr], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        a2ldata = addr2line.communicate()[0].splitlines()
        if (len(a2ldata) >= 2):
          frameFunc = a2ldata[0]
          frameSrc = a2ldata[1]
          self.crashTraceSymbols.append((frameNum, frameFunc, frameSrc))
          next
        elif (len(a2ldata) == 1):
          frameFunc = a2ldata[0]
          self.crashTraceSymbols.append((frameNum, frameFunc, frameFile))
          next

      self.crashTraceSymbols.append((frameNum, frameAddr, frameFile))

    return self.crashTraceSymbols

if __name__ == "__main__":
  raise Exception("This module cannot run standalone, but is used by ADBFuzz")
