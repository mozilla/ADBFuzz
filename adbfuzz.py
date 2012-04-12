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

from mozdevice import DeviceManagerADB

from triage import Triager
from minidump import Minidump

def usage():
  print ""
  print "Usage: " + sys.argv[0] + " cfgFile cmd params"
  print "  Supported commands:"
  print "    run        - Run the fuzzer until manually aborted"
  print "    showdump   - Show the (symbolized) trace for a given dump"
  print "      param[0]: path to dump file"
  print "      param[1]: symbol search path"
  print "    reproduce"
  print "      param[0]: file to test"
  print "      param[1]: run timeout"
  print ""
def main():
  if (len(sys.argv) > 2):
      cfgFile = sys.argv.pop(1)
      fuzzInst = ADBFuzz(cfgFile)
  else:
      print "Missing configuration file!"
      usage()
      exit(1)
  
  cmd = sys.argv.pop(1)
  if (cmd == "showdump"):
    print "Obtaining symbolized trace..."
    dumpFile = sys.argv[1]
    libSearchPath = sys.argv[2]
    minidump = Minidump(dumpFile, libSearchPath)
    symbolTrace = minidump.getSymbolizedCrashTrace()
    print ""
    for frame in symbolTrace:
      print "#" + frame[0] + "\t" + frame[1] + " at " + frame[2]
  elif (cmd == "reproduce"):
    fuzzInst.fuzzerFile = sys.argv[1]
    fuzzInst.runTimeout = int(sys.argv[2])
    if fuzzInst.testCrash():
      exit(0)
    exit(1)
  elif (cmd == "run"):
    fuzzInst.remoteInit()
    fuzzInst.loopFuzz()


class ADBFuzz:

  def __init__(self, cfgFile):
    cfgDefaults = {}
    cfgDefaults['remoteHost'] = None
    cfgDefaults['localPort'] = '8088'
    cfgDefaults['useWebSockets'] = False
    cfgDefaults['localWebSocketPort'] = '8089'
    cfgDefaults['libDir'] = None

    self.cfg = SafeConfigParser(cfgDefaults)
    if (len(self.cfg.read(cfgFile)) == 0):
      raise Exception("Unable to read configuration file: " + cfgFile)

    self.fuzzerFile = self.cfg.get('main', 'fuzzer')
    self.runTimeout = self.cfg.getint('main', 'runTimeout')
    self.remoteAddr = self.cfg.get('main', 'remoteHost')
    self.localAddr = self.cfg.get('main', 'localHost')
    self.localPort = self.cfg.get('main', 'localPort')

    self.useWebSockets = self.cfg.getboolean('main', 'useWebSockets')
    self.localWebSocketPort = self.cfg.get('main', 'localWebSocketPort')

    self.libDir = self.cfg.get('main', 'libDir')

    self.HTTPProcess = None
    self.logProcesses = []
    self.remoteInitialized = None

    self.triager = Triager(cfgFile)

  def remoteInit(self):
    if (self.remoteInitialized != None):
      return

    self.dm = DeviceManagerADB(self.remoteAddr, 5555)
    self.appName = self.dm.packageName
    self.appRoot = self.dm.getAppRoot(self.appName)
    self.profileBase = self.appRoot + "/files/mozilla"
    self.profiles = self.getProfiles()

    # Install a signal handler that shuts down our external programs on SIGINT
    signal.signal(signal.SIGINT, self.signal_handler)

    if (len(self.profiles) == 0):
      print "Failed to detect any valid profile, aborting..."
      return 1

    self.defaultProfile = self.profiles[0]

    if (len(self.profiles) > 1):
      print "Multiple profiles detected, using the first: " + self.defaultProfile

    self.remoteInitialized = True

  def signal_handler(self, signal, frame):
    self.cleanupProcesses()
    sys.exit(0)

  def cleanupProcesses(self):
    self.stopFennec()
    if (self.HTTPProcess != None):
      try:
        self.HTTPProcess.terminate()
      except:
        pass
    if (self.logProcesses != None):
      try:
        while (len(self.logProcesses) > 0):
          self.logProcesses.pop().terminate()
      except:
        pass

  def loopFuzz(self):
    try:
      while True:
        self.runFuzzer()
    except:
      self.cleanupProcesses()
      raise

  def runFuzzer(self):
    self.remoteInit()

    # Ensure Fennec isn't running
    if self.isFennecRunning():
      self.stopFennec()

    # Clean all existing minidumps
    if not self.clearMinidumps():
      raise Exception("Failed to clean existing minidumps")

    # Start our HTTP server for serving the fuzzer code
    self.HTTPProcess = self.startHTTPServer()

    # Start all loggers
    self.startLoggers()

    # Start Fennec
    self.startFennec()

    # Even though the program is already running, we should grant it
    # some extra time to load the fuzzer source and start running,
    # so it isn't directly diagnosed as hanging
    time.sleep(10);
    
    logSize = 0
    hangDetected = False
    while(self.isFennecRunning()):
      time.sleep(self.runTimeout)

      if not os.path.exists(self.logFile):
        raise Exception("Logfile not present. If you are using websockets, this could indicate a network problem.")

      # Poor man's hang detection. Yes, this is a bad
      # idea, just for the sake of proof-of-concept
      newLogSize = os.path.getsize(self.logFile)
      if (logSize == newLogSize):
        hangDetected = True
        break
      else:
        logSize = newLogSize

    if hangDetected:
      self.stopFennec()
      while (len(self.logProcesses) > 0):
        self.logProcesses.pop().terminate()
      print "Hang detected"
    else:
      # Fennec died
      dumps = self.getMinidumps()
      if (len(dumps) > 1):
        raise Exception("Multiple dumps detected!")

      if not self.fetchMinidump(dumps[0]):
        raise Exception("Failed to fetch minidump with UUID " + dumps[0])

      # Terminate our logging processes and copy logfiles
      while (len(self.logProcesses) > 0):
        self.logProcesses.pop().terminate()
      shutil.copy2(self.syslogFile, dumps[0] + ".syslog")
      shutil.copy2(self.logFile, dumps[0] + ".log")

      minidump = Minidump(dumps[0] + ".dmp", self.libDir)

      print "Crash detected. Reproduction logfile stored at: " + dumps[0] + ".log"
      crashTrace = minidump.getCrashTrace()
      crashType = minidump.getCrashType()
      print "Crash type: " + crashType
      print "Crash backtrace:"
      print ""
      print crashTrace

      self.triager.process(minidump, dumps[0] + ".syslog", dumps[0] + ".log")

    self.HTTPProcess.terminate()
    return

  def testCrash(self):
    self.remoteInit()

    # Ensure Fennec isn't running
    if self.isFennecRunning():
      self.stopFennec()

    # Clean all existing minidumps
    if not self.clearMinidumps():
      raise Exception("Failed to clean existing minidumps")

    # Start our HTTP server for serving the fuzzer code
    self.HTTPProcess = self.startHTTPServer()

    # Start Fennec
    self.startFennec()

    startTime = time.time()

    while(self.isFennecRunning()):
      time.sleep(1)
      if ((time.time() - startTime) > self.runTimeout):
        self.stopFennec()
        self.HTTPProcess.terminate()
        return False

    self.HTTPProcess.terminate()

    # Fennec died, check for crashdumps
    dumps = self.getMinidumps()
    if (len(dumps) > 0):
      return True
    else:
      # Fennec exited, but no crash
      return False

  def getProfiles(self):
    profiles = []

    candidates = self.dm.listFiles(self.profileBase)
    for candidate in candidates:
      if self.dm.dirExists(self.profileBase + "/" + candidate + "/minidumps"):
        profiles.append(candidate)

    return profiles

  def getMinidumps(self):
    dumps = self.dm.listFiles(self.profileBase + "/" + self.defaultProfile + "/minidumps")
    dumpIDs = []

    for dump in dumps:
      if dump.find('.dmp') > -1:
        dumpIDs.append(dump.replace('.dmp',''))

    return dumpIDs

  def fetchMinidump(self, dumpId):
    dumpPath = self.profileBase + "/" + self.defaultProfile + "/minidumps/" + dumpId + ".dmp"
    print dumpPath
    if (self.dm.getFile(dumpPath, dumpId + ".dmp") != None):
      return True

    return False;

  def clearMinidump(self, dumpId):
    dumpPath = self.profileBase + "/" + self.defaultProfile + "/minidumps/" + dumpId + ".dmp"
    extraPath = self.profileBase + "/" + self.defaultProfile + "/minidumps/" + dumpId + ".extra"
    
    if (self.dm.removeFile(dumpPath) != None and self.dm.removeFile(extraPath) != None):
      return True

    return False;

  def clearMinidumps(self):
    dumps = self.getMinidumps()
    for dump in dumps:
      if not self.clearMinidump(dump):
        return False

    return True

  def startLoggers(self):
    if self.useWebSockets:
      # This method starts itself multiple processes (proxy included)
      self.startNewWebSocketLog()
    self.startNewDeviceLog()

  def startNewDeviceLog(self):
    # Clear the log first
    subprocess.check_call(["adb", "logcat", "-c"])

    # Logfile
    self.syslogFile = 'device.log'

    # Start logging
    logFile = open(self.syslogFile, 'w')
    logProcess = subprocess.Popen(["adb", "logcat", "-s", "Gecko:v", "GeckoDump:v", "GeckoConsole:v", "MOZ_Assert:v"], stdout=logFile)
    self.logProcesses.append(logProcess)

  def startNewWebSocketLog(self):
    self.logFile = 'websock.log'
    # TODO: Remove hardcoded port here
    logProcess = subprocess.Popen(["em-websocket-proxy", "-p", "8090", "-q", self.localWebSocketPort, "-r", "localhost"])
    self.logProcesses.append(logProcess)
    proxyProcess = subprocess.Popen(["python", "websocklog.py", "localhost", self.localWebSocketPort])
    self.logProcesses.append(proxyProcess)

  def startHTTPServer(self):
    HTTPProcess = subprocess.Popen(["python", "-m", "SimpleHTTPServer", self.localPort ])
    return HTTPProcess

  def startFennec(self):
    env = {}
    env['MOZ_CRASHREPORTER_NO_REPORT'] = '1'
    env['MOZ_CRASHREPORTER_SHUTDOWN'] = '1'
    self.dm.launchProcess([self.appName, "http://" + self.localAddr + ":" + self.localPort + "/" + self.fuzzerFile], None, None, env)

  def stopFennec(self):
    ret = self.dm.killProcess(self.appName, True)

    if self.isFennecRunning():
      # Try sleeping first and give the process time to react
      time.sleep(5)
      if self.isFennecRunning():
        # If the process doesn't terminate, try SIGKILL
        print "Process did not react to SIGTERM, trying SIGKILL"
        return self.dm.killProcess(self.appName, True)

    return ret

  def isFennecRunning(self):
    procList = self.dm.getProcessList()
    for proc in procList:
      if (proc[1] == self.appName):
        return True

    return False

if __name__ == "__main__":
  main()
