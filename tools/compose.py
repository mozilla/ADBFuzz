#!/usr/bin/python

import subprocess
import time
import shutil
import os
import sys

def main():
  logfile = sys.argv[1]
  fuzzFile = sys.argv[2]
  searchStr = sys.argv[3]
  logLines = []

  log = open(logfile, "r")
  rawLogLines = log.readlines()
  log.close()

  for rawLogLine in rawLogLines:
    idx = rawLogLine.find(searchStr)
    if (idx > -1):
      rawLogLine = rawLogLine[idx:]
      # Remove the nasty \r from adb shell output
      logLines.append(rawLogLine.translate(None, '\r'))
 
  jsf = open(fuzzFile, "r")
  jsfo = open("testmin.js", "w")
  skipTillSplice = False
  for line in jsf.readlines():
    if skipTillSplice and not line.find("SPLICE") > -1:
      next
    elif line.find("SPLICE") > -1:
      if skipTillSplice:
        skipTillSplice = False
      else:
        jsfo.writelines(logLines)
        skipTillSplice = True
    else:
      jsfo.write(line)

  jsf.close()
  jsfo.close()

if __name__ == "__main__":
  main()
