#!/usr/bin/python

import os
import subprocess

def main():
  testFile = sys.argv[1]

  if (testFile.endswith('.log')):
    # First, compose the test from the log
    subprocess.call(["python", "tools/compose.py", testFile, os.environ['FUZZFILE']])
    testFile = "testmin.html"
  
  exit(subprocess.call(["python", "adbfuzz.py", "reproduce", testFile, os.environ['TIMEOUT']]))

if __name__ == "__main__":
  main()
