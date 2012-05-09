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

import smtplib

class Mailer:
  def __init__(self, config):
    self.config = config
    
  def notify(self, issueUUID, issueDesc, miniDump):
    
    msg = ("From: %s\r\nTo: %s\r\n" % (self.config.mailFrom, self.config.mailTo))
    msg = msg + "Subject: [ADBFuzz] Issue report: " + issueDesc + "\r\n\r\n"
    msg = msg + "Crash UUID: " + issueUUID + "\r\n"
    msg = msg + "Instance identifier: " + self.config.id + "\r\n"
    msg = msg + "\r\n"
    
    if miniDump != None:
      msg = msg + "Crash trace:" + "\r\n"
    
      crashTrace = miniDump.getSymbolizedCrashTrace()
    
      for (frameNum, frameAddr, frameFile) in crashTrace:
        msg = msg + "  " + frameNum + " " + frameAddr + " " + frameFile + "\r\n"

    server = smtplib.SMTP(self.config.SMTPHost)
    server.set_debuglevel(1)
    server.sendmail(self.config.mailFrom, [ self.config.mailTo ], msg)
    server.quit()

    return

if __name__ == "__main__":
  raise Exception("This module cannot run standalone, but is used by ADBFuzz")
