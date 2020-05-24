#!/usr/bin/env python
# @file     dnsProxy.py
# @author   Sebastien LEGRAND
# @date     2017-01-26
#
# @brief    Implement a DNS proxy to control access to the DNS via a set of rules
# @history
#           2017-01-26 - 1.0.0 - SLE
#           Initial Version
# @notes
#           Signals allow the user to interact with the software:
#           USR1 : reload the configuration
#           USR2 : switch the proxy between active/inactive
#           TERM : gracefuly stop the proxy

# imports
#----------
import sys
import signal
import argparse

import packages


# globals
#----------

# define the application object
app = packages.Application.getInstance()
app.PROGRAM_VERSION = "1.0.0"


# functions & classes
#----------

# dummy object to hold the global variable to one place
class Dummy:
    def __init__(self):
        pass


# begin
#----------

# create global vars
myVars = Dummy()
myVars.application = app

# create the lock
appLock = packages.Lock("/tmp/{0}.lock".format(app.PROGRAM_NAME))
try:
    # try to acquire the lock
    appLock.acquire(blocking = False)

    # read the command line
    parser = argparse.ArgumentParser(version=app.PROGRAM_VERSION)
    parser.add_argument("-c", "--config", action="store", dest="config", help="Configuration file", required=True)
    args = parser.parse_args()

    # read the configuration file
    myVars.config_path = args.config
    app.readConfig(myVars.config_path)

    # create the logger
    myVars.logger = packages.Logger(myVars)
    myVars.logger.info("********************************")
    myVars.logger.info("* DNS Proxy / Parental Control")
    myVars.logger.info("* S. LEGRAND / v.{0}".format(app.PROGRAM_VERSION))
    myVars.logger.info("********************************")

    # create the rule processor and load the rules
    myVars.dns_processor = packages.RuleProcessor(myVars)
    myVars.dns_processor.loadRules()

    # change the signal handler
    myVars.signals = packages.SignalHandler(myVars)
    signal.signal(signal.SIGUSR1, myVars.signals.USR1)
    signal.signal(signal.SIGUSR2, myVars.signals.USR2)
    signal.signal(signal.SIGTERM, myVars.signals.TERM)

    # create the proxy
    myVars.proxy = packages.UDPProxy(myVars)
    if myVars.proxy.initialize() == True:
        myVars.proxy.run()

    # last message
    myVars.logger.info("*********** END ****************")

# exception thrown by the Lock mechanism
except IOError:
    sys.exit(1)

# release the lock
finally:
    appLock.release()


