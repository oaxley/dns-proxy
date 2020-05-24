# @file     Application.py
# @author   Sebastien LEGRAND
# @date     2017-01-26
#
# @brief    Application class
# @history
#           2017-01-26 - 1.0.0 - SLE
#           Initial Version

# imports
#----------
import os
import sys
import ConfigParser


# globals
#----------

# variable to hold an instance of Application class
__instance = None


# functions
#----------

# return the instance of the class
def getInstance():
    return __instance


# class
#----------

# this class should not be called by external modules
class __DummyClass():
    # constructor
    def __init__(self):
        # program name is derivated from the cmdline arguments
        self.PROGRAM_NAME = os.path.basename(sys.argv[0])

        # program version should be set by the developer at the begining
        self.PROGRAM_VERSION = ""

        # empty configuration
        self.config = None


    # read the configuration files
    def readConfig(self, path):
        if not os.path.exists(path):
            return

        if self.config is None:
            self.config = ConfigParser.ConfigParser()
            self.config.readfp(open(path))
        else:
            self.config.read(path)


# create an instance of the class
__instance = __DummyClass()
