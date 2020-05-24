# @file     SignalHandler.py
# @author   Sebastien LEGRAND
# @date     2017-02-07
#
# @brief    Class to manage the signals
# @history
#           2017-02-07 - 1.0.0 - SLE
#           Initial Version

# imports
#----------
import signal


# globals
#----------


# functions
#----------


# class
#----------
class SignalHandler:
    # constructor
    def __init__(self, dummy):
        self.dummy = dummy
        self.application = dummy.application
        self.logger = dummy.logger


    # reload the configuration
    def USR1(self, signum, stack):
        self.logger.info("USR1: Reloading rules from the configuration...")
        self.application.config = None
        self.application.readConfig( self.dummy.config_path )

        # reload the rules
        self.dummy.dns_processor.reset()
        self.dummy.dns_processor.loadRules()

    # change the process rule
    def USR2(self, signum, stack):
        self.logger.info('USR2: switching rule processor mode...')
        self.dummy.dns_processor.switchMode()

    # stop the proxy gracefully
    def TERM(self, signum, stack):
        self.logger.info('TERM: stopping the proxy...')
        self.dummy.proxy.stop()

