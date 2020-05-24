# @file     Logger.py
# @author   Sebastien LEGRAND
# @date     2017-01-26
#
# @brief    Class to create a rotating logs
# @history
#           2017-01-26 - 1.0.0 - SLE
#           Initial Version

# imports
#----------
import logging

from logging.handlers import TimedRotatingFileHandler


# globals
#----------

# define wrappers around log levels
LOGGER_LEVEL_DEBUG      = logging.DEBUG
LOGGER_LEVEL_INFO       = logging.INFO
LOGGER_LEVEL_WARNING    = logging.WARNING
LOGGER_LEVEL_ERROR      = logging.ERROR
LOGGER_LEVEL_CRITICAL   = logging.CRITICAL


# class
#----------
class Logger:
    # constructor
    def __init__(self, dummy):
        self.dummy = dummy
        self.logLevel = None

        # retrieve the log file name from the configuration
        logfile = dummy.application.config.get("proxy", "log_file")

        # create a handler for rotating the logs every day and keeping 1 week of data
        self.logger = logging.getLogger("Rotating Log")
        handler = TimedRotatingFileHandler(logfile, when = "d", interval = 1, backupCount = 5)
        handler.setFormatter( logging.Formatter("%(asctime)s %(levelname)-8s %(message)s") )

        self.logger.addHandler(handler)

        # set the default level
        self.level(LOGGER_LEVEL_INFO)
        if self.dummy.application.config.has_option("proxy", "debug"):
            if self.dummy.application.config.getboolean("proxy", "debug") == True:
                self.level(LOGGER_LEVEL_DEBUG)
                self.debug("Mode debug activated")



    # set/get the log level
    def level(self, level = None):
        if level is None:
            return self.logLevel
        else:
            self.logLevel = level
            self.logger.setLevel(level)

    # send a debug message
    def debug(self, message, *args, **kwargs):
        self.logger.debug(message, *args, **kwargs)

    # send an info message
    def info(self, message, *args, **kwargs):
        self.logger.info(message, *args, **kwargs)

    # send a warning message
    def warning(self, message, *args, **kwargs):
        self.logger.warning(message, *args, **kwargs)

    # send an error message
    def error(self, message, *args, **kwargs):
        self.logger.error(message, *args, **kwargs)

    # send a critical message
    def critical(self, message, *args, **kwargs):
        self.logger.critical(message, *args, **kwargs)
