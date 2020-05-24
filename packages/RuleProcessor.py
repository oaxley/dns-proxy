# @file     RuleProcessor.py
# @author   Sebastien LEGRAND
# @date     2017-01-26
#
# @brief    DNS Rule Processor to validate DNS requests against a set of rules
# @history
#           2017-01-26 - 1.0.0 - SLE
#           Initial Version

# imports
#----------
import re
import time
import threading

from DNSRule import DNSRule


# globals
#----------

RULE_MATCHED = True
RULE_DO_NOT_MATCHED = False

VALUES_IP = 0
VALUES_DOMAIN = 1
VALUES_TIME = 2
VALUES_DAY = 3


# functions
#----------


# class
#----------
class RuleProcessor:
    def __init__(self, dummy):
        # configuration
        self.dummy  = dummy
        self.logger = dummy.logger

        # lock
        self.lock = threading.Lock()

        # dictionary to contain rules
        self.rules = dict()
        self.count = 0

        # current rule matched
        self.current = None

        # default action
        self.default_action = None

        # process rules trigger
        self.process_rule = True
        self.enable_time  = None
        self.disable_time = None


    # switch the process rules

    # reset the rules
    def reset(self):
        # acquire the lock before resetting things
        self.lock.acquire()

        self.rules = dict()
        self.count = 0
        self.default_action = None
        self.current = None

        self.process_rule = True
        self.enable_time  = None
        self.disable_time = None

        # release the lock
        self.lock.release()


    # switch the mode
    def switchMode(self):
        self.logger.warning('Switching rule processor from {0} to {1}'.format(self.process_rule, not(self.process_rule)))
        self.process_rule = not self.process_rule

    # load the rules
    def loadRules(self):
        # acquire the lock
        self.lock.acquire()

        config = self.dummy.application.config

        # read the aliases
        aliases = dict()
        if config.has_section("aliases"):
            for alias in config.options("aliases"):
                value = config.get("aliases", alias)
                aliases[alias.lower()] = value

        # read all the section
        for section in config.sections():

            # ignore the "proxy" and "aliases" sections
            if (section.lower() == "proxy") or (section.lower() == "aliases"):
                continue

            # specific case for generic section
            if section.lower() == "generic":
                domain = "generic"
            else:
                # ignore section badly configured
                if config.has_option(section, "domain") == False:
                    self.logger.warning("Section [{0}] has no domain defined !".format(section))
                    continue
                else:
                    domain = config.get(section, "domain")

            # add the domain to the rules list
            if domain not in self.rules:
                self.rules[domain] = list()

            # read the rules for this domain
            for rule in config.options(section):

                # ignore domain
                if rule == "domain":
                    continue

                # create a rule object
                text = config.get(section, rule)
                try:
                    obj = DNSRule( text, section, aliases )
                    self.rules[domain].append(obj)

                    # rule counter
                    self.count = self.count + 1
                except:
                    self.logger.error("An error occured when parsing the rule '{0}' for domain '{1}'.".format(text, domain))
                    self.logger.error("Rule has been skipped.")

        # print a line in the logs
        self.logger.info("{0} rules loaded.".format(self.count))

        # load the default action
        self.default_action = config.get("proxy", "default_action")

        # load the processor other variables
        if config.has_option('proxy', 'process_rule'):
            self.process_rule = config.getboolean('proxy', 'process_rule')
        else:
            self.process_rule = True

        # enable / disable processor time
        if config.has_option('proxy', 'enable_processor_time'):
            self.enable_time = config.get('proxy', 'enable_processor_time').replace(':','')
            self.logger.info("Enable time set to {0}".format(self.enable_time))
        else:
            self.enable_time = None

        if config.has_option('proxy', 'disable_processor_time'):
            self.disable_time = config.get('proxy', 'disable_processor_time').replace(':','')
            self.logger.info("Disable time set to {0}".format(self.disable_time))
        else:
            self.disable_time = None

        # avoid discrepancy in the enable / disable
        if (self.enable_time == None) or (self.disable_time == None):
            self.enable_time  = None
            self.disable_time = None


        # release the lock
        self.lock.release()


    # process the rules against a set of parameters
    def processRules(self, values):
        # acquire the lock
        self.lock.acquire()

        # check if we need to proceed
        if self.process_rule == False:
            self.logger.debug('Rule Processor is disabled. Request accepted.')
            self.lock.release()
            return True

        # check the time
        if self.enable_time:
            if not ((values[VALUES_TIME] > self.enable_time) and (values[VALUES_TIME] < self.disable_time)):
                self.logger.debug('Time outside check boundaries. Request accepted.')
                self.lock.release()
                return True


        self.logger.debug("Values = {0}".format(values))

        # reset the current matching rule
        self.current = None

        # process the generic rules first
        self.logger.debug("Testing generic rules")
        for rule in self.rules['generic']:
            self.logger.debug("Processing rule '{0}'".format(rule))
            result = self.__processRule(rule, values)
            if result == RULE_MATCHED:
                self.logger.debug("Rule matched")
                self.current = rule
            else:
                self.logger.debug("Rule did not matched")

        # process the specific rules
        self.logger.debug("Testing specific rules")
        for domain in self.rules.keys():
            if domain == "generic":
                continue

            # check if the domain match
            if re.search(domain, values[VALUES_DOMAIN]):
                self.logger.debug("Requested domain '{0}' match '{1}'".format(values[VALUES_DOMAIN], domain))

                for rule in self.rules[domain]:
                    self.logger.debug("Processing rule '{0}'".format(rule))
                    result = self.__processRule(rule, values)
                    if result == RULE_MATCHED:
                        self.logger.debug("Rule matched")
                        self.current = rule
                    else:
                        self.logger.debug("Rule did not matched")

        # action to be taken
        result = None

        # nothing has matched
        if self.current is None:
            self.logger.warning("No rule has been found for this set of parameters.")
            action = self.default_action

            if self.default_action == "deny":
                self.logger.warning("Domain has been denied by default action.")
                result = False
            else:
                self.logger.warning("Domain has been accepted by default action.")
                result = True
        else:
            # action taken
            if self.current.action == 'allow':
                self.logger.debug("Domain has been accepted by rule {0}.".format(self.current))
                result = True
            else:
                self.logger.warning("Domain has been denied by rule {0}.".format(self.current))
                result = False

        # release the lock
        self.lock.release()
        return result


    # check one rule at a time
    # values[0] = ip address of the requester
    # values[1] = domain requested
    # values[2] = time of the request
    # values[3] = current day of the week
    #
    def __processRule(self, rule, values):
        if (rule.day != '*') and (rule.day != values[VALUES_DAY]):
            return RULE_DO_NOT_MATCHED

        # check the ip
        if (rule.ip != '*') and (rule.ip != values[VALUES_IP]):
            return RULE_DO_NOT_MATCHED

        # start and stop are wildcards
        if (rule.start == '*') and (rule.stop == '*'):
            pass   # nothing to be done

        # start is a wildcard
        if (rule.start == '*') and (rule.stop != '*'):
            if values[VALUES_TIME] > rules.stop:
                return RULE_DO_NOT_MATCHED

            if self.current:
                if (self.current.stop != '*') and (rules.stop > self.current.stop):
                    return RULE_DO_NOT_MATCHED

        # start & stop are not wildcard
        if (rule.start != '*') and (rule.stop != '*'):
            if (values[VALUES_TIME] < rule.start) or (values[VALUES_TIME] > rule.stop):
                return RULE_DO_NOT_MATCHED

            if self.current:
                if self.current.start != '*':
                    start = self.current.start
                else:
                    start = "0000"

                if self.current.stop != '*':
                    stop = self.current.stop
                else:
                    stop = "2359"

                if (rule.start < start) and (rule.stop > stop):
                    return RULE_DO_NOT_MATCHED

        # stop is a wildcard
        if (rule.start != '*') and (rule.stop == '*'):
            if values[VALUES_TIME] < rule.start:
                return RULE_DO_NOT_MATCHED

            if self.current:
                if (self.current.start != '*') and (rule.start < self.current.start):
                    return RULE_DO_NOT_MATCHED

        # if we passed all the test, the rule has matched
        return RULE_MATCHED
