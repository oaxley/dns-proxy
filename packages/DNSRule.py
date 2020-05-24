# @file     DNSRule.py
# @author   Sebastien LEGRAND
# @date     2017-01-26
#
# @brief    Class to maintain DNS Rule in a simple format
# @history
#           2017-01-26 - 1.0.0 - SLE
#           Initial Version

# imports
#----------


# class
#----------
# The text should have the following format:
# day of the week (mon-sun|*);start time (00:00-23:59)-stop time (00:00-23:59);ip address or *;allow|deny
class DNSRule:
    # constructor
    def __init__(self, text, section, aliases = None):
        # split the rule by its fields and remove the ':' from the hours
        d,t,i,a = text.split(';')
        start, stop = t.replace(':', '').split('-')

        # store the values in these fields
        self.day     = d.lower()
        self.start   = start
        self.stop    = stop
        self.action  = a.lower()
        self.section = section

        # check if the ip is a name
        if i[0].isdigit():
            self.ip = i
        else:
            if aliases and (i.lower() in aliases):
                self.ip = aliases[i.lower()]
            else:
                self.ip = i.lower()


    # create a string object with the values
    def __str__(self):
        return "{5} / {0};{1}-{2};{3};{4}".format(self.day, self.start, self.stop, self.ip, self.action, self.section)

