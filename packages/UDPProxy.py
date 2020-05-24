# @file     UDPProxy.py
# @author   Sebastien LEGRAND
# @date     2017-02-07
#
# @brief    UDP Proxy to forward the DNS request and control who access the DNS
# @history
#           2017-02-07 - 1.0.0 - SLE
#           Initial Version

# imports
#----------
import time
import socket
import select
import binascii

from DNSQuery import DNSQuery


# globals
#----------

MAX_BUFFER = 32768


# functions
#----------


# class
#----------
class UDPProxy:
    # constructor
    def __init__(self, dummy):
        self.dummy = dummy
        self.config = dummy.application.config
        self.logger = dummy.logger

        self.isRunning = False


    # initialize the proxy
    def initialize(self):
        # look for the proxy section in the configuration
        if self.config.has_section("proxy") == False:
            self.logger.error("Cannot find the 'proxy' section in the configuration!")
            return False


        # initialize all the variables
        #----------------------

        # listening port
        if self.config.has_option('proxy', 'listening_port'):
            self.listening_port = self.config.getint('proxy', 'listening_port')
            self.logger.info("Proxy will listen on port {0}".format(self.listening_port))
        else:
            self.logger.error("Option 'listening_port' is not present in the 'proxy' section!")
            return False

        # dns host
        if self.config.has_option('proxy', 'dns_host'):
            self.dns_host = self.config.get('proxy', 'dns_host')
        else:
            self.logger.error("Option 'dns_host' is not present in the 'proxy' section!")
            return False

        # dns port
        if self.config.has_option('proxy', 'dns_port'):
            self.dns_port = self.config.getint('proxy', 'dns_port')
        else:
            self.logger.error("Option 'dns_port' is not present in the 'proxy' section!")
            return False

        self.logger.info("DNS requests will be forwarded to {0}:{1}".format(self.dns_host, self.dns_port))

        return True


    # stop the proxy
    def stop(self):
        self.isRunning = False


    # run the proxy
    def run(self):
        # create the listening socket
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('', self.listening_port))
        except socket.error as e:
            self.logger.error('An error occured when creating the socket!: {0}'.format((str(e))))
            return

        # list of listening socket for select
        in_select = [ self.sock ]

        # main loop
        self.logger.info('Starting UDP proxy ...')
        self.isRunning = True

        while self.isRunning:

            # wait for an event while protecting select against select.error due to kill signal
            while self.isRunning:
                try:
                    # wait for a socket
                    rd, wr, ex = select.select(in_select, [], [])
                    break
                except select.error:
                    if self.isRunning == False:
                        rd = list()
                        break


            # treat only rd socket
            for sock in rd:
                # a new client has connected
                if sock == self.sock:

                    # retrieve the data and who connect
                    data, addr = sock.recvfrom(MAX_BUFFER)
                    if not data:
                        self.logger.debug('Connection {0} has closed.'.format(addr))
                        continue

                    self.logger.debug('New connection from {0}'.format(addr))
                    self.logger.debug('> {0}'.format(binascii.hexlify(data)))

                    # decode the DNS query
                    query = DNSQuery()
                    result = query.decode(data, addr)
                    
                    # unable to decode the packet!
                    if result is None:
                        continue

                    self.logger.info("New query from [{0}] : [{1}]".format(query.ip, query.domain))

                    # create the values for the rules processor
                    day = time.strftime("%a", time.localtime()).lower()
                    daytime = time.strftime('%H%M', time.localtime())
                    values = [ query.ip, query.domain, daytime, day ]

                    # check the rules
                    result = self.dummy.dns_processor.processRules(values)

                    # request has been denied
                    if result == False:
                        sock.sendto( query.deny(), addr )
                        continue

                    # request has been authorized -> request the real DNS
                    new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    new_sock.sendto(data, (self.dns_host, self.dns_port))
                    response, _ = new_sock.recvfrom(MAX_BUFFER)
                    new_sock.close()

                    # forward the answer to the initial caller
                    self.logger.debug('< {0}'.format(binascii.hexlify(response)))
                    sock.sendto(response, addr)


                # Wtf??
                else:
                    self.logger.error('Unknown socket???')

        self.logger.info('Proxy has been stopped')
