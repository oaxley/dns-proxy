# @file     DNSQuery.py
# @author   Sebastien LEGRAND
# @date     2017-02-08
#
# @brief    Class to maintain the DNS queries
# @history
#           2017-02-08 - 1.0.0 - SLE
#           Initial Version

# imports
#----------
import struct


# globals
#----------


# functions
#----------


# class
#----------
class DNSQuery:
    # constructor
    def __init__(self):
        self.requestID  = None          # Request ID of the message
        self.flags      = 0             # Flags
        self.queries    = 0             # Number of queries in the message
        self.answers    = 0             # Number of answers in the message
        self.authority  = 0             # Number of authority
        self.additional = 0             # Number of additional fields
        self.domain     = None          # domain for the query

        self.ip         = None
        self.port       = None

        self.data       = None          # initial parameter of the client
        self.addr       = None


    # decode a request from the client
    def decode(self, data, addr):
        try:
            # decode the fields from the request
            self.requestID  = int( struct.unpack('>H', data[0:2])[0] )
            self.flags      = int( struct.unpack('>H', data[2:4])[0] )
            self.queries    = int( struct.unpack('>H', data[4:6])[0] )
            self.answers    = int( struct.unpack('>H', data[6:8])[0] )
            self.authority  = int( struct.unpack('>H', data[8:10])[0] )
            self.additional = int( struct.unpack('>H', data[10:12])[0] )
            self.data       = data
            self.addr       = addr

            # decode the domain name
            self.domain = ''
            index = 12
            while True:
                count = struct.unpack('B',data[index])[0]
                index = index + 1
                # end of the domain field
                if count == 0:
                    break

                text = data[index:index + count]

                # add the new string to the domain string
                if self.domain == '':
                    self.domain = text
                else:
                    self.domain = self.domain + '.' + text

                # next string
                index = index + count

            # decode the ip address
            self.ip, self.port = addr
        except:
            return None

        return True


    # create a packet for denying a request
    def deny(self):
        # prepare the DNS answer
        self.flags = 0x8583

        # create the new packet
        data = ''
        data = data + struct.pack('>H', self.requestID)
        data = data + struct.pack('>H', self.flags)
        data = data + struct.pack('>H', self.queries)
        data = data + struct.pack('>H', self.answers)
        data = data + struct.pack('>H', self.authority)
        data = data + struct.pack('>H', self.additional)
        data = data + self.data[12:]

        return data
