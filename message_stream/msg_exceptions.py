#!/usr/bin/python

# pre-defined error constants
E_OK = 0
E_ERROR = 1   # generic error
E_COMERR = 2  # communication error
E_INVAL = 3   # invalid argument
E_NOENT = 4   # no entry (cannot read)
E_ISENT = 5   # already exists (cannot create)
E_ACCESS = 6  # permission error
E_LOW_MEM = 7 # out of memory (temporary)
E_NO_MEM = 8  # out of memory (fatal)
E_NO_DISK = 9 # out of disk space
E_PIPE = 10   # connection broken
E_INVCMD = 11 # invalid command
E_LOGIN = 12  # login failure
E_EXPSID = 13 # session id expired


E_DATAERR = 101     # data corruption error - in the process of being deprecated


# Exception handling is a bit messy here - trying to limit the usage of 
# 'ProtocolExceptions' to states which must be passed to the calling program
#
# - Ideally, this would allow this object to detect errors that can be smoothly
#   managed within a session, and raising the rest to the calling program -
#   this is very much a work in progress, and it's not used cleanly or 
#   consistently yet.
#
class ProtocolException(Exception):
    """
    Based off of the existing Protocol Error codes - adds in a message field
    for some additional info as desired
    """
    def __init__(self, _code, _message = ''):
        self.message = _message
        self.code = _code

    def __str__(self):
        str_repr = "[%d] %s" % (self.code, self.message)
        return str_repr


# The ProtocolException is intended to provide verification and some basic
# integrity checking on both the protocol level and the internal data level
#class ProtocolException(Exception):
#    def __init__(self, _message = ''):
#        self.message = _message
#    def __str__(self):
#        return self.message

class HeaderIncomplete(ProtocolException):
    pass
class PacketIncomplete(ProtocolException):
    pass
class HeaderCorruption(ProtocolException):
    pass
class DataCorruption(ProtocolException):
    pass


# use this for non-catchable exceptions or just catching debug states
class ProtocolFatal(Exception):
    def __init__(self, _message = ''):
        self.message = _message
    def __str__(self):
        return (self.message)

