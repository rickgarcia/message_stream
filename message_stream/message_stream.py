#!/usr/bin/python
#
import sys
if sys.version_info < (2, 6):
    raise "requires python v2.6"
import socket
import time
import re
import threading

from security import encrypt_login
from msg_dtypes import *
from msg_exceptions import *

################################################# 
# internal constants

#TODO: move to a config file
DEFAULT_PORT = 50000  # Default message bus port 

# message types
MTYPE_CMD = '100'
MTYPE_REPLY = '200'

# Largest bulk size for post_bulk we're allowing here...
MAX_BULKSZ = 2048

# set the RECV_BUFSZ low (<= 1024) to force data fragmentation
# in order to test error handling exceptions; set above typical
# packet size to speed up normal operation (>= 2048)
RECV_BUFSZ = 4096


########
# network communication defs

# add the protocol header to a packet
def prepend_header(data_packet1, data_packet2):
    packet1_len= len(data_packet1)
    packet2_len= len(data_packet2)
    header = "%d/1.0 %d %d\r\n" % ("stream", packet1_len, packet2_len)
    return header + data_packet1 + data_packet2


#
# this can probably be handled better as a class
# TODO: Implement as a class and see if it's prettier
#
def stream_socket(d_host, d_port = DEFAULT_PORT, timeout = 5):
    s = None
    for res in socket.getaddrinfo(
            d_host, d_port, socket.AF_UNSPEC, socket.SOCK_STREAM):

        af, socktype, proto, canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
        except socket.error, msg:
            s = None
            continue
        try:
            # timeout on initial connection, then wait and listen
            d_to = socket.getdefaulttimeout()
            s.settimeout(timeout)
            retval = s.connect(sa)
            s.settimeout(d_to)
        except socket.error, msg:
            s.close()
            s = None
            continue
        break
    if s is None:
        raise ProtocolException(E_COMERR, 'socket error')

    return s


#
#
def _parse_protocol_header(_packet):
    """
    header definition
      - protocol/version.ver 123 456
      - this regex allows for a protocol, version and multiple data sets
        to be attached.  The end of the size list is indicated by an eol char,
        either '\x0d\x0a' for '\r' or just a '\x0a' for '\n'.
        The data packet sizes are space delimited.
      - The space in front of the size list is included in the regex to
        prevent an empty string in the split tuple - the delimiter from
        version->size list can be different
      - sizes is translated from the integer list
      - _data is a potentially incomplete binary data string; sizes defines
        how much data is supposed to be in the total string
    """
    try:
        parse_header = re.match(
            r"^(\w+)\/([\d\.]+)\s?([ \d]+)[\x0a\x0d]+(.*)",
            _packet)
    except Exception as e:
        raise ProtocolException(E_DATAERR, 
                              "header format: %s" % repr(_packet[:20]))

    try:
        (protocol, version, size_list, _data) = parse_header.groups()
        packet_size_list = re.split('\s+', size_list, 16)
    #except (ValueError, IndexError), e:
    except Exception as e:
        raise ProtocolException(E_DATAERR,
                              "header sizes: %s" % repr(_packet[:20]))

    # because some calls require multiple packets, the _data field here
    # may be incomplete - calling functions need to verify that the complete
    # data field is being received.
    return {
        'protocol' : protocol,
        'version' : version,
        'sizes' : map(int, packet_size_list),
        '_data' : _data
    }


#
# testing out some different matching from the other version of this def...
# - go ahead and throw errors - calling function should catch
protocol_match = None
def stream_parse_message(_packet):
    # for whatever reason, this is failing to match properly when attempting
    # to capture trailing data completely - so just grab the header and 
    # then get the end of the match from the regex
    global protocol_match
    if protocol_match is None:
        protocol_match = re.compile(r"^(\w+)\/([\d\.]+)\s([\d\s]+)\x0d\x0a")
    try:
        parse_header = protocol_match.match(_packet)
        (protocol, version, size_list) = parse_header.groups()
        data_start_index = parse_header.end()

    # there doesn't seem to be a good consistent way to disinguish between
    # a corrupt or incomplete header - so just ensure that the chunk
    # size is greater than the probable header length (>20), and assume
    # corruption if it's above that - this is imperfect, but works
    # in the vast majority of the pathological cases - we can get more 
    # specific by testing for stricter protocol definitions
    except AttributeError as e:
         if (len(_packet) < 20):
             raise HeaderIncomplete(repr(_packet))
         else:
             raise HeaderCorruption(repr(_packet[:32]))

    packet_size_list = re.split('\s+', size_list, 16)
    sizes = map(int, packet_size_list)
    full_data_len = sum(sizes)

    # this check is, unfortunately, still needed... ideally, there'd be a way
    # to handle this via direct exception, but IndexErrors are unsafe when
    # being used on binary strings, as they don't always trigger when accessing
    # out-of-bounds indexes on strings with internal \0 chars
    if (len(_packet) < (full_data_len + data_start_index)):
         raise PacketIncomplete(
            "packet_incomplete: %d/%d" % (len(_packet), full_data_len))

    # parse out the header/data/trailing data from the data stream
    # - here is where an invalid index doesn't necessarily trigger an 
    #   IndexError exception - so we need to test manually above
    # NOTE: explicit index handling here could probably reduce some memory
    #       load during the parsing
    try:
        _data = _packet[data_start_index:]
        pkt_data = _data[:full_data_len]
        trailing_data = _data[full_data_len:]
        # parse out the header/data sections from the packet sections
        # - same IndexError caveats apply as above
        d_index = 0
        d_struct = {}
        for _size in sizes:
            d_struct[d_index] = pkt_data[:_size]
            pkt_data = pkt_data[_size:]
            d_index += 1

    except IndexError as e:
        raise PacketIncomplete("packet_data_incomplete: %s" % pkt_data[:32])

    return {
        'protocol' : protocol,
        'version' : version,
        'sizes' : sizes,
        'data' : d_struct,
        '_data' : trailing_data
    }


# request_reply
#
# requires a socket and a message - returns reply or raises an exception
#
# -  Verifing a full reply reception requires parsing the protocol header;
#    the struct returned is:
#
#     p_header = {
#        'protocol' : protocol,
#        'version' : version,
#        'sizes' : int[]
#        'data' : unparsed_bin_data
#     }
#
#    _parse_protocol_header returns a similar struct, but with an incomplete
#    '_data' entry which contains the beginning of binary data; if the data
#    is incomplete according to the size, then pull data off the socket until
#    the entry is complete
#
#    TODO: add timeout handling to the recv calls - should be rare, but need
#          to be handled for stability 
#
def request_reply(msg_sock, req_msg):
    """
    This allocates an initial buffer for receiving messages and parses
    the header to determine if there is any left to receive;
    any remaining data is then allocated for and retrieved
    """
    try:
        msg_sock.send(req_msg)
    except socket.error, msg:
        raise msg

    # grab the first 32 bytes and parse to get some valid sizes
    reply_data = msg_sock.recv(32)
    p_header = _parse_protocol_header(reply_data)

    # determine how much data remains for the message
    msg_data_len = sum(p_header['sizes'])
    bytes_left = msg_data_len - len(p_header['_data'])

    # add on any remaining data from the stream and remove the partials
    while (bytes_left > 0):
        # size read off of the socket isn't consistent - it can return any
        # size up to and including the block size
        next_block = msg_sock.recv(RECV_BUFSZ)
        # subtract whatever was received
        bytes_left -= len(next_block)
        p_header['_data'] = p_header['_data'] + next_block

    # verify that the full message is received 
    if (len(p_header['_data']) != msg_data_len):
        raise ProtocolException(E_DATAERR,
                              '_dsize mismatch',
                              {'_data': p_header['_data'][:20]})
   
    # loop thru the datum sizes and parse them out to the dict 
    data_index = 0
    data_struct = {}
    for _size in p_header['sizes']:
        data_struct[data_index] = p_header['_data'][:_size]
        p_header['_data'] = p_header['_data'][_size:]
        data_index += 1
        
    p_header['data'] = data_struct
    del p_header['_data']

    return p_header



#debug data dumping function...
# 
def dump_dict(_dict):
    for _key in sorted(_dict):
        print "%30s : %s" % (_key, repr(_dict[_key]))
# dump full packet
def dump_full_packet(_packet):
    print "  Protocol: %s" % _packet['protocol']
    print "  Version : %s" % _packet['version']
    for i in _packet['data']:
        print "  _d_packet[%d]:" % i
        dump_dict(_packet['data'][i])
    return E_OK
# 
def _dump_dict(_dict):
    for _key in sorted(_dict):
        print >> sys.stderr, "%30s : %s" % (_key, _dict[_key])
# dump full packet
def _dump_full_packet(_packet):
    print >> sys.stderr, "  Protocol: %s" % _packet['protocol']
    print >> sys.stderr, "  Version : %s" % _packet['version']
    for i in _packet['data']:
        print >> sys.stderr, "  _d_packet[%d]:" % i
        _dump_dict(_packet['data'][i])


# - this is really just a helper def to generate a command structure with 
# the appropriate field names
#
# the command structure requires a bit of flexibility - I don't usually
# like parameter strings this long
def _cmd_struct(_address, _command, _ip, _port, _timeout = 10, _sid = None):

    _cmd = {
        'mtype' : MTYPE_CMD,
        'cmd' : _command,
        'ts' : int(time.time()),
        'src' : ("%s/%d" % (_ip, _port)),
        'timeout' : _timeout,
        'seq' : 0,
        'addr' : _address,
    }
    if (_sid is not None):
        _cmd['sid'] = _sid
    return _cmd


#
#
def _generate_login_args(username, password):

    # just one right now, but additional addresses can be added by config
    # note: the iplist should be stored in the class
    ip_list = "|%s|" % ("|".join(_get_ip_list()))
    login_data = {
            "time" : int(time.time()),
            "type" : 0,
            "id" : username,
            "password" : password,
            "ip_list" : ip_list
    }

    # the login arguments require both the encrypted data string and the
    # non-packed length of the unencrypted data
    #
    # convert the packed string to a binary string
    login_packed = dtype_binary(str(binarypack_pystruct(login_data)))

    # encrypt the login info; zero-pack to 16 bytes
    enc_login = encrypt_login(login_packed, 16)

    return {
        "encrdta" : enc_login,
        "encrlen" : len(login_packed),
        "mode" : 0,
        "type" : 0
    }


#
# generate a list of ip addresses present on the box - this can be
# generalized a bit more to loop thru the 'eth%d' 'wlan%d' until there's an
# error, indicating that there are no more interfaces
SIOCGIFADDR = 0x8915
def _get_ip_list():
    import os
    import fcntl
    import struct

    # read the addresses from the inet interface
    # This probably needs to be fixed for ipv6 - needs testing
    def get_interface_ip(ifname):
        _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _interface_ip = socket.inet_ntoa(
            fcntl.ioctl(
                _sock.fileno(), 
                SIOCGIFADDR, 
                struct.pack('256s', ifname[:15]))[20:24])
        _sock.close()
        return _interface_ip
                                
    _ip_list = []
    interfaces = [
        "eth0", "eth1", "eth2", "eth3", "eth4",
        "en0", "en1", "en2", "en3", "en4",
        "wlan0", "wlan1",
        "wifi0",
        "ath0", "ath1",
        "ppp0",
        "lo"
        ]
    for ifname in interfaces:
        try:
            ip = get_interface_ip(ifname)
            _ip_list.append(ip)
        except IOError:
            pass
    return _ip_list

# This is independent of both server and session
# TODO: pull the address_lookup out of session
class address_cache:
    pass


# thread decorator for session functions
def threaded(fn):
    def wrapper(*args, **kwargs):
        w_thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        w_thread.daemon = True
        w_thread.start()
    return wrapper

#
#
class session:
    """
    This should control a full session from login to logout, ideally hiding
    all the implementation specific details so that commands can be called
    with pure python data structures
    """

    def set_sessionid(self, sid):
        self._sid = sid

    # if we're dealing with multiple sessions, we might want to look into 
    # the possibility of making this singleton across the sessions
    def address_lookup(self, address):
        """ address to ip/port resolution """
        if (self._cache_addresses):
            try:
                _a_ns_rslv = self._addr_cache[address]
                return _a_ns_rslv
            except (IndexError, KeyError) as e:
                pass

        try:
            _a_ns_rslv = self.local_message('nametoip', {'name': address})
        except ProtocolException as e:
            raise ProtocolException(e.code, "name resolution: %s" % address)

        # return the resolved name addr
        if (self._cache_addresses):
            self._addr_cache[address] = _a_ns_rslv
        return _a_ns_rslv 


    # yep. this needs to be a class.
    #
    # On reconsideration, it may be that this needs to be abstracted under
    # a "connection" class, and may become either "subscription" or "server"
    # and allow the message subs to be combined... depending on usage...
    #
    # TODO: implement clean close (_close for reply)
    #       implement thread listener to trigger clean close 
    @threaded
    def subscribe(self, _address, _queue, _id, _callback, 
                  _bulk = None, _timeout = 10):

        cmd_thread = threading.current_thread()
        thread_status = {
            'command': 'subscribe',
            'args':  (_queue, _id, _bulk),
            'rx_msgs': 0, 
            'tx_msgs': 0, 
            'address': _address,
            'sequence': 0,
            'status': E_OK
            } 
        self._threads[cmd_thread] = thread_status
        
        _a_ip = self.address_lookup(_address)
        s = stream_socket(_a_ip['ip'], _a_ip['port'])

        (ip_addr, localport) = s.getsockname()
        # set the timeout for the initial command, but set to 'None' after the
        # initial 'subscribe' reply
        s.settimeout(_timeout)

        # subscribe command
        queue_args = {
            'attach': _queue,
            'id': _id
        }
        if (_bulk is not None):
            queue_args['bulk_size'] = _bulk

        _cmd = _cmd_struct('', 'subscribe', ip_addr, localport, 
                           _timeout, self._sid)
        cmd_packet = prepend_header(binarypack_pystruct(_cmd),
                                    binarypack_pystruct(queue_args))

        try:
            s.send(cmd_packet)
        except socket.error, msg:
            raise ProtocolException(E_COMERR, repr(msg))

        _first_reply = 1
        prev_seq = 0

        # setup a buffer... string handling here is painful
        buffers = []

        # this loop should probably be status controlled instead of always true
        subs_rc = E_OK
        #while (subs_rc == E_OK):
        while True:

            # string appends are significantly faster than '+' - at least in
            # the initial py version we're using here...
            _recv_buffer = s.recv(RECV_BUFSZ)
            buffers.append(_recv_buffer)

            # message/data parsing - critical error checking done here
            try:
                # stream_parse_message will guarantee that the buffer
                # contains a valid protocol header and at least enough data
                # constitute a full message from that header.  It can raise
                # three exceptions:
                # - header incomplete - keep listening
                # - data incomplete - keep listening
                # - header corrupt - drop data and try to continue
                p_header = stream_parse_message("".join(buffers))

                # at this point, we have enough data to satisfy the header,
                # but no guarantee of the internal data consistency.  This
                # sub will parse through the message data and raise an 
                # exception on corruption - data corruption is pretty much
                # the only possible error here, as size is already checked
                # by the message protocol
                message_struct = parse_message_data(p_header)

            # this catches header errors and incomplete data states
            except (PacketIncomplete, HeaderIncomplete) as e: 
                continue
            # this catches internal data errors
            except (HeaderCorruption, DataCorruption) as e:
                # recovering from data corruption in the buffer requires
                # discarding all previously received data in the buffers
                # since the last good message - this somewhat depends on the
                # other side communicating properly, so all we can do is
                # return an error message and wait for a proper recover
                # response - otherwise, the thread must exit.
                # Note - it's definitely possible to recover from many types
                #        of data errors, but because it's expensive to correct
                #        *and* re-sync with the other side, we'll simply 
                #        error out and let the watcher handle this for now
                s.close()
                raise e

            # clear out the buffers and append any trailing stream data
            buffers = []
            buffers.append(p_header['_data'])

            # message sequence management
            if ((p_header['data'][0]['seq'] != (prev_seq + 1) and
                    (prev_seq != 0))):
                s.close()
                raise PacketCorruption("ooseq error: %d/%d" % 
                    (p_header['data'][0]['seq'], prev_seq))
            prev_seq = message_struct['data'][0]['seq']

            # check the message type
            try:
                msg_type = message_struct['data'][0]['mtype']
            except KeyError as e:
                s.close()
                thread_status['status'] = E_ERROR
                raise PacketCorruption("invalid message: %s" % 
                    (repr(message_struct)[:64]))

            # update the thread statistics
            thread_status['rx_msgs'] += 1
            thread_status['sequence'] = prev_seq

            # message dispatching - determine the message type and reply or
            # dispatch per message type and command
            if (msg_type == MTYPE_CMD):
                if (message_struct['data'][0]['cmd'] == '_close'):
                    s.close()
                    break
                elif (message_struct['data'][0]['cmd'] == 'post'):
                    subs_rc = _callback(message_struct)
                elif (message_struct['data'][0]['cmd'] == 'post_bulk'):
                    subs_rc = _callback(message_struct)
                else:
                    s.close()
                    thread_status['status'] = E_ERROR
                    raise ProtocolFatal("unhandled cmd: " + repr(message_struct))
            elif (msg_type == MTYPE_REPLY):
                subs_rc = message_struct['data'][0]['status']

                # don't think there's any error state to handle here...
                try:
                   _bulksz = message_struct['data'][1]['bulk_size']
                   if (_bulksz > MAX_BULKSZ):
                       raise ProtocolFatal("invalid bulk size (%d) " % _bulksz)
                   thread_status['bulk_size'] = _bulksz
                except (KeyError, IndexError) as e:
                    pass

                # the socket needs a timeout set when first establishing comms,
                # but sits and listens after that - so set the timeout to None
                # after we get a the first (seq = 0) reply
                if (prev_seq == 0):
                    s.settimeout(None)

                # and go back to the beginning to listen for more posts
                continue

            else:
                s.close()
                thread_status['status'] = E_ERROR
                raise ProtocolFatal("unhandled msg type %d" % msg_type)

            # ...and, reply - essentially an ack with sequence # and status
            _reply = {
                'mtype': MTYPE_REPLY,
                'seq': prev_seq,
                'status': subs_rc
            }
            try:
                s.send(prepend_header(binarypack_pystruct(_reply), 
                                      binarypack_pystruct(None)))
            except Exception as e:
                thread_status['status'] = E_COMERR
                raise ProtocolException(E_COMERR, 'socket exception')
            thread_status['tx_msgs'] += 1

        return subs_rc


    # ping the connection to determine if we're up
    def ping(self):
        pass

    # test the id to ensure it's valid
    def session_validate(self):
        pass

    # intended to provide abstraction for patterned messages (message
    #   transactions with a particular required communication flow)
    def _message(self, _address, _command, _arguments=None, _timeout=10):

        # open up a socket to the proper address
        _a_ip = self.address_lookup(_address)
        s = stream_socket(_a_ip['ip'], _a_ip['port'])
        (ip_addr, localport) = s.getsockname()

        # setup a command packet
        _cmd = _cmd_struct(_address, _command, ip_addr, localport, 
                           _timeout, self._sid)
        cmd_packet = prepend_header(binarypack_pystruct(_cmd),
                                    binarypack_pystruct(_arguments))

        # setup wait for reply
        reply_data = request_reply(s, cmd_packet)
        reply_struct = parse_message_data(reply_data)

        rc = reply_struct['data'][0]['status']
        rdata = reply_struct['data'][1]


    # send a message/request to the primary contact ip/port
    def local_message(self, _command, _arguments = None, _timeout = 10):
        """
        run a "local" command on the default listener
        """
        
        s = stream_socket(self.d_host, self.d_port)
        (ip_addr, localport) = s.getsockname()

        # setup a command packet
        _cmd = _cmd_struct('', _command, ip_addr, localport, 
                           _timeout, self._sid)
        cmd_packet = prepend_header(binarypack_pystruct(_cmd),
                                    binarypack_pystruct(_arguments))

        # setup wait for reply
        reply_data = request_reply(s, cmd_packet)
        reply_struct = parse_message_data(reply_data)

        rc = reply_struct['data'][0]['status']
        if (rc != E_OK):
            raise ProtocolException(rc, "error in '%s'" % _command)

        rdata = reply_struct['data'][1]

        ######################################################
        ### complete hack alert - handling this here is not pretty
        # TODO: this should be able to be handled via callback if we replace
        #       the request_reply with the subscribe parsing methods
        if ((_command == 'login') and (rc == E_OK)):
            self._sid = rdata['sid']
        ### end hack
        ######################################################

        # setup the closing packet
        _close_cmd = _cmd_struct('', "_close", ip_addr, localport, 
                                 _timeout, self._sid)
        close_packet = prepend_header(binarypack_pystruct(_close_cmd),
                                      binarypack_pystruct(None))

        # close out the command and the socket   
        try:
            s.send(close_packet)
        except socket.error, msg:
            raise msg
        s.close()
        return rdata

    #
    # post an addressed message - resolves using nametoip
    def message(self, _address, _command, _arguments=None, _timeout=10):

        # open up a socket to the proper address
        _a_ip = self.address_lookup(_address)
        s = stream_socket(_a_ip['ip'], _a_ip['port'])
        (ip_addr, localport) = s.getsockname()

        # setup a command packet
        _cmd = _cmd_struct(_address, _command, ip_addr, localport, 
                           _timeout, self._sid)
        cmd_packet = prepend_header(binarypack_pystruct(_cmd),
                                    binarypack_pystruct(_arguments))

        # setup wait for reply
        reply_data = request_reply(s, cmd_packet)
        reply_struct = parse_message_data(reply_data)

        rc = reply_struct['data'][0]['status']
        rdata = reply_struct['data'][1]

        # setup the closing packet
        _close_cmd = _cmd_struct(_address, '_close', ip_addr, localport,
                                 _timeout, self._sid)
        close_packet = prepend_header(binarypack_pystruct(_close_cmd),
                                      binarypack_pystruct(None))

        # close out the command and the socket   
        try:
            s.send(close_packet)
        except socket.error, msg:
            raise msg
        s.close()

        if (rc != E_OK):
            raise ProtocolException(rc, "error in %s" % _command)

        return rdata


    #
    # install_pkg - TODO: all
    def install_pkg(self, _address, _command, _arguments=None, _timeout=10):

        # open up a socket to the proper address
        _a_ip = self.address_lookup(_address)
        s = stream_socket(_a_ip['ip'], _a_ip['port'])
        (ip_addr, localport) = s.getsockname()

        # setup a command packet
        _cmd = _cmd_struct(_address, _command, ip_addr, localport, 
                           _timeout, self._sid)
        cmd_packet = prepend_header(binarypack_pystruct(_cmd),
                                    binarypack_pystruct(_arguments))

        # setup wait for reply
        reply_data = request_reply(s, cmd_packet)
        reply_struct = parse_message_data(reply_data)

        if (__debug__) :
            #dump_full_packet(reply_data)
            pass

        rc = reply_struct['data'][0]['status']
        rdata = reply_struct['data'][1]

        if (rc != E_OK):
            raise ProtocolException(rc, "error in %s" % _command)

        return rdata
 

    # user login
    def user_login(self, user, password):
        _login_encrdata = _generate_login_args(user, password)
        try:
            l_struct = self.local_message('login', _login_encrdata, 0)
        except ProtocolException as e:
            raise ProtocolException(E_LOGIN, "Login Error (%d)" % e.code)

        self._sid = l_struct['sid']
        return l_struct


    def threads(self):
        return self._threads


    #
    #
    def __init__(self, _d_host, _d_port = DEFAULT_PORT, _s_host = None):
        # normal internal vars
        self.d_host = _d_host # d_host/port might not be a good var to have in
        self.d_port = _d_port # the session object when threading commands
        self.s_host = _s_host # ...and neither are the s_host/port
        self._sid = None

        # TODO: enable address caching 
        self._cache_addresses = True
        self._addr_cache = {}

        # list of active threads - not terribly robust yet... or even more than
        # minimally functional
        self._threads = {}

        # get network info
        self._hostname = socket.gethostname()
        try:
            self._default_ip = socket.gethostbyname(self._hostname)
        except Exception:
            self._default_ip = socket.gethostbyname('')
        self._ip_list = _get_ip_list()

        if (self.s_host is None):
            self.s_host = self._default_ip

        # this is a ping to the host target
        pc_struct = self.local_message('session_checkin', { 'type' : 1 }, 0)

