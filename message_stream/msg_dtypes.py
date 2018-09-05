# Message Bus type handling
#
# The message bus type system includes many "types" which are not completely
# compatibly with native python types.  These classes enable type matching to
# extend native python so that all expected types have available classes
#
# If types are not specified, then the pack routines will default to the 
# closest matching type:
#   python int -> TYPE_INT
#   python str -> TYPE_STR
#   python dict -> TYPE_STRUCT
#   python list -> TYPE_STRING_LIST
#  

import re
from msg_exceptions import *

#
# type constants
TYPE_NONE = 0
TYPE_INT = 1
TYPE_INT_LIST = 2         # list of ints - \x00 delimited
TYPE_INT9 = 3             # front-zero-padded integer
TYPE_CHR = 6              #
TYPE_CHR_LIST = 7         # string (list of chars)
TYPE_STR = 7              # string (list of chars)
TYPE_STR_LIST = 8         # list of strings - \x00 delimited
TYPE_FLOAT = 16
TYPE_FLOAT_LIST = 17      # unimplemented
TYPE_STRUCT = 21
TYPE_VOID = 22
TYPE_LIST = 24
TYPE_I64 = 27


##
# data packing classes and routines

# TYPE_INT 1
#  - "integer\x001\x005\x009999\x00"
#  - 9999
class dtype_int(int):
    """
    Enhanced Integer class for message data type integers
    """
    def __new__(self, content):
        return int.__new__(self, content)
    def code(self):
        return TYPE_INT
    def pack(self, _key = "INT"):
        pattern = "%s\x00%d\x00%d\x00%d\x00"
        return pattern % (_key, TYPE_INT, (len(str(self)) + 1), int(self))


# TYPE_INT_LIST 2
#  - "integerlist\x002\x0012\x0012\x0034\x0056\x0078\x00"
#  - [12, 34, 56, 78]
class dtype_int_list(list):
    """
    Enhanced Integer list class
    """
    def __new__(self, content):
        return list.__new__(self, content)
    def code(self):
        return TYPE_INT_LIST
    def pack(self, _key = "INT_LIST"):
        #TODO: manage empty list size
        packed_list = "\x00".join(map(str, self))
        pattern = "%s\x00%d\x00%d\x00%s\x00"
        return pattern % (_key, TYPE_INT, (len(packed_list) + 1), packed_list)


# TYPE_INT 3
#  - "integer\x003\x005\x00000009999\x00"
#  - 9999
class dtype_int9(int):
    """
     Integer class for message data type integers
    """
    def __new__(self, content):
        return int.__new__(self, content)
    def code(self):
        return TYPE_INT
    def pack(self, _key = "INT9"):
        pattern = "%s\x00%d\x00%09d\x00%s\x00"
        return pattern % (_key, TYPE_INT9, (len(str(self)) + 1), str(self))


# TYPE_STR 7
class dtype_str(str):
    """
    Enhanced Integer class for message data type integers
    """
    def __new__(self, content):
        return str.__new__(self, content)
    def code(self):
        return TYPE_STR
    def pack(self, _key = "STR"):
        data_len = len(self)
        if (data_len == 0):
             return "%s\x00%d\x00%d\x00" % (_key, TYPE_STR, 0)
        pattern = "%s\x00%d\x00%d\x00%s\x00"
        return pattern % (_key, TYPE_STR, (data_len + 1), self)


#
# TYPE_FLOAT 16
# TODO: THIS CLASS IS UNTESTED!!!
class dtype_float(float):
    def __new__(self, content):
        return float.__new__(self, content)
    def __str__(self):
        return str(float(self))
    def code(self):
        return TYPE_FLOAT

    # handling 0 or 0.0 needs to be tested....
    def pack(self, _key = "FLOAT"):
        flt_str = str(self)
        flt_str_len = len(flt_str)
        # based off of the handling empty strs 
        if (flt_str_len == 0): 
            pattern = "%s\x00%d\x00%d\x00"
            return pattern % (_key, TYPE_FLOAT, flt_str_len)

        flt_str_len += 1
        pattern = "%s\x00%d\x00%d\x00%f\x00"
        return pattern % (_key, TYPE_FLOAT, flt_str_len, flt_str)
   

# TYPE_STRUCT 21
#
class dytpe_struct(dict):
    """
    Yay enhanced dict!
    """ 
    def __new__(self, content):
        return dict.__new__(self, content)
    def code(self):
        return TYPE_STRUCT
    def pack(self, _key = "STRUCT"):
        packed_data = ''
        for subkey in self:
            try:
                packed_data += self[subkey].pack(subkey)
            except AttributeError, e:
                packed_data += binarypack_pystruct(self[subkey])
        pattern = "%s\x00%d\x00%d\x00%s"
        return pattern % (_key, TYPE_STRUCT, len(packed_data), packed_data)


# TYPE_VOID 22
# binary data string type
class dtype_binary(str):
    """
    Just a class to distinguish between normal text strings and binary
    stream/string data
    """
    def __new__(self, content):
        return str.__new__(self, content)
    def code(self):
        return TYPE_VOID
    def pack(self, _key = 'VOID'):
        data_len = len(str(self))
        if (data_len == 0):
            return "%s\x00%d\x00%d\x00" % (_key, TYPE_VOID, 0)
        else:
            return "%s\x00%d\x00%d\x00%s" % (
                     _key, TYPE_VOID, data_len, str(self))
    def zpack(self, modulus):
        """
        zero padding on the end of the binary string to specified
        modulus length
        """
        packed = self
        while (len(packed) % modulus):
            packed += "\x00"
        return packed


# TYPE_STRUCT 24
#
class dytpe_list(list):
    """
    Yay enhanced dict!
    """ 
    def __new__(self, content):
        return list.__new__(self, content)
    def code(self):
        return TYPE_LIST
    def pack(self, _key = "LIST"):
        # this is currently only tested for lists of structs (dicts) - other
        # types may cause issues as the message bus may expect lists of other
        # types to be structured differently
        index = 0
        packed_data = ''
        for list_item in self:
            try:
                packed_data += list_item.pack(str(index))
            except AttributeError, e:
                packed_data += binarypack_pystruct({str(index): list_item})
            index += 1
        pattern = "%s\x00%d\x00%09d\x00%s"
        return pattern % (_key, TYPE_LIST, len(packed_data), packed_data)


#
# pack a python structure into a binary stream; order can be forced by
# passing a list of keys in the _ordered field
#
# TODO: this is horrifically inefficient due to python strings being
#       immutable - this needs to be modified to prevent constantly
#       reallocating/appending strings
#
#       - the best way to rework this is probably to finish the class/types
#         as noted in the class todo above under dtype_binary
def binarypack_pystruct(data_pystruct, _ordered = None):
    """
    binarypack_pystruct takes a full python structure and packs it into the
    target binary string representation

    The source data_pystruct is a native typed python dictionary.  The
    data types will be converted into the necessary format/type on the
    fly by the dispatcher.

    data_py_struct = {
        'name' : data,
        'name2' : data2,
        'nested' = {
            'nested1' : data,
             ...
        },
        'listname' : [item1, item2,...]
        ...
    }

    _ordered is a list which allows the caller to force the ordering of
    the items in the resulting binary representation.

    _ordered = ['name', 'name2', 'nested', ...]
    """
    if data_pystruct is None:
        return '' 

    if (str(data_pystruct.__class__.__name__) != 'dict'):
        if (__debug__):
            raise Exception("cannot pack unstructured data")
        return ''

    binary_data = ''
    if (_ordered is None):
        _ordered = data_pystruct.keys()

    for _key in _ordered:
        # the __class__.__name__ is consistent for built-in and user types
        # - that's necessary to distinguish between binary strings (VOID) and
        # normal \0 deliminated strings
        cn_string = str((data_pystruct[_key]).__class__.__name__)
        #
        if (cn_string == 'str'):
            data_pystruct[_key] = dtype_str(data_pystruct[_key])
        elif (cn_string == 'int'):
            data_pystruct[_key] = dtype_int(data_pystruct[_key])
        elif (cn_string == 'float'):
            data_pystruct[_key] = dtype_float(data_pystruct[_key])
        elif (cn_string == 'dict'):
            data_pystruct[_key] = dtype_struct(data_pystruct[_key])
        elif (cn_string == 'list'):
            data_pystruct[_key] = dtype_list(data_pystruct[_key])

        try:
            binary_data += data_pystruct[_key].pack(_key)
        except AttributeError, e:
            msg = "unhandled dtype: %s" % (cn_string)
            raise ProtocolFatal(msg)

    return binary_data


# Parsing defs/methods
# note:
#  - this probably needs to be better organized into two levels of binary
#    parsing:
#     - first level is the protocol message.  This contains the
#       protocol name, version, and the complete message size.
#     - second level is the packed binary data.  This is the internal data
#       which can have integrity errors completely unrelated to the message/
#       transport protocol
#
##


##
# primary defs for reading binary message data encapsulated by the messaging
#    protocol
#
#
# parse_raw_data_string: reads binary data formats, determines types,
#                        and outputs to a python dictionary with type info.
#                        Throws DataCorruption exceptions
#
# dictionary_parse_deftyped_struct: recursive function (which calls
#                                   parse_raw_data_string) which converts the
#                                   dictionary output of prds to native
#                                   python types
#                                   Drops exceptions and returns avail data
#
# parse_message_data: entry function for the flat parse_raw_data_string def and
#                     the recursive dictionary_parse_deftyped_struct functions
#


##
# parse_raw_data_string
#
# - single flat pass of parsing over a packed binary data string
#
# - all data is still raw after parsing; the type is contained in the struct
#   and may be restructured/reparsed based on type.  All lists/structs are
#   handled by the calling functions, as they contain internal structure
#
# returns:
#     data_struct = {
#         'struct1' : {
#             'name' : string - 'struct1' - same as key name
#             'type' : int
#             'size' : int
#             'data' : unparsed binary data
#             }
#        'struct2' : {...
#        ...
#     }
#
data_match = None # static regex to avoid constant recompiles
def parse_raw_data_string(data_string):

    data_struct = {}

    # compile the regex on the first call
    global data_match
    if (data_match is None):
        # pattern is : NAME\x00TYPE\x00SIZE\x00actual_data_follows...
        # exclude ctrl and whitespace chars (0-31) from NAME
        data_match = re.compile(r"^([^\x00-\x19]+)\x00(\d+)\x00(\d+)\x00")

    # manual index handling is somewhat more reliable on binary data, as
    # python has issues with IndexErrors on binary strings
    parse_len = len(data_string)
    parse_head = 0
    while (parse_head < parse_len):
        # match the datum header, but not the data itself
        parse_metadata = data_match.match(data_string[parse_head:])
        try:
            (data_name, _type, _size) = parse_metadata.groups()
        except AttributeError as e:
            raise DataCorruption(
                "dstring format: %s" % repr(data_string[parse_head:]))

        data_idx_start = parse_head + parse_metadata.end()
        data_type = int(_type)
        data_size = int(_size)
        data_idx_end = data_idx_start + data_size

        # assign the dict values
        try:
            data_struct[data_name] = {
                'name' : data_name,
                'type' : data_type,
                'size' : data_size,
                'data' : data_string[data_idx_start:data_idx_end]
            }
        except IndexError as e:
            raise DataCorruption("dstring size: %s" % repr(data_string[:32]))

        # move the head to the end of the data str
        parse_head = data_idx_end

    return data_struct


#
# parse a defined-type structure into a python dictionary structure
#
# - recursion capable on nested types; the entry value is a dictionary
#   containing the data type, names, size, and value.  This converts to
#   python types, and (for nested types) calls the flat parser and recurses
#   (nested types are arrays/hash types)
#
# - currently set to silently drop data errors; TODO: it would be preferable
#   to set an option to allow for silent dropping or strict data checking as
#   desired by the target application
#
def dictionary_parse_deftyped_struct(typed_struct):
    dict_struct = {}
    key_fix_flag = 0
    for _key in typed_struct.keys():
        try:
            sub_struct = typed_struct[_key]

            if (sub_struct['type'] == TYPE_INT):
                # known issue: occasionally, a field with two \0 chars will
                # come thru
                sub_strlen = sub_struct['size'] - 1
                dict_struct[_key] = dtype_int(sub_struct['data'][:sub_strlen])

            elif (sub_struct['type'] == TYPE_INT_LIST):
                # \x00 delimited list of ascii integers - chomp off the
                # trailing \x00
                # TODO:
                # - this leaves the ints as strings, not ints - needs to be
                #   converted
                sub_list = re.split("\x00", sub_struct['data'][:-1])
                dict_struct[_key] = dtype_int_list(map(int, sub_list))

            elif (sub_struct['type'] == TYPE_INT9):
                # TYPE_INT9 strings are 0 buffered integers - sizes should be
                # absolute byte numbers in 9 chars, ie. 40 = 000000040
                dict_struct[_key] = sub_struct['data']

            elif (sub_struct['type'] == TYPE_STR):
                # chomp off the trailing \0 from the binary stream - watch
                # for empty strings
                sub_strlen = sub_struct['size']
                if (sub_strlen > 0):
                    sub_strlen -= 1
                dict_struct[_key] = sub_struct['data'][:sub_strlen]

            elif (sub_struct['type'] == TYPE_VOID):
                dict_struct[_key] = sub_struct['data']

            elif (sub_struct['type'] == TYPE_FLOAT):
                fltstr_len = sub_struct['size'];
                if (fltstr_len > 0):
                    fltstr_len -= 1
                dict_struct[_key] = dtype_float(sub_struct['data'][:fltstr_len])

            elif (sub_struct['type'] == TYPE_STR_LIST):
                # same as LIST- just with simple types instead of
                # substructs
                sub_data = parse_raw_data_string(sub_struct['data'])
                _struct = dictionary_parse_deftyped_struct(sub_data)
                dict_struct[_key] = []
                for dkey in _struct.keys():
                    dict_struct[_key].append(_struct[dkey])

            elif (sub_struct['type'] == TYPE_STRUCT):
                sub_data = parse_raw_data_string(sub_struct['data'])
                dict_struct[_key] = dictionary_parse_deftyped_struct(sub_data)

            elif (sub_struct['type'] == TYPE_LIST):
                sub_data = parse_raw_data_string(sub_struct['data'])
                _struct = dictionary_parse_deftyped_struct(sub_data)

                dict_struct[_key] = []
                for dkey in _struct.keys():
                    dict_struct[_key].append(_struct[dkey])
            else:
                print >>sys.stderr, ("Source struct: %s" % repr(typed_struct))
                raise ProtocolFatal("unhandled type: %s" % repr(sub_struct))

        # we have the option here to either drop data, or raise an exception
        # TODO: add session variable enabling strict data checking
        except (ValueError, TypeError) as e:
            ###############################
            # Hack alert
            ###############################
            # hack fix for an external bulk_size format error - it appears to
            # be incorrectly formatted as an int list instead of an int
            if (_key == 'bulk_size'):
                sub_list = re.split("\x00", sub_struct['data'][:-1])
                dict_struct[_key] = dtype_int(sub_list[0])
                key_fix_flag = 1
                continue

            if (__debug__):
                print >> sys.stderr, ("dropping key: '%s'" % _key)
                print >> sys.stderr, ("data: %s" % repr(sub_struct['data']))
            continue
            raise e

#    if ((__debug__) && (key_fix_flag == 1)):
#        print >> sys.stderr, ("fixed struct: %s" % repr(dict_struct))
#        print >> sys.stderr, ("\nbulk_size: %d      bulk_list len: %d\n\n" % (dict_struct['bulk_size'], len(dict_struct['bulk_list'])))
    return dict_struct


# parse_message_data
#  - this operates directly on the header_struct, so data contained in it is
#    changed; in this case, the binary strings in header_struct['data'][i]
#    are parsed directly to keyed and typed structures, and then converted into
#    native python types
#
#  - This is essentially an entry function for the two data parsing
#    functions underlying the internal message data parsing; because internal
#    data can have nested structures, it's not possible for a simple
#    non-recursive function to completely parse the data; we handle this
#    by running an initial parse over the complete data which parses out
#    the top level of structures and typing, and then passes that result
#    onto a recursive-capable function which handles the nested data (if any)
#    and converts it into native python types.
#
#    Basic parsing flow:
#
#      parse_message_data
#        |
#        |----> parse_raw_data_string (coverts top level to data dictionary)
#                 |
#                 |-------> dictionary_parse_deftyped_struct ()
#                    |  ^      |-> parse_raw_data_string ()
#                    |  |------------| (return for recursion on nested types)
#                    |
#                    |----> return header_struct
#
def parse_message_data(header_struct):
    # we should have a header struct with a data list/dict - parse those
    for i in header_struct['data']:
        # this will turn the packed binaries into string data with types
        # defined by the type constants by the protocol
        typed_dictionary = parse_raw_data_string(header_struct['data'][i])

        # take the raw strings and convert them to native python types
        key_dict = dictionary_parse_deftyped_struct(typed_dictionary)

        # replace the binary strings with a parsed python typed dictionary
        header_struct['data'][i] = key_dict

    return header_struct

