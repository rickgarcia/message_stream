#!/usr/bin/python
from msg_dtypes import *
from ctypes import c_long, c_ulong, c_ulonglong
import twofish
import hashlib


################################################# 
DEFAULT_ZPACK = 16

#
def encrypt_login(binary_unenc, pack = DEFAULT_ZPACK):

    md = hashlib.md5()
    md.update(get_key())
    tf_key = md.digest()
    tf = twofish.Twofish(tf_key)

    enc_login = dtype_binary(tf.encrypt(binary_unenc.zpack(pack)))
    return enc_login


def get_key():
    return 0
    pass

