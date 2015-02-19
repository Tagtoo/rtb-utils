"""
crypto_price.py

Algorithms to encrypt/decrypt price string with DoubleClick mechanism
Algorithm reference: https://developers.google.com/ad-exchange/rtb/response-guide/decrypt-price

author: LittleQ <littleq@tagtoo.org>
"""

import hmac
import base64
from base64 import urlsafe_b64decode, urlsafe_b64encode
import hashlib

IV_SIZE = 16
CIPHERTEXT_SIZE = 8
SIGNATURE_SIZE = 4
BLOCK_SIZE = 20

__all__ = [
        "encrypt_price",
        "decrypt_price"
        ]

def split_encoded_price(s):
    """
    Structure of encrypted string from Open-Bidder (by order):
    {initialization_vector (16 bytes)}
    {encrypted_price (8 bytes)}
    {integrity (4 bytes)}
    """
    cursor = 0
    iv = s[cursor:cursor+IV_SIZE]

    cursor += IV_SIZE
    pad = s[cursor:cursor+CIPHERTEXT_SIZE]

    cursor += CIPHERTEXT_SIZE
    sig = s[cursor:cursor+SIGNATURE_SIZE]

    return (iv, pad, sig)

def my_hmac(k, d):
    hmac_obj = hmac.new(k, d, hashlib.sha1)
    return hmac_obj.digest()

def padding(s):
    pad = ""
    if (len(s) % 4) == 2:
        pad = "=="
    elif (len(s) % 4) == 3:
        pad = "="
    return s + pad

def unWebSafeAndPad(s):
    s = padding(s)
    return s.replace('-', '+').replace('_', '/')

def webSafeAndUnPad(s):
    return s.replace('+', '-').replace('/', '_').rstrip("=")

def websafe_base64_decode(s):
    return urlsafe_b64decode(padding(s))

def websafe_base64_encode(s):
    return webSafeAndUnPad(urlsafe_b64encode(s))

def sxor(s1, s2, length=CIPHERTEXT_SIZE):
    """
    XOR operation for strings
    """
    result = ''

    for i in range(length):
        # print ord(s1[i]), ord(s2[i])
        # print ord(s1[i])^ord(s2[i])
        result += chr(ord(s1[i]) ^ ord(s2[i]))

    return result



def decrypt(encoded_price, e_key, i_key):
    """
    Function to decode the string encoded by Open-Bidder

    Arguments:
    - encoded_price: encoded string which contains the information of bidding price.
    - e_key: encryption key we gave to bidder
    - i_key: integration key we gave to bidder


    Pseudo Code:
    enc_price = WebSafeBase64Decode(final_message)
    (iv, p, sig) = dec_price -- split up according to fixed lengths
    price_pad = hmac(e_key, iv)
    price = p <xor> price_pad
    conf_sig = hmac(i_key, price || iv)
    success = (conf_sig == sig)
    """

    enc_price = websafe_base64_decode(encoded_price)
    iv, p, sig = split_encoded_price(enc_price)

    ciphertext_size = len(enc_price) - IV_SIZE - SIGNATURE_SIZE
    assert ciphertext_size > 0

    price_pad = my_hmac(e_key, iv)
    # print 'price pad len: %s' % len(price_pad)
    # print 'price p len: %s' % len(p)
    price = sxor(p, price_pad)

    conf_sig = my_hmac(i_key, price + iv)[:SIGNATURE_SIZE]

    assert (conf_sig == sig), "Signature not match. Sig1: %s, Sig2: %s" % (conf_sig, sig)
    return price

def decrypt_price(encoded_price, e_key, i_key):
    decode_bytes = decrypt(encoded_price, e_key, i_key)
    return int(decode_bytes.encode('hex'), 16)

def encrypt(price, e_key, i_key, iv):
    """
    function to encrypt price string for open-bidder

    Pseudo Code:
    pad = hmac(e_key, iv)  // first 8 bytes
    enc_price = pad <xor> price
    signature = hmac(i_key, price || iv)  // first 4 bytes

    final_message = WebSafeBase64Encode( iv || enc_price || signature )
    """
    pad = my_hmac(e_key, iv)[:BLOCK_SIZE]
    # print len(pad), len(price)
    enc_price = sxor(pad, price)
    sig = my_hmac(i_key, price + iv)[:SIGNATURE_SIZE]


    # print len(iv), len(enc_price), len(sig)
    assert len( iv + enc_price + sig ) == 28, "Length of final message not match: %s" % len(iv + enc_price + sig)
    final_message = websafe_base64_encode( iv + enc_price + sig )
    return final_message



