from common import *
from bitstring import Bits
import random

key = random.choice(open('/usr/share/dict/words', 'rb').read().split(b'\n'))
print(key)

def auth(message):
	return sha1(key + message)

def check_auth(message, signature):
	return sha1(key + message) == signature

def break_keyed_mac(message, h, suffix):
	for keysize in range(30):
		int_h = tuple(x.uintbe for x in split_blocks(Bits(h), 32))
		res_message = md_pad(Bits(length=keysize*8) + Bits(message)) + suffix
		last_block = md_pad(res_message)[-512:]
		res_h = Bits().join(Bits(uintbe=x, length=32) for x in sha1_block(last_block, int_h)).bytes
		if check_auth(res_message.bytes[keysize:], res_h):
			return res_message.bytes[keysize:], res_h

message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
h = auth(message)
print(Bits(h).hex)
message, h = break_keyed_mac(message, h, b';admin=true')
print(message)
print(Bits(h).hex)
print(check_auth(message, h))

