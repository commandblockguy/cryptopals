from common import *
from bitstring import Bits
import random

def leftrotate(x, amt):
	x &= 0xffffffff
	return ((x << amt) | (x >> (32 - amt))) & 0xffffffff

def sha1_block(chunk, h):
	words = [x.uintbe for x in split_blocks(chunk, 32)]
	for i in range(16, 80):
		words.append(leftrotate(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1))

	# print(['{:08X}'.format(x) for x in words])

	a, b, c, d, e = h
	for i in range(80):
		grp = i // 20
		if grp == 0:
			f = (b & c) | ((~b) & d)
			k = 0x5A827999
		elif grp == 1:
			f = b ^ c ^ d
			k = 0x6ED9EBA1
		elif grp == 2:
			f = (b & c) | (b & d) | (c & d)
			k = 0x8F1BBCDC
		else:
			f = b ^ c ^ d
			k = 0xCA62C1D6
		a, b, c, d, e = (leftrotate(a, 5) + f + e + k + words[i]) & 0xffffffff, a, leftrotate(b, 30), c, d
		# print('t={:2}: {:08X}  {:08X}  {:08X}  {:08X}  {:08X}'.format(i, a, b, c, d, e))
	return tuple((x + y) & 0xffffffff for (x, y) in zip(h, (a, b, c, d, e)))

def md_pad(msg):
	ml = len(msg)
	num_pad_zeroes = -(ml + 1 + 64) % 512
	return msg + Bits([1]) + Bits([0]) * num_pad_zeroes + Bits(uintbe=ml, length=64)

def sha1(msg):
	h = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
	for chunk in split_blocks(md_pad(Bits(msg)), 512):
		h = sha1_block(chunk, h)
	return Bits().join(Bits(uintbe=x, length=32) for x in h).bytes

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

