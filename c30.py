from common import *
from bitstring import Bits
import random

def leftrotate(x, amt):
	x &= 0xffffffff
	return ((x << amt) | (x >> (32 - amt))) & 0xffffffff

def f(x, y, z):
	return (x & y) | (~x & z)

def g(x, y, z):
	return (x & y) | (x & z) | (y & z)

def h(x, y, z):
	return x ^ y ^ z

def md4_block(chunk, h2):
	words = [int.from_bytes(x.bytes, 'little') for x in split_blocks(chunk, 32)]

	h1 = list(h2)
	for i in range(16):
		a, b, c, d = (x % 4 for x in range(-i, -i + 4))
		s = [3, 7, 11, 19][i % 4]
		h1[a] = leftrotate(h1[a] + f(h1[b], h1[c], h1[d]) + words[i], s)

	for i in range(16):
		a, b, c, d = (x % 4 for x in range(-i, -i + 4))
		k = (i % 4) * 4 + i // 4
		s = [3, 5, 9, 13][i % 4]
		h1[a] = leftrotate(h1[a] + g(h1[b], h1[c], h1[d]) + words[k] + 0x5A827999, s)

	for i in range(16):
		a, b, c, d = (x % 4 for x in range(-i, -i + 4))
		k = [0, 8, 4, 12][i % 4] + [0, 2, 1, 3][i // 4]
		s = [3, 9, 11, 15][i % 4]
		h1[a] = leftrotate(h1[a] + h(h1[b], h1[c], h1[d]) + words[k] + 0x6ED9EBA1, s)

	return tuple((x + y) & 0xffffffff for (x, y) in zip(h1, h2))

def md_pad(msg):
	ml = len(msg)
	num_pad_zeroes = -(ml + 1 + 64) % 512
	return msg + Bits([1]) + Bits([0]) * num_pad_zeroes + Bits(uintle=ml, length=64)

def md4(msg):
	h = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
	for chunk in split_blocks(md_pad(Bits(msg)), 512):
		h = md4_block(chunk, h)
	return Bits().join(Bits(uintle=x, length=32) for x in h).bytes

key = random.choice(open('/usr/share/dict/words', 'rb').read().split(b'\n'))
print(key)

def auth(message):
	return md4(key + message)

def check_auth(message, signature):
	return md4(key + message) == signature

def break_keyed_mac(message, h, suffix):
	for keysize in range(30):
		int_h = tuple(x.uintle for x in split_blocks(Bits(h), 32))
		res_message = md_pad(Bits(length=keysize*8) + Bits(message)) + suffix
		last_block = md_pad(res_message)[-512:]
		res_h = Bits().join(Bits(uintle=x, length=32) for x in md4_block(last_block, int_h)).bytes
		if check_auth(res_message.bytes[keysize:], res_h):
			return res_message.bytes[keysize:], res_h

message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
hsh = auth(message)
print(Bits(hsh).hex)
message, hsh = break_keyed_mac(message, hsh, b';admin=true')
print(message)
print(Bits(hsh).hex)
print(check_auth(message, hsh))