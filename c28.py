from common import *
from bitstring import Bits

def leftrotate(x, amt):
	x &= 0xffffffff
	return ((x << amt) | (x >> (32 - amt))) & 0xffffffff

def sha1(msg):
	msg = Bits(msg)
	ml = len(msg)
	num_pad_zeroes = -(ml + 1 + 64) % 512
	msg = msg + Bits([1]) + Bits([0]) * num_pad_zeroes + Bits(uintbe=ml, length=64)

	# print(msg)
	
	h = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

	for chunk in split_blocks(msg, 512):
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
		h = tuple((x + y) & 0xffffffff for (x, y) in zip(h, (a, b, c, d, e)))
	return Bits().join(Bits(uintbe=x, length=32) for x in h).hex

key = b'secret'
message = b'words'

def auth(message):
	return sha1(key + message)

print(auth(message))
