import base64
from bitstring import Bits
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from common import *

def rep_xor(s, c):
	return bytes(c1 ^ c for c1 in s)

def break_rep_xor(ct):
	return max(((rep_xor(ct, c), string_score(rep_xor(ct, c))) for c in range(256)), key=lambda x: x[1])[0]

def distance(a, b):
	return sum(Bits(a) ^ Bits(b))

with open('6.txt', 'rb') as f:
	data = base64.b64decode(f.read())
	sizes = {keysize: sum(distance(data[i*keysize:(i+1)*keysize], data[(i+1)*keysize:(i+2)*keysize]) for i in range(10)) / keysize for keysize in range(2, 40)}
	keysize, _ = min(sizes.items(), key=lambda x: x[1])
	blocks = [data[i::keysize] for i in range(keysize)]
	print(b''.join(bytes(x) for x in zip(*[break_rep_xor(b) for b in blocks])))