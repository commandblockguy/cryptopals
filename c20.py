from base64 import b64decode
from common import *

key = random_bytes(16)

with open('20.txt') as f:
	secrets = [b64decode(x) for x in f.readlines()]
	ciphertexts = [encrypt_aes_ctr(x, key, 0) for x in secrets]

def rep_xor(s, c):
	return bytes(c1 ^ c for c1 in s)

def break_rep_xor(ct):
	return max(((rep_xor(ct, c), string_score(rep_xor(ct, c))) for c in range(256)), key=lambda x: x[1])[0]

def break_fixed_nonce_ctr(cts):
	a = [break_rep_xor(x) for x in zip(*cts)]
	print([bytes(x) for x in zip(*a)])

break_fixed_nonce_ctr(ciphertexts)
