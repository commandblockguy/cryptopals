from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from common import *
import random

secret = b64decode("""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")

key = random_bytes(16)

def encryption_oracle(data):
	max_random = 64
	plaintext = random_bytes(random.randint(0, max_random)) + data + secret
	encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
	return encryptor.update(pkcs(plaintext, b'\x04', 16)) + encryptor.finalize()

def unprepend_oracle(oracle, data, block_size):
	while True:
		ct = oracle(b'A' * block_size * 2 + data)
		blocks = split_blocks(ct, block_size)
		for i in range(len(blocks) - 1):
			if blocks[i] == blocks[i + 1]:
				return b''.join(blocks[i+2:])

def break_ecb(oracle):
	block_size = aes_get_block_size(oracle)
	print('block size:', block_size)
	mode = aes_detect_mode(oracle, block_size)
	print('mode:', mode)
	if mode != 'ECB': return None

	known = b''
	while known[-1:] != b'\x04':
		short_block = b'\x00' * (((-len(known) - 1)) % block_size)
		block_index = len(known) // block_size
		actual_block = unprepend_oracle(oracle, short_block, block_size)[block_size*block_index:block_size*(block_index+1)]
		for c in range(0, 256):
			known_block =  unprepend_oracle(oracle, (b'\x00' * block_size + known + bytes([c]))[-(block_size):], block_size)[:block_size]
			if actual_block == known_block:
				known += bytes([c])
				break
		else:
			print('out of possible chars')
			break
	return known[:-1]

print(break_ecb(encryption_oracle))
