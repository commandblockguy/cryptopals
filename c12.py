from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from common import *

secret = b64decode("""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")

key = random_bytes(16)

def encryption_oracle(data):
	plaintext = data + secret
	encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
	return encryptor.update(pkcs(plaintext, b'\x04', 16)) + encryptor.finalize()


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
		actual_block = oracle(short_block)[block_size*block_index:block_size*(block_index+1)]
		for c in range(0, 256):
			known_block = oracle((b'\x00' * block_size + known + bytes([c]))[-(block_size):])[:block_size]
			if actual_block == known_block:
				known += bytes([c])
				break
		else:
			print('out of possible chars')
			break
	return known[:-1]

print(break_ecb(encryption_oracle))
