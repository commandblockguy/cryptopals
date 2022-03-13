from base64 import b64decode
from common import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random

secrets = [
	'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
	'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
	'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
	'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
	'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
	'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
	'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
	'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
	'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
	'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
]

key = random_bytes(16)

def encrypt():
	iv = random_bytes(16)
	plaintext = b64decode(secrets[random.randint(0,len(secrets)-1)])
	encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
	return encryptor.update(pkcs7(plaintext, 16)) + encryptor.finalize(), iv

def decrypt(data, iv):
	decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
	return decryptor.update(data) + decryptor.finalize()

def verify_padding(data, iv):
	try:
		unpkcs7(decrypt(data, iv), 16)
		return True
	except ValueError:
		return False

def break_ct(ct, iv):
	result = b''
	prev_block = iv
	for block in split_blocks(ct, 16):
		result_block = b''
		for i in range(16):
			padding_byte = i + 1
			for c in range(256):
				test_block = xor_bytes(prev_block, b'A' * (15-i) + xor_bytes(bytes([c]) + result_block, bytes([padding_byte]) * (i + 1)))
				if verify_padding(block, test_block):
					result_block = bytes([c]) + result_block
					break
			else:
				print('womp womp')
				exit(1)
		prev_block = block
		result += bytes(result_block)
	return unpkcs7(result, 16)


found = set()
while len(found) < len(secrets):
	found.add(break_ct(*encrypt()))

for x in sorted(found):
	print(x)