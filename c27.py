from common import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = random_bytes(16)
message = b"We're no strangers to love. You know the rules and so do I."

print('SECRET KEY:', key)

def encrypt(data):
	encryptor = Cipher(algorithms.AES(key), modes.CBC(key)).encryptor()
	return encryptor.update(pkcs7(data, 16)) + encryptor.finalize()

def decrypt(data):
	decryptor = Cipher(algorithms.AES(key), modes.CBC(key)).decryptor()
	result = decryptor.update(data) + decryptor.finalize()
	if any(x > 127 for x in result):
		raise ValueError(b'Non-ASCII character found: ' + result)
	return 

ct = encrypt(message)

blocks = split_blocks(ct, 16)

try:
	decrypt(blocks[0] + b'\0' * 16 + blocks[0])
except ValueError as e:
	msg, = e.args
	pt = msg[27:]
	p1, _, p3 = split_blocks(pt, 16)
	print('key:', xor_bytes(p1, p3))