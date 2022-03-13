from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def xor_bytes(a, b):
	return bytes(ai ^ bi for (ai, bi) in zip(a, b))

with open('10.txt', 'r') as f:
	ct = b64decode(f.read())
	decryptor = Cipher(algorithms.AES(b'YELLOW SUBMARINE'), modes.ECB()).decryptor()
	encryptor = Cipher(algorithms.AES(b'YELLOW SUBMARINE'), modes.ECB()).encryptor()
	last_block = b'\x00' * 16
	for block in (ct[i*16:i*16+16] for i in range(len(ct) // 16)):
		print(xor_bytes(decryptor.update(block), last_block))
		last_block = block
