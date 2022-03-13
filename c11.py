import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def pkcs(data, c, l):
	return data + c * (-len(data) % l)

def random_bytes(n):
	return bytes(random.randint(0, 255) for _ in range(n))

def encryption_oracle(data):
	plaintext = random_bytes(random.randint(5,10)) + data + random_bytes(random.randint(5,10))
	mode = 'ECB' if random.randint(0,1) else 'CBC'
	encryptor = Cipher(algorithms.AES(b'YELLOW SUBMARINE'), modes.ECB() if mode == 'ECB' else modes.CBC(random_bytes(16))).encryptor()
	return encryptor.update(pkcs(plaintext, b'\x04', 16)) + encryptor.finalize(), mode

def split_blocks(data, size):
	return [data[size*i:size*(i+1)] for i in range(len(data) // size)]

def detect(ct):
	return 'ECB' if len(set(split_blocks(ct, 16))) != len(split_blocks(ct, 16)) else 'CBC'

num_correct = 0
for _ in range(100):
	ct, mode = encryption_oracle(b'\x00' * 64)
	if detect(ct) == mode:
		num_correct += 1

print(num_correct)
