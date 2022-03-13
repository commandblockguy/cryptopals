from common import *

key = random_bytes(16)

def encrypt(data):
	nonce = random.randrange(0, 2**32)
	plaintext = b'comment1=cooking%20MCs;userdata=' + data.replace(b';', b'%3B').replace(b'=', b'%3D') + b';comment2=%20like%20a%20pound%20of%20bacon'
	return encrypt_aes_ctr(plaintext, key, nonce), nonce

def decrypt(data, nonce):
	return encrypt_aes_ctr(data, key, nonce)

def is_admin(data):
	return b'admin=true' in data.split(b';')

ct, nonce = encrypt(b'\x00' * 11)
ct = ct[:32] + xor_bytes(b';admin=true', ct[32:43]) + ct[43:]
pt = decrypt(ct, nonce)
print(pt)
print(is_admin(pt))
