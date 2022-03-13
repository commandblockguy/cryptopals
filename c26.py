from common import *

key = random_bytes(16)

def encrypt(data):
	nonce = random.randrange(0, 2**32)
	plaintext = 'comment1=cooking%20MCs;userdata=' + data.replace(';', '%3B').replace('=', '%3D') + ';comment2=%20like%20a%20pound%20of%20bacon'
	return encrypt_aes_ctr(plaintext, key, nonce), nonce

def decrypt(data, nonce):
	return encrypt_aes_ctr(data, key, nonce)

def is_admin(data):
	return b'admin=true' in data.split(b';')
