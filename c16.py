from common import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = random_bytes(16)
iv = random_bytes(16)

def encrypt(data):
	plaintext = 'comment1=cooking%20MCs;userdata=' + data.replace(';', '%3B').replace('=', '%3D') + ';comment2=%20like%20a%20pound%20of%20bacon'
	encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
	return encryptor.update(pkcs7(bytes(plaintext, 'utf8'), 16)) + encryptor.finalize()

def decrypt(data):
	decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
	return decryptor.update(data) + decryptor.finalize()

def is_admin(data):
	return b'admin=true' in data.split(b';')

ct = encrypt('\x00' * 32)
ct = ct[:32] + xor_bytes(b'     ;admin=true', ct[32:48]) + ct[48:]
pt = decrypt(ct)
print(pt)
print(is_admin(pt))