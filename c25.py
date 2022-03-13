from common import *

secret = b'Never gonna give you up, never gonna let you down, never gonna run around and desert you'
nonce = 1337
key = random_bytes(16)

ct = encrypt_aes_ctr(secret, key, nonce)

def edit(ct, key, offset, newtext):
	pt = decrypt_aes_ctr(ct, key, nonce)
	pt = pt[:offset] + newtext + pt[offset+len(newtext):]
	return encrypt_aes_ctr(pt, key, nonce)

print(xor_bytes(ct, edit(ct, key, 0, b'\0' * len(ct))))