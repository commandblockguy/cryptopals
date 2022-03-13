from common import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def profile_for(email):
	return 'email=' + email.replace('&', '[amp]').replace('=', '[equ]') + '&uid=10&role=user'

key = random_bytes(16)

# not really, misread this earlier
def pkcs(data, c, l):
	count = -len(data) % l
	return data + c * count

def encryption_oracle(data):
	plaintext = bytes(profile_for(data), 'utf8')
	encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
	return encryptor.update(pkcs(plaintext, b'\x04', 16)) + encryptor.finalize()

def decrypt(data):
	decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
	return decryptor.update(data) + decryptor.finalize()


# block 0: email=foo+a@bar.
# block 1: com&uid=10&role=
# block 2: admin&uid=10&rol

def get_admin_file(oracle):
	block0, block1 = split_blocks(oracle('foo+a@bar.com'), 16)[:2]
	block2 = split_blocks(oracle('          admin'), 16)[1]
	return block0 + block1 + block2 + block0

print(parse_kv(str(decrypt(get_admin_file(encryption_oracle))), '&'))