from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

with open('7.txt', 'r') as f:
	ct = b64decode(f.read())
	decryptor = Cipher(algorithms.AES(b'YELLOW SUBMARINE'), modes.ECB()).decryptor()
	print(decryptor.update(ct) + decryptor.finalize())
