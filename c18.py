from base64 import b64decode
from common import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random

ciphertext = b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
key = b'YELLOW SUBMARINE'
nonce = 0

print(decrypt_aes_ctr(ciphertext, key, nonce))
