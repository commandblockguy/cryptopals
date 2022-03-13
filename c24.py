from common import *
import random

plaintext = b'A' * 14
secret_seed = random.randrange(0, 2**16)
ct = mt19937_stream(random_bytes(random.randint(0, 10)) + plaintext, secret_seed)

for x in range(2**16):
	print(x, 2**16)
	if mt19937_stream(ct, x)[-14:] == plaintext:
		print(x)
		break

print('secret:', secret_seed)