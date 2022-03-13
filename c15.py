from common import *

for x in range(20):
	print(pkcs7(b'A' * x, 16), unpkcs7(pkcs7(b'A' * x, 16), 16))