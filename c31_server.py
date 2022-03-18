from common import *
import time
# wow, this library is kinda garbage
# hey, it looked fine in the single example they gave
import web

app = web.application(('/test', 'test'), globals())
key = b'LIME GREEN BATTLESHIP OR SOMETHING IDK'

def hmac(k, m):
	if len(k) > 20:
		k = sha1(k)
	else:
		k = k[:20]
	return sha1(xor_bytes(k, b'\x5c' * 20) + sha1(xor_bytes(k, b'\x36' * 20) + m))

print(hmac(key, b'foo').hex())

def insecure_compare(a, b):
	if len(a) != len(b):
		return False
	for b1, b2 in zip(a, b):
		if b1 != b2:
			return False
		time.sleep(0.05)
	return True


class test:
	def GET(self):
		data = web.input(file=None, signature=None)
		if data.file is None or data.signature is None:
			raise web.HTTPError('500 Infernal Server Error')
		signature = bytes.fromhex(data.signature)
		hmac_valid = insecure_compare(hmac(key, bytes(data.file, 'utf8')), signature)
		if not hmac_valid:
			raise web.HTTPError('500 Infernal Server Error')
		return 'ACCESS GRANTED'

app.run()

