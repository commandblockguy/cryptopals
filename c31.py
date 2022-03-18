from common import *
import requests, time

def get_num_correct(file, signature):
	start = time.time()
	r = requests.get('http://localhost:8080/test?file={}&signature={}'.format(file, signature.hex()))
	end = time.time()
	num_correct = (end - start) // 0.05 if r.status_code != 200 else len(signature)
	return num_correct

file = 'foo'

known = b''
while len(known) < 20:
	for c in range(256):
		# hmm maybe I should have written this in javascript
		correct = get_num_correct(file, known + bytes([c]) + b'\0' * (19 - len(known)))
		if correct > len(known):
			known = known + bytes([c])
			print(known.hex())
			break
