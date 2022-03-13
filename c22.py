from common import *
import time, math
import random

def timestamp():
	return math.floor(time.time())

secret_timestamp = timestamp()
rand_num = next(Mt19937(secret_timestamp))
print('seed:', secret_timestamp)
time.sleep(random.randint(40, 1000))

curr_timestamp = timestamp()
for i in range(2000):
	if next(Mt19937(curr_timestamp - i)) == rand_num:
		print('Timestamp:', curr_timestamp - i)
		break
else:
	print("couldn't find timestamp")