import math, random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def pkcs7(data, l):
	count = -len(data) % l
	if count == 0: count = l
	return data + bytes([count]) * count

def unpkcs7(data, l):
	count = data[-1]
	if any(x != count for x in data[-count:]):
		raise ValueError('Bad PKCS#7 padding')
	return data[:-count]

def random_bytes(n):
	return bytes(random.randint(0, 255) for _ in range(n))

def round_up_to(x, n):
	return math.ceil(x / n) * n

def split_blocks(data, size):
	return [data[size*i:size*(i+1)] for i in range(math.ceil(len(data) / size))]

def aes_get_block_size(oracle):
	start_size = len(oracle(b''))
	i = 1
	while True:
		new_size = len(oracle(b'\x00' * i))
		if new_size != start_size:
			return new_size - start_size
		i += 1

def aes_detect_mode(oracle, block_size):
	ct = oracle(b'\x00' * (block_size * 3))
	return 'ECB' if len(set(split_blocks(ct, block_size))) != len(split_blocks(ct, block_size)) else 'CBC'

def parse_kv(s, sep):
	return {x.split('=')[0]: x.split('=')[1] for x in s.split(sep)}

def xor_bytes(a, b):
	return bytes(a1 ^ b1 for (a1, b1) in zip(a, b))

def char_score(c):
	freqs = {
		32: 407934,
		33: 170,
		34: 5804,
		35: 425,
		36: 1333,
		37: 380,
		38: 536,
		39: 5816,
		40: 5176,
		41: 5307,
		42: 1493,
		43: 511,
		44: 17546,
		45: 32638,
		46: 35940,
		47: 3681,
		48: 13109,
		49: 10916,
		50: 7894,
		51: 4389,
		52: 3204,
		53: 3951,
		54: 2739,
		55: 2448,
		56: 2505,
		57: 2433,
		58: 10347,
		59: 2884,
		60: 2911,
		61: 540,
		62: 2952,
		63: 3503,
		64: 173,
		65: 7444,
		66: 5140,
		67: 9283,
		68: 7489,
		69: 6351,
		70: 3365,
		71: 4459,
		72: 5515,
		73: 7631,
		74: 4102,
		75: 1633,
		76: 4476,
		77: 8386,
		78: 4954,
		79: 4378,
		80: 6211,
		81: 751,
		82: 5986,
		83: 9512,
		84: 7895,
		85: 1934,
		86: 2119,
		87: 6005,
		88: 815,
		89: 722,
		90: 180,
		91: 205,
		92: 37,
		93: 210,
		94: 8,
		95: 2755,
		96: 21,
		97: 123287,
		98: 24227,
		99: 50211,
		100: 59577,
		101: 203824,
		102: 32616,
		103: 37064,
		104: 65217,
		105: 116488,
		106: 2061,
		107: 16047,
		108: 75450,
		109: 39060,
		110: 118108,
		111: 137119,
		112: 36791,
		113: 1774,
		114: 101201,
		115: 103814,
		116: 151376,
		117: 49901,
		118: 20109,
		119: 30974,
		120: 4635,
		121: 26924,
		122: 1417,
		123: 62,
		124: 16,
		125: 61,
		126: 8
	}
	return freqs[c] if c in freqs else 0

def string_score(s):
	return sum(char_score(c) for c in s)

def encrypt_aes_ctr(plaintext, key, nonce):
	result = b''
	encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
	for counter, block in enumerate(split_blocks(plaintext, 16)):
		keystream = encryptor.update(nonce.to_bytes(8, byteorder='little') + counter.to_bytes(8, byteorder='little'))
		result += xor_bytes(keystream, block)
	return result

def decrypt_aes_ctr(ciphertext, key, nonce):
	return encrypt_aes_ctr(ciphertext, key, nonce)

class Mt19937:
	w, n, m, r = (32, 624, 397, 31)
	a = 0x9908B0DF
	u, d = (11, 0xFFFFFFFF)
	s, b = (7, 0x9D2C5680)
	t, c = (15, 0xEFC60000)
	l = 18
	f = 1812433253
	lower_mask = (1 << r) - 1
	upper_mask = (lower_mask ^ ((1 << w) - 1)) % 2**w

	def __init__(self, seed):
		self.index = Mt19937.n
		self.state = [seed]
		for i in range(1, Mt19937.n):
			self.state.append((Mt19937.f * (self.state[i-1] ^ (self.state[i-1] >> (Mt19937.w-2))) + i) % 2 ** Mt19937.w)

	def twist(self):
		for i in range(Mt19937.n):
			x = (self.state[i] & Mt19937.upper_mask) + (self.state[(i+1) % Mt19937.n] & Mt19937.lower_mask)
			xA = x >> 1
			if (x % 2) != 0:
				xA ^= Mt19937.a
			self.state[i] = self.state[(i+Mt19937.m) % Mt19937.n] ^ xA
		self.index = 0

	def get(self):
		if self.index >= Mt19937.n:
			self.twist()
		y = self.state[self.index]
		y ^= ((y >> Mt19937.u) & Mt19937.d)
		y ^= ((y << Mt19937.s) & Mt19937.b)
		y ^= ((y << Mt19937.t) & Mt19937.c)
		y ^= (y >> Mt19937.l)
		self.index += 1
		return y % 2**Mt19937.w

	def __iter__(self):
		return self

	def __next__(self):
		return self.get()

def mt19937_stream(data, seed):
	result = b''
	rng = Mt19937(seed)
	for counter, block in enumerate(split_blocks(data, 4)):
		keystream = next(rng).to_bytes(4, 'little')
		result += xor_bytes(keystream, block)
	return result
