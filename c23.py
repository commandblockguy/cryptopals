from common import *
from bitstring import Bits, BitArray
import itertools

def unright(x, s):
	x = Bits(uint=x, length=32)
	blocks = split_blocks(x, s)
	result = Bits()
	prev = Bits(length=s)
	for b in blocks:
		prev = b ^ prev[:len(b)]
		result = result + prev
	return result.uint

def unleft(x, s, m):
	x = Bits(uint=x, length=32)
	m = Bits(uint=m, length=32)
	blocks = [Bits(reversed(Bits(y))) for y in split_blocks(Bits(reversed(x)), s)]
	m_blocks = [Bits(reversed(Bits(y))) for y in split_blocks(Bits(reversed(m)), s)]
	result = b''
	prev = Bits(length=s)
	for (m, b) in zip(m_blocks, blocks):
		prev = b ^ (prev[-len(b):] & m[-len(b):])
		result = prev + result
	return result.uint


print(hex(unleft(left(0x13371337, 15, 0xEFC60000), 15, 0xEFC60000)))

def untemper(x):
	x = unright(x, Mt19937.l)
	x = unleft(x, Mt19937.t, Mt19937.c)
	x = unleft(x, Mt19937.s, Mt19937.b)
	x = unright(x, Mt19937.u)
	return x

hidden_gen = Mt19937(1337)

items = itertools.islice(hidden_gen, Mt19937.n)


spliced = Mt19937(0)
spliced.state = [untemper(x) for x in items]

print(list(itertools.islice(hidden_gen, 5)))
print(list(itertools.islice(spliced, 5)))