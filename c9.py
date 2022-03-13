def pkcs(data, c, l):
	return data + c * (l - len(data))

print(pkcs(b'YELLOW SUBMARINE', b'\x04', 20))