with open('8.txt', 'r') as f:
	for line in f.readlines():
		ct = bytes.fromhex(line)
		num_blocks = len(ct) // 16
		blocks = {ct[16*i:16*i+16] for i in range(num_blocks)}
		if len(blocks) != num_blocks:
			print('Line with repeated block:', line[:-1])
		
