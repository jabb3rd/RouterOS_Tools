#!/usr/bin/env python3

import struct, hashlib
from binascii import hexlify, unhexlify
from io import BytesIO
from socket import *
from time import sleep

# Packet headers
M2_HEADER = b'M2'

# Indicates that the length takes one byte, thus the value is less than 2^8
MT_SHORT_LENGTH		= 0x01000000

# Different data formats
MT_BOOL			= 0x00000000
MT_DWORD		= 0x08000000
MT_QWORD		= 0x10000000
MT_IPV6			= 0x18000000
MT_STRING		= 0x20000000
MT_MESSAGE		= 0x28000000
MT_RAW			= 0x30000000

# Array type is a bitwise OR between a data type and MT_ARRAY
MT_ARRAY		= 0x80000000

# Different array types
MT_BOOL_ARRAY		= MT_ARRAY | MT_BOOL
MT_DWORD_ARRAY		= MT_ARRAY | MT_DWORD
MT_QWORD_ARRAY		= MT_ARRAY | MT_QWORD
MT_IPV6_ARRAY		= MT_ARRAY | MT_IPV6
MT_STRING_ARRAY		= MT_ARRAY | MT_STRING
MT_MESSAGE_ARRAY	= MT_ARRAY | MT_MESSAGE
MT_RAW_ARRAY		= MT_ARRAY | MT_RAW

# Type/name filters are bitwise AND between a nametype and a corresponding filter
MT_TYPE_FILTER		= 0xf8000000
MT_NAME_FILTER		= 0x00ffffff
MT_ARRAY_FILTER		= 0x7fffffff
MT_BOOL_FILTER		= 0x01000000

# MT-style abbreviated notation
MT_TYPE_REDUCTION = {
	MT_BOOL: 		'b',
	MT_DWORD: 		'u',
	MT_QWORD:		'q',
	MT_IPV6:		'a',
	MT_STRING:		's',
	MT_MESSAGE:		'm',
	MT_RAW:			'r',
	MT_BOOL_ARRAY:		'B',
	MT_DWORD_ARRAY:		'U',
	MT_QWORD_ARRAY:		'Q',
	MT_IPV6_ARRAY:		'A',
	MT_STRING_ARRAY:	'S',
	MT_MESSAGE_ARRAY:	'M',
	MT_RAW_ARRAY:		'R'
}

# Backward translation from an abbreviated notation
MT_REDUCTION_TYPE = {
	'b':	MT_BOOL,
	'u':	MT_DWORD,
	'q':	MT_QWORD,
	'a':	MT_IPV6,
	's':	MT_STRING,
	'm':	MT_MESSAGE,
	'r':	MT_RAW,
	'B':	MT_BOOL_ARRAY,
	'U':	MT_DWORD_ARRAY,
	'Q':	MT_QWORD_ARRAY,
	'A':	MT_IPV6_ARRAY,
	'S':	MT_STRING_ARRAY,
	'M':	MT_MESSAGE_ARRAY,
	'R':	MT_RAW_ARRAY
}

# The size in bytes for the corresponing array elements
MT_TYPE_SIZE = {
	MT_BOOL:		1,
	MT_DWORD:		4,
	MT_QWORD:		8,
	MT_IPV6:		16,
	MT_STRING:		0,
	MT_MESSAGE:		0,
	MT_RAW:			0,
}

# Message protocol constants
MT_RECEIVER		= 0xff0001
MT_SENDER		= 0xff0002
MT_REPLY_EXPECTED	= 0xff0005
MT_REQUEST_ID		= 0xff0006
MT_COMMAND		= 0xff0007
MT_SESSION_ID		= 0xfe0001

# This class represents a network packet
class mtPacket(object):
	def __init__(self, raw = None):
		self.raw = raw
		self.header = False

	def size(self):
		return len(self.raw)

	def clear(self):
		self.raw = None
		self.header = False

	# Returns True if a raw packet data contains a M2 header
	def has_header(self):
		if self.raw is None:
			raise Exception('No raw data in the packet yet')
		return self.raw[4:6] == M2_HEADER

	# Adds a M2 header for a raw data
	def add_header(self):
		if self.has_header():
			raise Exception('The raw data already has got a header')
		buffer = BytesIO()
		size = len(self.raw)
		# The contents is short (doesn't exceed 255 bytes)
		if size + 4 < 0xff:
			buffer.write(struct.pack('<B', size + 4) + b'\x01' + struct.pack('>H', size + 2) + M2_HEADER)
			buffer.write(self.raw)
		# The contents is long (so split it into several chunks up to 255 bytes)
		else:
			raw_headed = struct.pack('>H', size + 2) + M2_HEADER + self.raw
			first_chunk = True
			pointer = 0
			while pointer < size + 4:
				remaining = 4 + size - pointer
				if remaining > 0xff:
					remaining = 0xff
				if first_chunk:
					insertion = struct.pack('<BB', remaining, 0x01)
					first_chunk = False
				else:
					insertion = struct.pack('<BB', remaining, 0xff)
				buffer.write(insertion + raw_headed[pointer:pointer+remaining])
				pointer += remaining
		self.raw = buffer.getvalue()
		self.header = True
		return self.raw

	# Remove a M2 header
	def remove_header(self):
		if not self.has_header():
			raise Exception('Not an M2 packet')
		buffer = BytesIO()
		length, start, = struct.unpack('<BB', self.raw[0:2])
		if start != 0x01:
			raise Exception('Incorrect packet')
		if length < 0xff:
			buffer.write(self.raw[2:2+length])
		else:
			big_length, = struct.unpack('>H', self.raw[2:4])
			pointer = 0
			chunk_read_bytes = 0
			chunk = 0
			while pointer < len(self.raw):
				chunk += 1
				chunk_size, chunk_next = struct.unpack('<BB', self.raw[pointer:pointer+2])
				if chunk == 1:
					if chunk_next != 0x01:
						raise Exception('The first chunk is bad')
				else:
					if chunk_next != 0xff:
						raise Exception('Error in the chunk chain')
				pointer += 2
				buffer.write(self.raw[pointer:pointer+chunk_size])
				chunk_read_bytes += chunk_size
				pointer += chunk_size
		self.raw = buffer.getvalue()[4:]
		self.header = False
		buffer.close()
		return self.raw

# mtMessage represents a Message protocol sequence
class mtMessage(object):
	def __init__(self, raw = None):
		self.contents = []
		self.raw = raw
		self.ready = False
		self.parsed = False

	# Clean up a bit, so the object can be reused again
	def clear(self):
		self.contents = []
		self.raw = None
		self.parsed = False

	# Add an arbitrary id/type/value to a sequence
	def add(self, id, type, value):
		self.contents.append((id, type, value))

	# Add a boolean
	def add_bool(self, id, value):
		self.add(id, MT_BOOL, value)

	# Add an integer (byte/dword)
	def add_int(self, id, value):
		self.add(id, MT_DWORD, value)

	# Add a long integer (qword)
	def add_long(self, id, value):
		self.add(id, MT_QWORD, value)

	# Add a string (a sequence of bytes, not a native python string)
	def add_string(self, id, value):
		self.add(id, MT_STRING, value)

	# Add a raw data
	def add_raw(self, id, value):
		self.add(id, MT_RAW, value)

	# Set a raw binary contents
	def set_raw(self, raw):
		self.raw = raw

	# Set a receiver, which will handle a request
	def set_receiver(self, handler, subhandler = None):
		if subhandler is None:
			self.add(MT_RECEIVER, MT_DWORD_ARRAY, [handler])
		else:
			self.add(MT_RECEIVER, MT_DWORD_ARRAY, [handler, subhandler])

	# Set a sender, which sends a request
	def set_sender(self, handler, subhandler = None):
		if subhandler is None:
			self.add(MT_SENDER, MT_DWORD_ARRAY, [handler])
		else:
			self.add(MT_SENDER, MT_DWORD_ARRAY, [handler, subhandler])

	# Set a command to execute
	def set_command(self, command):
		self.add_int(MT_COMMAND, command)

	# Set a request ID
	def set_request_id(self, id):
		self.add_int(MT_REQUEST_ID, id)

	# Set True to expect a reply after a request
	def set_reply_expected(self, value):
		self.add_bool(MT_REPLY_EXPECTED, value)

	def set_session_id(self, id):
		self.add_int(MT_SESSION_ID, id)

	# Get a value of a given id/type
	def get_value(self, get_id, get_type):
		if not self.parsed:
			raise Exception('Not parsed yet')
		for k in self.contents:
			id, type, value = k
			if id == get_id and type == get_type:
				return value
		return None

	# Return True if there is a sequence with a given id/type (with any value)
	def has_value(self, id, type):
		if self.get_value(id, type) is not None:
			return True
		return False

	# Make a binary representation of a Message sequence
	def build(self):
		buffer = BytesIO()
		for k in self.contents:
			id, type, value = k
			typeid = id | type
			array = (typeid & MT_ARRAY) >> 31
			if array:
				size = len(value)
				size_bytes = struct.pack('<H', size)
				elements_type = type & MT_ARRAY_FILTER
				value_bytes = b''
				for element in value:
					if elements_type == MT_BOOL:
						value_bytes += struct.pack('<B', element)
					elif elements_type == MT_DWORD:
						value_bytes += struct.pack('<I', element)
					elif elements_type == MT_QWORD:
						value_bytes += struct.pack('<Q', element)

			if type == MT_BOOL:
				size_bytes = b''
				value_bytes = b''
				typeid |= (value << 24)
			elif type == MT_DWORD:
				size_bytes = b''
				if value < 256:
					typeid |= MT_SHORT_LENGTH
					value_bytes = struct.pack('<B', value)
				else:
					value_bytes = struct.pack('<I', value)
			elif type == MT_QWORD:
				size_bytes = b''
				value_bytes = struct.pack('<Q', value)
			elif type == MT_STRING or type == MT_RAW:
				size = len(value)
				if size < 256:
					typeid |= MT_SHORT_LENGTH
					size_bytes = struct.pack('<B', size)
				else:
					size_bytes = struct.pack('<H', size)
				value_bytes = value
			typeid_bytes = struct.pack('<I', typeid)
			buffer.write(typeid_bytes + size_bytes + value_bytes)
		self.raw = buffer.getvalue()
		self.ready = True
		return self.raw

	# Dump a sequence (for debugging purposes)
	def dump(self):
		for i in self.contents:
			id, type, value = i
			print('%s%s:%s' % (MT_TYPE_REDUCTION[type], hex(id)[2:], value))

	# Make a Message sequence from a raw binary data
	def parse(self):
		if self.raw is None:
			raise Exception('No raw data')
		pointer = 0
		while pointer + 4 < len(self.raw):
			typeid, = struct.unpack('<I', self.raw[pointer:pointer+4])
			type = typeid & MT_TYPE_FILTER
			id = typeid & MT_NAME_FILTER
			short = (typeid & MT_SHORT_LENGTH) >> 24
			array = (typeid & MT_ARRAY) >> 31
			pointer += 4
			if array:
				if short:
					array_length, = struct.unpack('<B', self.raw[pointer:pointer+1])
					pointer += 1
				else:
					array_length, = struct.unpack('<H', self.raw[pointer:pointer+2])
					pointer += 2
				element_type = typeid & MT_ARRAY_FILTER
				i = 0
				array_contents = []
				elements_type = type & MT_ARRAY_FILTER
				while i < array_length:
					if elements_type == MT_BOOL:
						element_value, = struct.unpack('<B', self.raw[pointer:pointer+MT_TYPE_SIZE[MT_BOOL]])
						array_contents.append(element_value)
						pointer += MT_TYPE_SIZE[MT_BOOL]
					if elements_type == MT_DWORD:
						element_value, = struct.unpack('<I', self.raw[pointer:pointer+MT_TYPE_SIZE[MT_DWORD]])
						array_contents.append(element_value)
						pointer += MT_TYPE_SIZE[MT_DWORD]
					# Treat M2 array as a raw data
					elif elements_type == MT_MESSAGE:
						if short:
							raise Exception('M2 short: not implemented yet!')
						else:
							element_length, = struct.unpack('<H', self.raw[pointer:pointer+2])
							element_value = self.raw[pointer:pointer+element_length+2]
							pointer += (element_length + 2)
							array_contents.append(element_value)
					i += 1
				self.add(id, type, array_contents)
			else:
				if type == MT_BOOL:
					value = (typeid & MT_BOOL_FILTER) >> 24
					self.add(id, type, value)
				elif type == MT_DWORD:
					if short:
						value, = struct.unpack('<B', self.raw[pointer:pointer+1])
						pointer += 1
					else:
						value, = struct.unpack('<I', self.raw[pointer:pointer+MT_TYPE_SIZE[MT_DWORD]])
						pointer += MT_TYPE_SIZE[MT_DWORD]
					self.add(id, type, value)
				elif type == MT_QWORD:
					value, = struct.unpack('<Q', self.raw[pointer:pointer+MT_TYPE_SIZE[MT_QWORD]])
					pointer += MT_TYPE_SIZE[MT_QWORD]
					self.add(id, type, value)
				elif type == MT_STRING:
					if short:
						string_length, = struct.unpack('<B', self.raw[pointer:pointer+1])
						pointer += 1
					else:
						string_length, = struct.unpack('<H', self.raw[pointer:pointer+2])
						pointer += 2
					value = self.raw[pointer:pointer+string_length]
					pointer += string_length
					self.add(id, type, value)
				elif type == MT_RAW:
					if short:
						raw_length, = struct.unpack('<B', self.raw[pointer:pointer+1])
						pointer += 1
					else:
						raw_length, = struct.unpack('<H', self.raw[pointer:pointer+2])
						pointer += 2
					value = self.raw[pointer:pointer+raw_length]
					pointer += raw_length
					self.add(id, type, value)
				else:
					raise Exception('Typeid %s not implemented yet!' % hex(typeid))
		self.parsed = True

# mtTCPSession to handle TCP winbox connections
class mtTCPSession(object):
	def __init__(self, host, port = None, timeout = None):
		self.host = host
		if port:
			self.port = port
		else:
			self.port = 8291
		if timeout:
			self.timeout = timeout
		else:
			self.timeout = 15
		self.ready = False

	# Connect to a winbox service
	def connect(self):
		try:
			self.socket = socket(AF_INET, SOCK_STREAM)
		except:
			raise Exception('Socket creation error!')
		if timeout:
			self.socket.settimeout(self.timeout)
		try:
			self.socket.connect((self.host, int(self.port)))
		except:
			self.ready = False
			raise Exception('Connection error to %s:%s' % (self.host, self.port))
		self.ready = True

	# Send arbitrary bytes
	def send_bytes(self, bytes):
		if not self.ready:
			raise Exception('Not connected to %s:%s' % (self.host, self.port))
		try:
			self.socket.sendall(bytes)
		except:
			return False
		return True

	# Receive arbitrary bytes
	def recv_bytes(self, size):
		if not self.ready:
			raise Exception('Not connected to %s:%s' % (self.host, self.port))
		result = self.socket.recv(size)
		return result

	# Close a connection
	def close(self):
		self.socket.close()
		self.ready = False

	# Send an mtPacket
	def send(self, msg):
		if not msg.header:
			msg.add_header()
		self.send_bytes(msg.raw)

	# Receive an mtPacket
	def recv(self, size):
		received_bytes = self.recv_bytes(size)
		if received_bytes is not None:
			result = mtPacket(received_bytes)
			result.remove_header()
		else:
			result = None
		return result

# Winbox session with given data: host, port, user, password
class mtWinboxSession(object):
	def __init__(self, host, port):
		self.session = mtTCPSession(host, port)
		self.session.connect()
		self.session_id = None
		self.request_id = 0
		self.error = None

	# Close a session
	def close(self):
		self.session.close()
		self.session_id = None

	def request_list(self):
		self.request_id += 1
		msg = mtMessage()
		msg.set_receiver(2, 2)
		msg.set_sender(0, 11)
		msg.set_command(7)
		msg.set_request_id(self.request_id)
		msg.set_reply_expected(True)
		msg.add_string(1, b'list')
		pkt = mtPacket(msg.build())

		self.session.send(pkt)
		sleep(0.2)
		reply = self.session.recv(1460)
		result = mtMessage(reply.raw)
		result.parse()

		error = result.get_value(0xff0008, MT_DWORD)
		if error is not None:
			self.error = error
			return False

		session_id = result.get_value(0xfe0001, MT_DWORD)
		if session_id is not None:
			self.session_id = session_id
			return True
		else:
			raise Exception('Got no session id')
		return False

	# Request a challenge
	def request_challenge(self):
		if self.session_id is None:
			raise Exception('No session')

		self.request_id += 1

		msg = mtMessage()
		msg.set_session_id(self.session_id)
		msg.set_command(5)
		msg.set_sender(0, 11)
		msg.set_receiver(2, 2)
		pkt1 = mtPacket(msg.build())
		self.session.send(pkt1)

		msg.clear()
		msg.set_reply_expected(True)
		msg.set_request_id(self.request_id)
		msg.set_command(4)
		msg.set_sender(0, 11)
		msg.set_receiver(13, 4)
		pkt2 = mtPacket(msg.build())
		self.session.send(pkt2)

		reply = self.session.recv(1460)
		result = mtMessage(reply.raw)
		result.parse()
		return result.get_value(9, MT_RAW)

	# MD5 challenge/response authentication
	def login(self, user, password):
		if self.session_id is not None:
			raise Exception('Already logged in')
		self.request_list()
		salt = self.request_challenge()
		digest = hashlib.md5()
		digest.update(b'\x00')
		digest.update(password)
		digest.update(salt)
		hashed = b'\x00' + digest.digest()

		self.request_id += 1
		msg = mtMessage()
		msg.set_receiver(13, 4)
		msg.set_sender(0, 8)
		msg.set_command(1)
		msg.set_request_id(self.request_id)
		msg.set_session_id(self.session_id)
		msg.set_reply_expected(True)
		msg.add_string(1, user)
		msg.add_raw(9, salt)
		msg.add_raw(10, hashed)
		pkt = mtPacket(msg.build())
		self.session.send(pkt)
		reply = self.session.recv(1460)
		result = mtMessage(reply.raw)
		result.parse()

		error = result.get_value(0xff0008, MT_DWORD)
		if error is not None:
			self.error = error
			return False
		return True

	# Dude-style cleartext login to a winbox server
	def login_cleartext(self, user, password):
		if self.session_id is not None:
			raise Exception('Already logged in')
		self.request_id += 1
		msg = mtMessage()
		msg.set_receiver(13, 4)
		msg.set_sender(0, 8)
		msg.add_int(7, 11)
		msg.add_int(0xff0003, 1)
		msg.set_request_id(self.request_id)
		msg.set_command(1)
		msg.add_string(1, user)
		msg.add_string(3, password)
		pkt = mtPacket(msg.build())

		self.session.send(pkt)
		reply = self.session.recv(1460)
		result = mtMessage(reply.raw)
		result.parse()

		error = result.get_value(0xff0008, MT_DWORD)
		if error is not None:
			self.error = error
			return False

		session_id = result.get_value(MT_SESSION_ID, MT_DWORD)
		if session_id is not None:
			self.session_id = session_id
			return True
		return False

# Requests a file from a device
class mtFileRequest(object):
	def __init__(self, winbox_session, filename):
		self.session = winbox_session.session
		self.session_id = None
		self.request_id = winbox_session.request_id
		self.filename = filename
		self.file_size = None
		self.fragment_size = 1460
		self.part_size = 32168
		self.buffer = BytesIO()
		self.error = None
		self.error_description = None

	# Get ready for a download and the necessary data such as file size and session id
	def request_download(self):
		self.request_id += 1
		msg = mtMessage()
		msg.set_reply_expected(True)
		msg.set_request_id(self.request_id)
		msg.set_command(3)
		msg.add_string(1, self.filename)
		msg.set_sender(0, 8)
		msg.set_receiver(2, 2)
		pkt = mtPacket(msg.build())
		self.session.send(pkt)
		reply = self.session.recv(self.fragment_size)
		result = mtMessage(reply.raw)
		result.parse()

		self.error = result.get_value(0xff0008, MT_DWORD)
		if self.error == 0xfe0006:
			self.error_description = result.get_value(0xff0009, MT_STRING)
			return False
		elif self.error is not None:
			return False
		self.session_id = result.get_value(MT_SESSION_ID, MT_DWORD)
		if self.session_id is None:
			raise Exception('Error getting download session id')
		self.file_size = result.get_value(2, MT_DWORD)
		return True

	# Proceed with download, requesting a file chunk by chunk
	def download(self):
		if self.session_id is None:
			raise Exception('No session')
		if self.file_size is None:
			raise Exception('Haven\'t got a file size')
		file_done = False
		while not file_done:
			self.request_id += 1
			msg = mtMessage()
			msg.set_reply_expected(True)
			msg.set_request_id(self.request_id)
			msg.set_session_id(self.session_id)
			msg.add_int(2, self.part_size)
			msg.set_command(4)
			msg.set_sender(0, 8)
			msg.set_receiver(2, 2)
			pkt = mtPacket(msg.build())
			self.session.send(pkt)
			sleep(0.1)
			part_buffer = BytesIO()
			part_done = False
			while not part_done:
				data = self.session.recv_bytes(self.fragment_size)
				data_size = len(data)
				if data_size < self.fragment_size:
					part_done = True
				part_buffer.write(data)
			unpkt = mtPacket(part_buffer.getvalue())
			part_buffer.close()
			unpkt.remove_header()
			unmsg = mtMessage(unpkt.raw)
			unmsg.parse()
			part_data = unmsg.get_value(3, MT_RAW)
			part_data_size = len(part_data)
			if part_data_size < self.part_size:
				file_done = True
			self.buffer.write(part_data)
		return self.buffer.getvalue()

def ip2dword(addr):
        return struct.unpack('<I', inet_aton(addr))[0]

def h(msg, data):
	print(msg, hexlify(data).decode())

if __name__ == '__main__':
	raise Exception('This is a library, please import it using "from winbox import *"')
