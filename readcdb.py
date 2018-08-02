#!/usr/bin/python3

import binascii, struct, sys

if len(sys.argv) != 2:
	print('Usage %s <filename.cdb>' % sys.argv[0])
	exit(1)

filename = sys.argv[1]

# Addresses.cdb file signature
signature = b'\x0d\xf0\x1d\xc0'

# Block signature
M2 = b'\x4d\x32'

# Data types
MT_DWORD = 0x08
MT_BOOL_FALSE = 0x00
MT_BOOL_TRUE = 0x01
MT_ARRAY = 0x88
MT_STRING = 0x21
MT_BYTE = 0x09
MT_BOOL = {MT_BOOL_FALSE: False, MT_BOOL_TRUE: True}

# Addressbook field names
ADDR_BOOK_FIELD = {1: 'host', 2: 'login', 3: 'password', 4: 'note', 6: 'session', 8: 'group', 11: 'romon-agent'}

with open(filename, mode='rb') as file:
	content = file.read()

ptr = 0
if content[ptr:ptr+4] != signature:
	print('Bad signature in', filename)
	exit(1)

ptr += 4
block_no = 0
while ptr < len(content):
	block_size = struct.unpack('<I', content[ptr:ptr+4])[0]
	print('Record #%s' % block_no)
	ptr += 4
	if content[ptr:ptr+2] != M2:
		print('Bad block #%s' % block_no)
		exit(1)
	block_start = ptr
	ptr += 2
	while ptr < (block_size + block_start):
		record_code = struct.unpack('<I', content[ptr:ptr+3] + b'\x00')[0]
		ptr += 3
		record_type = ord(content[ptr:ptr+1])
		ptr += 1
		# Skip records with the following types: DWORD, BYTE, ARRAY
		if record_type == MT_DWORD:
			ptr += 4
		elif record_type == MT_BYTE:
			ptr += 1
		elif record_type == MT_BOOL_FALSE or record_type == MT_BOOL_TRUE:
			ptr += 0
		elif record_type == MT_ARRAY:
			length = struct.unpack('<H', content[ptr:ptr+2])[0]
			ptr += 2
			element = 0
			while element < length:
				element += 1
				ptr += 4
		# Process strings
		elif record_type == MT_STRING:
			length = ord(content[ptr:ptr+1])
			ptr += 1
			value = content[ptr:ptr+length]
			ptr += length
			try:
				decoded_value = value.decode('UTF-8')
			except:
				decoded_value = value
			print('%s = %s' % (ADDR_BOOK_FIELD[record_code], decoded_value))
	block_no += 1
	print('')
