#!/usr/bin/python3

import binascii, sys

M2 = b'\x4d\x32'
WPA_PSK = b'\x15\x00\x00\x21'
WPA2_PSK = b'\x04\x00\x00\x21'

def parse_str(entry, id):
	if id[3:4] != b'\x21':
		raise ValueError('The record type is not a string')
	data = entry.split(id)[1]
	data_len = data[0]
	if data_len > 0:
		result = data[1:1 + data_len].decode('UTF-8')
	else:
		result = ''
	return result

if len(sys.argv) < 2:
	print('Usage: %s <file>' % sys.argv[0])
	exit(0)

wpf = open(sys.argv[1], 'rb')
data = wpf.read()

for entry in data.split(M2)[1:]:
	psk1 = parse_str(entry, WPA_PSK)
	psk2 = parse_str(entry, WPA2_PSK)

	if psk1 != '':
		print(psk1)
	if psk2 != '':
		print(psk2)

wpf.close()
