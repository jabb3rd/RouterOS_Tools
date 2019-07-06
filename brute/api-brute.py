#!/usr/bin/env python3

import socket, hashlib, argparse, signal, sys, binascii
from multiprocessing import Pool

# Authorization result codes
AUTH_GOOD  = 0
AUTH_BAD   = 1
AUTH_ERROR = 2
AUTH_RESULT_CODES = ['GOOD', 'BAD', 'ERROR']
TIMEOUT = 5
DEFAULT_CREDS = ('admin', '')

# Global variables
targets = []
creds = []
number_of_threads = 10
stop_after_good = False
log = False
api_port = 8728

# File name for good results
results_filename = 'api-brute.log'

class ApiRos:
	"Routeros api"
	def __init__(self, sk):
		self.sk = sk
		self.currenttag = 0

	def login(self, username, pwd):
		for repl, attrs in self.talk(["/login", "=name=" + username, "=password=" + pwd]):
			if repl == '!trap':
				return False
			elif '=ret' in attrs.keys():
				chal = binascii.unhexlify((attrs['=ret']).encode('UTF-8'))
				md = hashlib.md5()
				md.update(b'\x00')
				md.update(pwd.encode('UTF-8'))
				md.update(chal)
				for repl2, attrs2 in self.talk(["/login", "=name=" + username, "=response=00" + binascii.hexlify(md.digest()).decode('UTF-8')]):
					if repl2 == '!trap':
						return False
		return True

	def talk(self, words):
		if self.writeSentence(words) == 0: return
		r = []
		while 1:
			i = self.readSentence();
			if len(i) == 0: continue
			reply = i[0]
			attrs = {}
			for w in i[1:]:
				j = w.find('=', 1)
				if (j == -1):
					attrs[w] = ''
				else:
					attrs[w[:j]] = w[j+1:]
			r.append((reply, attrs))
			if reply == '!done': return r

	def writeSentence(self, words):
		ret = 0
		for w in words:
			self.writeWord(w)
			ret += 1
		self.writeWord('')
		return ret

	def readSentence(self):
		r = []
		while 1:
			w = self.readWord()
			if w == '': return r
			r.append(w)

	def writeWord(self, w):
		#print(("<<< " + w))
		self.writeLen(len(w))
		self.writeStr(w)

	def readWord(self):
		ret = self.readStr(self.readLen())
		#print((">>> " + ret))
		return ret

	def writeLen(self, l):
		if l < 0x80:
			self.writeByte((l).to_bytes(1, sys.byteorder))
		elif l < 0x4000:
			l |= 0x8000
			tmp = (l >> 8) & 0xFF
			self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
			self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
		elif l < 0x200000:
			l |= 0xC00000
			self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
			self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
			self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
		elif l < 0x10000000:
			l |= 0xE0000000
			self.writeByte(((l >> 24) & 0xFF).to_bytes(1, sys.byteorder))
			self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
			self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
			self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
		else:
			self.writeByte((0xF0).to_bytes(1, sys.byteorder))
			self.writeByte(((l >> 24) & 0xFF).to_bytes(1, sys.byteorder))
			self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
			self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
			self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))

	def readLen(self):
		c = ord(self.readStr(1))
		if (c & 0x80) == 0x00:
			pass
		elif (c & 0xC0) == 0x80:
			c &= ~0xC0
			c <<= 8
			c += ord(self.readStr(1))
		elif (c & 0xE0) == 0xC0:
			c &= ~0xE0
			c <<= 8
			c += ord(self.readStr(1))
			c <<= 8
			c += ord(self.readStr(1))
		elif (c & 0xF0) == 0xE0:
			c &= ~0xF0
			c <<= 8
			c += ord(self.readStr(1))
			c <<= 8
			c += ord(self.readStr(1))
			c <<= 8
			c += ord(self.readStr(1))
		elif (c & 0xF8) == 0xF0:
			c = ord(self.readStr(1))
			c <<= 8
			c += ord(self.readStr(1))
			c <<= 8
			c += ord(self.readStr(1))
			c <<= 8
			c += ord(self.readStr(1))
		return c

	def writeStr(self, str):
		n = 0
		while n < len(str):
			r = self.sk.send(bytes(str[n:], 'UTF-8'))
			if r == 0: raise RuntimeError("connection closed by remote end")
			n += r

	def writeByte(self, str):
		n = 0
		while n < len(str):
			r = self.sk.send(str[n:])
			if r == 0: raise RuntimeError("connection closed by remote end")
			n += r

	def readStr(self, length):
		ret = ''
		while len(ret) < length:
			s = self.sk.recv(length - len(ret))
			if s == b'': raise RuntimeError("connection closed by remote end")
			if s >= (128).to_bytes(1, "big") :
				return s
			ret += s.decode('UTF-8', "replace")
		return ret

# Authenticate to the remote API
def do_auth(host, user, password):
	result = AUTH_ERROR
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(TIMEOUT)
	try:
		s.connect((host, api_port))
	except:
		print('[-] %s %s %s [CONNECT_ERROR]' % (host, user, password))
		s.close()
		return AUTH_ERROR
	api = ApiRos(s)
	try:
		if not api.login(user, password):
			print('[-] %s %s %s [BAD]' % (host, user, password))
			result = AUTH_BAD
		else:
			print('\033[32m[+] %s %s %s [GOOD]\033[39m' % (host, user, password))
			result = AUTH_GOOD
	except:
		print('[-] %s %s %s [ERROR]' % (host, user, password))
		s.close()
		return AUTH_ERROR
	return result

def bruteforce(target):
	result = []
	for l, p in creds:
		print('[*] Trying to connect to target: %s:%s (%s:%s)' % (target, api_port, l, p))
		code = do_auth(target, l, p)
		result.append((target, l, p, code))
		if code == AUTH_GOOD:
			if stop_after_good:
				return result
		elif code == AUTH_ERROR:
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
	parser.add_argument('-t', '--target', help = 'Target hostname', required = False)
	parser.add_argument('-p', '--port', help = 'API port (default = 8728)', required = False)
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
		api_port = int(args['port'])

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
