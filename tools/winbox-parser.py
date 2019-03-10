#!/usr/bin/env python3

# You can feed the script with a hexadecimal (raw) wireshark output

from binascii import hexlify, unhexlify
from winbox.packet import *
from winbox.message import *
import sys

for hex in sys.stdin.readlines():
	binary = unhexlify(hex.replace('\n', ''))
	packet = mtPacket(binary)
	packet.remove_header()
	message = mtMessage(packet.raw)
	message.parse()
	message.dump()
