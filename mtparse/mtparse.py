#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys

def read_config(filename):
	config = None
	try:
		f = open(filename, 'r')
	except:
		return None
	try:
		config = f.read().replace('\r', '').replace('\\\n    ', '')
	finally:
		f.close()
	return config

def read_section(config, section):
	result = []
	section_begin = False
	section_end = False

	for line in config.split('\n'):
		if not section_begin:
			if line == section:
				section_begin = True
		else:
			if not section_end:
				if (len(line) > 0 and line[0] == '/') or len(line) == 0:
					section_end = True
				else:
					result.append(line)
	return result

def list_sections(config):
	result = []
	for line in config.split('\n'):
		if len(line) > 0:
			if line[0] == '/':
				result.append(line)
	return result

def parse_line(line):
	result = []
	key = ''
	keyword_found = False
	quote_found = False
	backslash_found = False

	line += '\n'

	for c in line:
		if keyword_found:
			if quote_found:
				key += c
				if backslash_found:
					backslash_found = False
				else:
					if c in '\\':
						backslash_found = True
					elif c in '"':
						result.append(key)
						key = ''
						quote_found = False
			else:
				if c in '"':
					key += c
					quote_found = True
				elif c in ' \n':
					result.append(key)
					key = ''
					keyword_found = False
				else:
					key += c
		else:
			if c not in ' \n':
				key += c
				keyword_found = True
	return result

def line_dict(line):
	result = {}

	brackets_found = False
	brackets = {}

	for i in parse_line(line):
		k = i.split('=', 1)
		if not brackets_found:
			if len(k) == 1:
				if k[0] == '[':
					brackets_found = True
				else:
					l = len(result)
					if len(k[0]) > 0:
						result[l] = k[0]
			if len(k) == 2:
				result[k[0]] = k[1]
		else:
			if len(k) == 1:
				l = len(brackets)
				if k[0] == ']':
					if l > 1:
						l = len(result)
						result[l] = brackets
						brackets = {}
					brackets_found = False
				else:
					brackets[l] = k[0]
			if len(k) == 2:
				brackets[k[0]] = k[1]
	return result
