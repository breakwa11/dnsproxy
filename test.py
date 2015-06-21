#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copyleft (c) 2015 breakwa11
https://github.com/breakwa11/dnsproxy
'''

import logging
import socket
import socks
import os
import time
import json
import traceback

def encode(data):
	if hasattr(data, 'encode'):
		return data.encode('utf-8')
	return data

def load_config():
	fmt = '[%(asctime)s] %(levelname)s: %(message)s'
	logging.basicConfig(filename = os.path.join(os.getcwd(), 'dnslog.txt'), level = logging.DEBUG, format = fmt)
	console = logging.StreamHandler()
	console.setLevel(logging.DEBUG)
	formatter = logging.Formatter(fmt)
	console.setFormatter(formatter)
	logging.getLogger('').addHandler(console)

	bind = ("0.0.0.0", 53)
	dns_list = ["114.114.114.114", "114.114.115.115", "8.8.8.8", "8.8.4.4"]
	proxy = ("127.0.0.1", 1080)

	try:
		f = file(os.path.join(os.getcwd(), "config.json"), "r")
		config = json.loads(f.read())
		if config:
			local_address = config.get("local_address", None)
			local_port = config.get("local_port", None)
			dns = config.get("dns", None)
			proxy_address = config.get("proxy_address", None)
			proxy_port = config.get("proxy_port", None)
			if local_address is not None and local_port is not None:
				bind = (local_address, local_port)
				logging.info("bind %s:%d loaded" % (local_address, local_port))
			if proxy_address is not None and proxy_port is not None:
				proxy = (proxy_address, proxy_port)
				logging.info("proxy %s:%d loaded" % (proxy_address, proxy_port))
			if dns is not None:
				dns_list = []
				for item in dns:
					dns_list.append(encode(item))
				logging.info("dns %s loaded" % (dns_list,))

	except Exception as e:
		logging.error(e)
		pass

	return bind, dns_list, proxy

def test(bindaddr, dnslist, proxy):
	for try_cnt in xrange(4):
		if proxy:
			addrs = socket.getaddrinfo(proxy[0], 0, 0, socket.SOCK_DGRAM, socket.SOL_UDP)
			af, socktype, proto, canonname, sa = addrs[0]
			s = socks.socksocket(af, socket.SOCK_DGRAM)
			s.set_proxy(socks.SOCKS5, *proxy)
		else:
			addrs = socket.getaddrinfo("0.0.0.0", 0, 0, socket.SOCK_DGRAM, socket.SOL_UDP)
			af, socktype, proto, canonname, sa = addrs[0]
			s = socket.socket(af, socktype, proto)
		s.setblocking(False)

		try:
			r = s.sendto("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+"\x06"+"google"+"\x03"+"com"+"\x00\x00\x01\x00\x01",
			(dnslist[0], 53) )
		except Exception as e:
			traceback.print_exc()
			#print("Send data ERROR: connection refused")
			break

		res = None

		for i in xrange(5*5):
			time.sleep(0.2)
			try:
				res = s.recvfrom(65536)
				break
			except Exception as e:
				pass

		if res is not None:
			print('Test success with proxy %s' % (proxy,))
			break
		else:
			print('Test failure with proxy %s' % (proxy,))
			s.close()

	print("Test finish")
	try:
		input()
	except Exception as e:
		pass

if __name__ == '__main__':
	test(*load_config())

