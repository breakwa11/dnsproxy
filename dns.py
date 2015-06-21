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
import threading
import time
import json
import eventloop

BUF_SIZE = 65536

class UDPHandler(object):
	def __init__(self, addr, proxy, ttl):
		super(UDPHandler, self).__init__()
		self.proxy = proxy
		self.key = None

		if self.proxy is None:
			addrs = socket.getaddrinfo(addr[0], 0, 0, socket.SOCK_DGRAM, socket.SOL_UDP)
			af, socktype, proto, canonname, sa = addrs[0]
			self.socket = socket.socket(af, socktype, proto)
		else:
			self.socket = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
			self.socket.set_proxy(socks.SOCKS5, proxy[0], proxy[1])
		self.socket.setblocking(False)

		self.last_update_time = time.time()
		self.ttl = ttl

	def sendto(self, data, addr):
		try:
			self.last_update_time = time.time()
			return self.socket.sendto(data, addr)
		except Exception as e:
			logging.error("sendto %s failed" % (addr, ))

	def recvfrom(self):
		try:
			res = self.socket.recvfrom(BUF_SIZE)
			self.last_update_time = time.time()
			return res
		except Exception as e:
			pass

	def close(self):
		try:
			self.socket.close()
		except Exception as e:
			pass

	def is_expire(self):
		return time.time() - self.last_update_time > self.ttl

class UDPRelay(object):
	def __init__(self, proxy, target_dns_list):
		super(UDPRelay, self).__init__()
		self._eventloop = None
		self._closed = False

		self.socket = None
		self.handler = {}
		self.proxy = proxy
		self.target = target_dns_list
		self._fd_to_h = {}

	def bind(self, addr, port):
		try:
			addrs = socket.getaddrinfo(addr, port, 0, socket.SOCK_DGRAM, socket.SOL_UDP)
			af, socktype, proto, canonname, sa = addrs[0]
			self.socket = socket.socket(af, socktype, proto)
			self.socket.setblocking(False)
			self.socket.bind((addr, port))
			logging.info("bind %s:%d success" % (addr, port))
			return True
		except Exception as e:
			pass

	def sendto(self, data, addr):
		try:
			return self.socket.sendto(data, addr)
		except Exception as e:
			logging.error("sendto %s failed" % (addr, ))

	def recvfrom(self):
		try:
			res = self.socket.recvfrom(BUF_SIZE)
			return res
		except Exception as e:
			pass

	def add_to_loop(self, loop):
		if self._eventloop:
			raise Exception('already add to loop')
		if self._closed:
			raise Exception('already closed')
		self._eventloop = loop
		loop.add_handler(self._handle_events)

		self._eventloop.add(self.socket,
							eventloop.POLL_IN | eventloop.POLL_ERR)

	def _handle_server(self):
		recv = self.recvfrom()
		if recv is not None:
			logging.info("send %s %d bytes" % ( recv[1], len(recv[0]) ) )
			for target in self.target:
				key = (recv[1], target)
				if key not in self.handler:
					self.handler[key] = UDPHandler(target, self.proxy, 10)
					self.handler[key].key = key
					self._fd_to_h[self.handler[key].socket] = self.handler[key]
					self._eventloop.add(self.handler[key].socket, eventloop.POLL_IN)
				handler = self.handler[key]
				logging.debug("send %s %d bytes to %s" % ( recv[1], len(recv[0]), target ) )
				#handler.sendto(recv[0], (target, 53))
				threading.Thread(target = handler.sendto, args = (recv[0], (target, 53))).start()

	def _handle_client(self, sock):
		handler = self._fd_to_h[sock]
		recv = handler.recvfrom()
		if recv is not None:
			key = handler.key
			logging.debug("recv %s %d bytes from %s" % ( key, len(recv[0]), recv[1] ) )
			self.sendto(recv[0], key[0])

		'''
		for key in self.handler:
			handler = self.handler[key]
			if handler.socket == sock:
				recv = handler.recvfrom()
				if recv is not None:
					logging.debug("recv %s %d bytes from %s" % ( key, len(recv[0]), recv[1] ) )
					self.sendto(recv[0], key[0])
		'''

	def _handle_events(self, events):
		# handle events and dispatch to handlers
		for sock, fd, event in events:
			if sock == self.socket:
				if event & eventloop.POLL_ERR:
					logging.error('UDP server_socket err')
				self._handle_server()
			else:
				if event & eventloop.POLL_ERR:
					logging.error('UDP client_socket err')
				self._handle_client(sock)

		for key in self.handler.keys():
			handler = self.handler[key]
			if handler.is_expire():
				self._eventloop.remove(handler.socket)
				logging.debug("close %s" % (key,) )
				handler.close()
				del self._fd_to_h[handler.socket]
				del self.handler[key]

def main_loop(bindaddr, dnslist, proxy):
	dns = UDPRelay(proxy, dnslist)
	loop = eventloop.EventLoop()
	if dns.bind(bindaddr[0], bindaddr[1]):
		dns.add_to_loop(loop)
		loop.run()
	else:
		logging.error("bind failed")

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

if __name__ == '__main__':
	main_loop(*load_config())
