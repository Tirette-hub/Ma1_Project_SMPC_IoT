#!/bin/bash/python3
#encoding: utf-8

import socket
import threading
from . import Frame, Octets

import sys

BYTEORDER = sys.byteorder
MPC_PORT = 5005

SUCCESS = 1
FAILED = 0
CUTOFF = -1
UNKNOWN = -2

class Message:
	PING = 0
	FRAME = 1
	def __init__(self, type, origin, content):
		self.type = type
		self.origin = origin
		self.content = content

	def get(self):
		return (self.type, self.origin, self.content)

	def set_origin(self, addr):
		self.origin = addr

	def get_origin(self):
		return self.origin

	def __repr__(self):
		return self.get()

	def __str__(self):
		string = "["
		if self.type == Message.PING:
			string += "PING: "
		elif self.type == Message.FRAME:
			string += "FRAME: "

		string += f"from {self.origin} with payload {self.content}]"
		return string

	def __eq__(self, o):
		if type(o) != type(self):
			return False

		if o.get() == self.get():
			return True

		return False

	def to_bytes(self):
		s = b""

		s += self.content.to_bytes()

		return s

	def from_bytes(b):
		frame = Frame.Frame.from_bytes(b[:])

		return Message(Message.FRAME, None, frame)

class NetworkInterface(threading.Thread):
	def __init__(self):
		super(NetworkInterface, self).__init__()
		self.parties_addr = {}
		self.quit = False

		self.on_recv_callback = None
		self.ip = '0.0.0.0' #socket.gethostbyname(socket.gethostname())
		print("My IP is:", self.ip)
		self.port = MPC_PORT
		self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		with open("/tmp/log.log", "a") as f:
			f.write(f"port = {self.port}\n")

	def get_ip(self):
		return self.ip

	def get_port(self):
		return self.port

	def get_addr(self):
		return (self.ip, self.port)

	def set_recv_handler(self, callback):
		"""
		Set the callback to use when receiving a message.

		Arguments:
			callback (function): the callback to use.
		"""
		self.on_recv_callback = callback

	def stop(self):
		self.quit = True

	def run(self):
		"""
		"""
		print("binding")
		self.s.bind((self.ip, self.port))

		while not self.quit:
			data, (addr, port) = self.s.recvfrom(1024)
			if data:
				message = Message.from_bytes(data)
				message.set_origin((addr, port))
				self.on_recv_callback(message)

	def set_party(self, id, addr):
		"""
		Bind the id to the address.

		Arguments:
			id (int): Identifier of a party.
			addr (str): String representing an IPv4 address.
		"""
		if id in self.parties_addr.keys():
			return False
		
		self.parties_addr[id] = addr

	def get_party_id_by_addr(self, addr):
		"""
		Get the party id from the addr.

		Arguments:
			addr (str): String representing an IPv4 address.

		Returns:
			The party id whom the address belongs to, if known. None otherwize.
		"""
		for party_id, party_addr in self.parties_addr.items():
			if party_addr == addr:
				return party_id

		return None

	def broadcast(self, message):
		"""
		Allows broadcasting of messages.

		Arguments:
			message (Message): the message to be sent.

		Returns:
			Sending status.
		"""
		return self.s.sendto(message.to_bytes(), ("255.255.255.255", 5005))

	def send_to(self, to_pid, message):
		"""
		Allows a network interface to send a message to another party.

		Arguments:
			to_pid (int): pid of the party to whom the message is destinated to.
			message (Message): the message to be sent.

		Returns:
			Sending status.
		"""
		return self.s.sendto(message.to_bytes(), (self.parties_addr[to_pid]))