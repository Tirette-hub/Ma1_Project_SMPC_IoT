#!/bin/bash/python3
#encoding: utf-8

"""
Types:
- 0x0 List of known parties exchange (if empty: party just entered the network)
- 0x1 Share
- 0x2 MUL gate result
- 0x3 Final Result (only the party who requested it must receive)
- 0x4 Sync parties on how to compute the gates (circuit)
- 0x5 Request the computation
- 0x6 Party leaves the Network
- 0x7 (PCEAS) Vector of coefficients B
- 0x8 (PCEAS) Malicious behavior alert

Versions:
- 0x0 PCEPS
- 0x1 PCEAS
"""

from . import Octets
from . import Crypto

import sys

BYTEORDER = sys.byteorder

class UnknownVersionException(Exception):
	pass

class UnknownTypeException(Exception):
	pass

class Frame:
	ADVERT = 0
	SHARE = 1
	MUL = 2
	RESULT = 3
	SYNC = 4
	REQUEST = 5
	LEAVE = 6
	BVECT = 7
	MALICIOUS = 8

	PCEPS = 0
	PCEAS = 1
	def __init__(self, type, version, origin, payload):
		self.type = type
		self.version = version
		self.origin = origin
		self.payload = payload

	def __repr__(self):
		return f"({Frame.get_str_type(self.type)}, {'PCEPS' if self.version == 0 else 'PCEAS'}, {self.origin}, {self.payload})"

	def __eq__(self, o):
		if type(o) != type(self):
			return False

		if self.type != o.type or self.version != o.version or self.payload != o.payload or self.origin != o.origin:
			return False

		return True

	def get_origin(self):
		return self.origin

	def get_payload(self):
		return self.payload

	def get_type(self):
		return self.type

	def get_str_type(t):
		if t == Frame.ADVERT:
			return "ADVERT"
		elif t == Frame.SHARE:
			return "SHARE"
		elif t == Frame.MUL:
			return "MUL"
		elif t == Frame.RESULT:
			return "RESULT"
		elif t == Frame.SYNC:
			return "SYNC"
		elif t == Frame.REQUEST:
			return "REQUEST"
		elif t == Frame.LEAVE:
			return "LEAVE"
		elif t == Frame.BVECT:
			return "BVECT"
		elif t == Frame.MALICIOUS:
			return "MALICIOUS"

	def get_version(self):
		return self.version

	def from_bytes(b):
		"""
		Builds a Frame object from bytes.

		Arguments:
			b (bytes): bytes representing the frame.

		Returns:
			The frame object represented by the bytes.

		Raises:
			UnknownVersionException: Version is invalid.
			UnknownTypeException: Type is invalid.
		"""
		type_version = int(b[0])
		t,v = type_version, 0
		if type_version % 16 == 1:
			t = (t-1)//16
			v = 1
		elif type_version % 16 == 0:
			t = t//16
		else:
			raise UnknownVersionException(f"Unknown version {type_version%16}.")

		origin_len = b[1]
		origin_pid = int.from_bytes(b[2:2+origin_len], BYTEORDER)

		payload_len = b[2+origin_len]

		payload = None

		start_payload = 2+origin_len+1

		if 0 <= t < 4 or 4 < t <= 6:
			payload = int.from_bytes(b[start_payload:start_payload+payload_len], BYTEORDER)
		elif t == 4 and v == 0:
			p_len = int.from_bytes(b[start_payload:start_payload+1], BYTEORDER)
			p = int.from_bytes(b[start_payload+1:start_payload+1+p_len], BYTEORDER)
			circuit = Crypto.Circuit.from_bytes(b[start_payload+1+p_len:start_payload+1+p_len+payload_len-1])
			circuit.set_prime(p)
			payload = (p, circuit)
		elif t == 4 and v == 1:
			p_len = int.from_bytes(b[start_payload:start_payload+1], BYTEORDER)
			p = int.from_bytes(b[start_payload+1:start_payload+1+p_len], BYTEORDER)
			g_len =  int.from_bytes(b[start_payload+1+p_len:start_payload+2+p_len], BYTEORDER)
			g = int.from_bytes(b[start_payload+2+p_len:start_payload+2+p_len+g_len], BYTEORDER)
			circuit = Crypto.Circuit.from_bytes(b[start_payload+2+p_len+g_len:start_payload+payload_len])
			circuit.set_prime(p)
			payload = (p, g, circuit)
		elif (t == 7 or t == 8) and v == 1:
			payload = []
			b_array = b[start_payload:start_payload+payload_len]
			next_len = None
			i = 0
			while i < payload_len:
				next_len = b_array[i]
				i += 1
				payload.append(int.from_bytes(b_array[i:i+next_len], BYTEORDER))
				i += next_len
		elif (t == 7 or t == 8) and v == 0:
			raise UnknownTypeException(f"Unknown Frame type 0x{t} for the PCEPS version (0x{0}).")
		else:
			raise UnknownTypeException(f"Unknown Frame type 0x{t} for the given version 0x{v}.")

		return Frame(t, v, origin_pid, payload)

	def to_bytes(self):
		"""
		Builds a sting of bytes representing the frame.

		Returns:
			The frame as bytes.

		Raises:
			UnknownVersionException: Version is invalid.
			UnknownTypeException: Type is invalid.
		"""
		if self.version > 1:
			raise UnknownVersionException(f"Unknown version {self.version}.")

		s = b""

		s += (self.type*16 + self.version).to_bytes(1, BYTEORDER)

		origin_len = Octets.get_len(self.origin)
		s += origin_len.to_bytes(1, BYTEORDER)
		s += self.origin.to_bytes(origin_len, BYTEORDER)

		if 0 <= self.type < 4 or 4 < self.type <= 6:
			payload_len = Octets.get_len(self.payload)
			s += payload_len.to_bytes(1, BYTEORDER)
			s += self.payload.to_bytes(payload_len, BYTEORDER)

		elif self.type == 4 and self.version == 0:
			p, circuit = self.payload
			encoded_circuit = circuit.to_bytes()
			p_len = Octets.get_len(p)
			payload_len = len(encoded_circuit) + 1 + p_len

			s += payload_len.to_bytes(1, BYTEORDER)

			s += p_len.to_bytes(1, BYTEORDER)
			s += p.to_bytes(p_len, BYTEORDER)

			s += encoded_circuit

		elif self.type == 4 and self.version == 1:
			p, g, circuit = self.payload
			encoded_circuit = circuit.to_bytes()
			p_len = Octets.get_len(p)
			g_len = Octets.get_len(g)
			payload_len = len(encoded_circuit) + 2 + p_len + g_len

			s += payload_len.to_bytes(1, BYTEORDER)

			s += p_len.to_bytes(1, BYTEORDER)
			s += p.to_bytes(p_len, BYTEORDER)
			s += g_len.to_bytes(1, BYTEORDER)
			s += g.to_bytes(g_len, BYTEORDER)

			s += encoded_circuit

		elif (self.type == 7 or self.type == 8) and self.version == 1:
			encoded_payload = b""
			for p in self.payload:
				p_len = Octets.get_len(p)
				encoded_payload += p_len.to_bytes(1, BYTEORDER)
				encoded_payload += p.to_bytes(p_len, BYTEORDER)

			s += len(encoded_payload).to_bytes(1, BYTEORDER)
			s += encoded_payload

		else:
			raise UnknownTypeException(f"Unknown Frame type 0x{self.type} for the given version 0x{self.version}.")

		return s