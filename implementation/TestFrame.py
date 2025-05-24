#!/bin/bash/python3
#encoding: utf-8

from core.Frame import *

from core import Crypto

import unittest


class TestFrame(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		print("""Launching Frame class test...""")

	@classmethod
	def setUp(self):
		print("""\tLaunching new test:""", end=" ")

	@classmethod
	def tearDown(self):
		print("""\tTest done.""")

	@classmethod
	def tearDownClass(self):
		print("""Frame class test done.\n""")

	def test_eq(self):
		print("""comparison between 2 identical frames""")
		frame1 = Frame(0,1,2)
		frame2 = Frame(0,1,2)

		result = frame1 == frame2

		self.assertTrue(result)

	def test_eq_bad(self):
		print("""comparison between 2 different frames""")
		frame1 = Frame(0,1,2)
		frame2 = Frame(0,1,1)

		result = frame1 == frame2

		self.assertFalse(result)

	def test_eq_not(self):
		print("""difference between 2 different frames""")
		frame1 = Frame(0,1,2)
		frame2 = Frame(0,1,1)

		result = frame1 != frame2

		self.assertTrue(result)

	def test_eq_other_type(self):
		print("""comparison between frame and another object of another type""")
		frame1 = Frame(0,1,2)
		frame2 = 1

		result = frame1 == frame2

		self.assertFalse(result)

	def test_from_bytes_ADVERT(self):
		print("""[from_bytes] for 0x0 type messages""")
		frame = b"\x00\x01\x01"
		expected = Frame(0,0,1)

		result = Frame.from_bytes(frame)

		self.assertEqual(result, expected)

	def test_from_bytes_SHARE(self):
		print("""[from_bytes] for 0x1 type messages""")
		frame = b"\x10\x01\x01"
		expected = Frame(1,0,1)

		result = Frame.from_bytes(frame)

		self.assertEqual(result, expected)

	def test_from_bytes_MUL(self):
		print("""[from_bytes] for 0x2 type messages""")
		frame = b"\x20\x01\x01"
		expected = Frame(2,0,1)

		result = Frame.from_bytes(frame)

		self.assertEqual(result, expected)

	def test_from_bytes_RESULT(self):
		print("""[from_bytes] for 0x3 type messages""")
		frame = b"\x30\x01\x01"
		expected = Frame(3,0,1)

		result = Frame.from_bytes(frame)

		self.assertEqual(result, expected)

	def test_from_bytes_SYNC(self):
		print("""[from_bytes] for 0x4 type messages""")
		frame = b"\x40\x11\x02\x01\x07\x11\x10\x00\x01\x01\x00\x01\x02\x12\x01\x02\x00\x01\x02"
		circuit = Crypto.Circuit()

		a = Crypto.Gate(Crypto.Gate.SHARE, value = 1)
		b = Crypto.Gate(Crypto.Gate.SHARE, value = 2)

		gate1 = Crypto.Gate(Crypto.Gate.ADD)
		inputs = [a, b]
		gate1.set_inputs(inputs)

		gate2 = Crypto.Gate(Crypto.Gate.CMUL, value = 2)
		inputs = [b]
		gate2.set_inputs(inputs)

		gate = Crypto.Gate(Crypto.Gate.MUL)
		inputs = [gate1, gate2]
		gate.set_inputs(inputs)

		circuit.add_gate(gate1)
		circuit.add_gate(gate2)
		circuit.add_gate(gate)

		expected = Frame(4,0,(263, circuit))

		result = Frame.from_bytes(frame)

		self.assertEqual(result, expected)

	def test_from_bytes_REQUEST(self):
		print("""[from_bytes] for 0x5 type messages""")
		frame = b"\x50\x01\x01"
		expected = Frame(5,0,1)

		result = Frame.from_bytes(frame)

		self.assertEqual(result, expected)

	def test_from_bytes_LEAVE(self):
		print("""[from_bytes] for 0x6 type messages""")
		frame = b"\x60\x01\x01"
		expected = Frame(6,0,1)

		result = Frame.from_bytes(frame)

		self.assertEqual(result, expected)

	def test_from_bytes_BVECT(self):
		print("""[from_bytes] for 0x7 type messages""")
		frame = b"\x71\x09\x01\x40\x02\x04\x00\x01\x0c\x01\x69"
		expected = Frame(7,1,[64, 1024, 12, 105])

		result = Frame.from_bytes(frame)

		self.assertEqual(result, expected)

	def test_from_bytes_MALICIOUS(self):
		print("""[from_bytes] for 0x8 type messages""")
		frame = b"\x81\x09\x01\x40\x02\x04\x00\x01\x0c\x01\x69"
		expected = Frame(8,1,[64, 1024, 12, 105])

		result = Frame.from_bytes(frame)

		self.assertEqual(result, expected)

	def test_from_bytes_UnknownVersion(self):
		print("""[from_bytes] Unknown Version Exception""")
		frame = b"\x62\x01\x01"
		result = lambda: Frame.from_bytes(frame)
		expected = UnknownVersionException
		self.assertRaises(expected, result)

	def test_from_bytes_UnknownType(self):
		print("""[from_bytes] Unknown Type Exception""")
		frame = b"\x70\x01\x01"
		result = lambda: Frame.from_bytes(frame)
		expected = UnknownTypeException
		self.assertRaises(expected, result)

	def test_to_bytes_ADVERT(self):
		print("""[to_bytes] for 0x0 type messages""")
		expected = b"\x00\x01\x01"
		frame = Frame(0,0,1)

		result = frame.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_SHARE(self):
		print("""[to_bytes] for 0x1 type messages""")
		expected = b"\x10\x01\x01"
		frame = Frame(1,0,1)

		result = frame.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_MUL(self):
		print("""[to_bytes] for 0x2 type messages""")
		expected = b"\x20\x01\x01"
		frame = Frame(2,0,1)

		result = frame.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_RESULT(self):
		print("""[to_bytes] for 0x3 type messages""")
		expected = b"\x30\x01\x01"
		frame = Frame(3,0,1)

		result = frame.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_SYNC(self):
		print("""[to_bytes] for 0x4 type messages""")
		expected = b"\x40\x11\x02\x01\x07\x11\x10\x00\x01\x01\x00\x01\x02\x12\x01\x02\x00\x01\x02"
		circuit = Crypto.Circuit()

		a = Crypto.Gate(Crypto.Gate.SHARE, value = 1)
		b = Crypto.Gate(Crypto.Gate.SHARE, value = 2)

		gate1 = Crypto.Gate(Crypto.Gate.ADD)
		inputs = [a, b]
		gate1.set_inputs(inputs)

		gate2 = Crypto.Gate(Crypto.Gate.CMUL, value = 2)
		inputs = [b]
		gate2.set_inputs(inputs)

		gate = Crypto.Gate(Crypto.Gate.MUL)
		inputs = [gate1, gate2]
		gate.set_inputs(inputs)

		circuit.add_gate(gate1)
		circuit.add_gate(gate2)
		circuit.add_gate(gate)

		frame = Frame(4,0,(263,circuit))

		result = frame.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_REQUEST(self):
		print("""[to_bytes] for 0x5 type messages""")
		expected = b"\x50\x01\x01"
		frame = Frame(5,0,1)

		result = frame.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_LEAVE(self):
		print("""[to_bytes] for 0x6 type messages""")
		expected = b"\x60\x01\x01"
		frame = Frame(6,0,1)

		result = frame.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_BVECT(self):
		print("""[to_bytes] for 0x7 type messages""")
		expected = b"\x71\x09\x01\x40\x02\x04\x00\x01\x0c\x01\x69"
		frame = Frame(7,1,[64, 1024, 12, 105])

		result = frame.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_MALICIOUS(self):
		print("""[to_bytes] for 0x8 type messages""")
		expected = b"\x81\x09\x01\x40\x02\x04\x00\x01\x0c\x01\x69"
		frame = Frame(8,1,[64, 1024, 12, 105])

		result = frame.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_UnknownVersion(self):
		print("""[to_bytes] Unknown Version Exception""")
		frame = Frame(6,2,1)
		result = lambda: frame.to_bytes()
		expected = UnknownVersionException
		self.assertRaises(expected, result)

	def test_to_bytes_UnknownType(self):
		print("""[to_bytes] Unknown Type Exception""")
		frame = Frame(7,0,1)
		result = lambda: frame.to_bytes()
		expected = UnknownTypeException
		self.assertRaises(expected, result)


if __name__ == '__main__':
	unittest.main()