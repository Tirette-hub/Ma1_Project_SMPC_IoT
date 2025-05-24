#!/bin/bash/python3
#encoding: utf-8

from core import Link, Party, Crypto

import unittest

class TestCrypto(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		print("""Launching Crypto functions test...""")

	@classmethod
	def setUp(self):
		print("""\tLaunching new test:""", end=" ")

	@classmethod
	def tearDown(self):
		print("""\tTest done.""")

	@classmethod
	def tearDownClass(self):
		print("""Crypto functions test done.""")

	def test_isPrime_ok(self):
		print("""[isPrime]""")
		result = Crypto.isPrime(7)
		self.assertTrue(result)

	def test_isPrime_even(self):
		print("""[isPrime] of an even number""")
		result = Crypto.isPrime(8)
		self.assertFalse(result)

	def test_isPrime_large(self):
		print("""[isPrime] of a large prime number""")
		n = 3000000019
		result = Crypto.isPrime(n)
		self.assertTrue(result)

	def test_compute_recombination_vector(self):
		print("""[compute_recombination_vector]""")
		result = Crypto.compute_recombination_vector([1,2,3], 31)
		expected = {1:3,2:28,3:1}

		self.assertEqual(result, expected)

	def test_compute_MPC_result(self):
		print(f"""[compute_MPC_result]""")
		import random

		secrets = []
		shares = []
		r_vector = {}
		results = {}

		p = Crypto.generateRandomPrime(2**31, (2**32)-1)
		k = 3
		n = 5

		r_vector = Crypto.compute_recombination_vector(list(range(1, n+1)), p)

		for i in range(k):
			secret = random.randint(20,30)
			secrets.append(secret)
			shares.append(Crypto.create_shares(secret, list(range(1, n+1)), k, p))

		for party_id in range(1, n+1):
			r = 0
			for i in range(k):
				r = (r + shares[i][party_id])%p

			results[party_id] = r

		result = Crypto.compute_MPC_result(r_vector, results, p)/k

		expected = (sum(secrets)/k)%p

		self.assertEqual(result, expected)

class TestGate(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		print("""Launching Gate class test...""")

	@classmethod
	def setUp(self):
		print("""\tLaunching new test:""", end=" ")

	@classmethod
	def tearDown(self):
		print("""\tTest done.""")

	@classmethod
	def tearDownClass(self):
		print("""Gate class test done.""")

	def test_get_input_number(self):
		print("""[get_input_number]""")
		expected = 1
		gate = Crypto.Gate(Crypto.Gate.CMUL, value = 2)
		result = gate.get_input_number()

		self.assertEqual(result, expected)

	def test_set_inputs(self):
		print("""[set_inputs]""")
		inputs = [Crypto.Gate(Crypto.Gate.SHARE, value = 3),Crypto.Gate(Crypto.Gate.SHARE, value = 2)]
		expected = 2
		gate = Crypto.Gate(Crypto.Gate.ADD)
		gate.set_inputs(inputs)
		result = gate.get_input_number()

		self.assertEqual(result, expected)

	def test_add_inputs(self):
		print("""[add_inputs]""")
		inputs1 = [Crypto.Gate(Crypto.Gate.SHARE, value = 3)]
		inputs2 = [Crypto.Gate(Crypto.Gate.SHARE, value = 2)]
		expected = 2
		gate = Crypto.Gate(Crypto.Gate.ADD)
		gate.add_inputs(inputs1)
		gate.add_inputs(inputs2)
		result = gate.get_input_number()

		self.assertEqual(result, expected)

		expected = ValueError
		result = lambda: gate.add_inputs(inputs1)

		self.assertRaises(expected, result)

	def test_compute_CONST(self):
		print("""[compute] on CONST test gate""")
		expected = 1
		gate = Crypto.Gate(Crypto.Gate.CONST, value = 264)
		gate.set_prime(263)
		gate.compute()
		result = gate.get_result()

		self.assertEqual(result, expected)

	def test_compute_SHARE(self):
		print("""[compute] on SGARE gate""")
		expected = 30
		gate = Crypto.Gate(Crypto.Gate.SHARE, value = 1)
		gate.set_prime(263)
		gate.add_inputs([expected])
		gate.compute()
		result = gate.get_result()

		self.assertEqual(result, expected)

	def test_compute_ADD(self):
		print("""[compute] on ADD gate""")
		inputs = [Crypto.Gate(Crypto.Gate.CONST, value = 3), Crypto.Gate(Crypto.Gate.CONST, value = 2)]
		expected = inputs[0].get_result() + inputs[1].get_result()
		gate = Crypto.Gate(Crypto.Gate.ADD)
		gate.set_prime(263)
		gate.set_inputs(inputs)
		gate.compute()
		result = gate.get_result()

		self.assertEqual(result, expected)

	def test_compute_ADD_Error(self):
		print("""[compute] on ADD gate with wrong number of inputs""")
		inputs = [Crypto.Gate(Crypto.Gate.CONST, value = 3)]
		gate = Crypto.Gate(Crypto.Gate.ADD)
		gate.set_prime(263)
		result = lambda: gate.compute()
		expected = Crypto.GateInputException

		self.assertRaises(expected, result)

		gate.add_inputs(inputs)

		self.assertRaises(expected, result)

	def test_compute_MUL(self):
		print("""[compute] on MUL gate""")
		inputs = [Crypto.Gate(Crypto.Gate.CONST, value = 3), Crypto.Gate(Crypto.Gate.CONST, value = 2)]
		expected = inputs[0].get_result() * inputs[1].get_result()
		gate = Crypto.Gate(Crypto.Gate.MUL)
		gate.set_prime(263)
		gate.set_inputs(inputs)
		gate.compute()
		result = gate.get_result()

		self.assertEqual(result, expected)

	def test_compute_MUL_Error(self):
		print("""[compute] on MUL gate with wrong number of inputs""")
		inputs = [Crypto.Gate(Crypto.Gate.CONST, value = 3)]
		gate = Crypto.Gate(Crypto.Gate.MUL)
		gate.set_prime(263)
		result = lambda: gate.compute()
		expected = Crypto.GateInputException

		self.assertRaises(expected, result)

		gate.add_inputs(inputs)

		self.assertRaises(expected, result)

	def test_compute_CMUL(self):
		print("""[compute] on CMUL gate""")
		inputs = [Crypto.Gate(Crypto.Gate.CONST, value = 3)]
		constant = 2
		expected = inputs[0].get_result() * constant
		gate = Crypto.Gate(Crypto.Gate.CMUL, value = constant)
		gate.set_prime(263)
		gate.set_inputs(inputs)
		gate.compute()
		result = gate.get_result()

		self.assertEqual(result, expected)

	def test_compute_CMUL_Error(self):
		print("""[compute] on CMUL gate with wrong number of inputs""")
		inputs = []
		constant = 2
		gate = Crypto.Gate(Crypto.Gate.CMUL, value = constant)
		gate.set_prime(263)
		result = lambda: gate.compute()
		expected = Crypto.GateInputException

		self.assertRaises(expected, result)

	def test_to_bytes_SHARE(self):
		print("""[to_bytes] for SHARE intermediate gate""")
		gate = Crypto.Gate(Crypto.Gate.SHARE, value = 1)
		gate.set_prime(263)
		expected = b"\x00\x01\x01"

		result = gate.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_ADD(self):
		print("""[to_bytes] for ADD gate""")
		inputs = [Crypto.Gate(Crypto.Gate.SHARE, value = 3), Crypto.Gate(Crypto.Gate.SHARE, value = 2)]
		gate = Crypto.Gate(Crypto.Gate.ADD)
		gate.set_prime(263)
		gate.set_inputs(inputs)
		expected = b"\x10\x00\x01\x03\x00\x01\x02"

		result = gate.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_MUL(self):
		print("""[to_bytes] for MUL gate""")
		inputs = [Crypto.Gate(Crypto.Gate.SHARE, value = 3), Crypto.Gate(Crypto.Gate.SHARE, value = 2)]
		gate = Crypto.Gate(Crypto.Gate.MUL)
		gate.set_prime(263)
		gate.set_inputs(inputs)
		expected = b"\x11\x00\x01\x03\x00\x01\x02"

		result = gate.to_bytes()

		self.assertEqual(result, expected)

	def test_to_bytes_CMUL(self):
		print("""[to_bytes] for CMUL gate""")
		inputs = [Crypto.Gate(Crypto.Gate.SHARE, value = 3)]
		gate = Crypto.Gate(Crypto.Gate.CMUL, value = 2)
		gate.set_prime(263)
		gate.set_inputs(inputs)
		expected = b"\x12\x01\x02\x00\x01\x03"

		result = gate.to_bytes()

		self.assertEqual(result, expected)

	def test_from_bytes_SHARE(self):
		print("""[from_bytes] for SHARE gate""")
		gate = b"\x00\x01\x02"
		expected = Crypto.Gate(Crypto.Gate.SHARE, value = 2)

		result, b = Crypto.Gate.from_bytes(gate)

		self.assertEqual(result, expected)

	def test_from_bytes_CONST(self):
		print("""[from_bytes] for CONST test gate""")
		gate = b"\x01\x01\x02"
		expected = Crypto.Gate(Crypto.Gate.CONST, value = 2)

		result, b = Crypto.Gate.from_bytes(gate)

		self.assertEqual(result, expected)

	def test_from_bytes_ADD(self):
		print("""[from_bytes] for ADD gate""")
		gate = b"\x10\x00\x01\x01\x00\x01\x02"
		expected = Crypto.Gate(Crypto.Gate.ADD)
		#inputs = [Crypto.Gate(Crypto.Gate.SHARE, value = 1), Crypto.Gate(Crypto.Gate.SHARE, value = 2)]
		#expected.set_inputs(inputs)

		result, b = Crypto.Gate.from_bytes(gate)

		self.assertEqual(result, expected)
		self.assertEqual(b, gate[1::])

	def test_from_bytes_MUL(self):
		print("""[from_bytes] for MUL gate""")
		gate = b"\x11\x00\x01\x01\x00\x01\x02"
		expected = Crypto.Gate(Crypto.Gate.MUL)
		#inputs = [Crypto.Gate(Crypto.Gate.SHARE, value = 1), Crypto.Gate(Crypto.Gate.SHARE, value = 2)]
		#expected.set_inputs(inputs)

		result, b = Crypto.Gate.from_bytes(gate)

		self.assertEqual(result, expected)
		self.assertEqual(b, gate[1::])

	def test_from_bytes_CMUL(self):
		print("""[from_bytes] for CMUL gate""")
		gate = b"\x12\x01\x02\x00\x01\x02"
		expected = Crypto.Gate(Crypto.Gate.CMUL, value = 2)
		#inputs = [Crypto.Gate(Crypto.Gate.SHARE, value = 2)]
		#expected.set_inputs(inputs)

		result, b = Crypto.Gate.from_bytes(gate)

		self.assertEqual(result, expected)
		self.assertEqual(b, gate[3::])

	def test_from_bytes_UnknownGateException(self):
		print("""[from_bytes] with unknown gate type""")
		gate = b"\x13"
		expected = Crypto.UnknownGateException

		result = lambda: Crypto.Gate.from_bytes(gate)

		self.assertRaises(expected, result)

class TestCircuit(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		print("""Launching Circuit class test...""")
		self.circuit = Crypto.Circuit()
		self.gate1 = Crypto.Gate(Crypto.Gate.CMUL, value = 2)
		self.gate2 = Crypto.Gate(Crypto.Gate.ADD)
		self.circuit.add_gate(self.gate1)
		self.circuit.add_gate(self.gate2)

	@classmethod
	def setUp(self):
		print("""\tLaunching new test:""", end=" ")

	@classmethod
	def tearDown(self):
		print("""\tTest done.""")

	@classmethod
	def tearDownClass(self):
		print("""Circuit class test done.""")

	def test_len(self):
		print("""[len]""")
		expected = 2
		result = len(self.circuit)

		self.assertEqual(result, expected)

	def test_get_gates(self):
		print("""[get_gates]""")
		expected = [self.gate1, self.gate2]
		result = self.circuit.get_gates()

		self.assertEqual(result, expected)

	def test_get_gate_by_id(self):
		print("""[get_gate_by_id]""")
		expected = self.gate1
		result = self.circuit.get_gate_by_id(0)

		self.assertEqual(result, expected)

	def test_get_next_gate(self):
		print("""[get_next_gate]""")
		expected = self.gate1
		result = self.circuit.get_next_gate()

		self.assertEqual(result, expected)

		expected = self.gate2
		result = self.circuit.get_next_gate()

		self.assertEqual(result, expected)

		expected = IndexError
		result = lambda: self.circuit.get_next_gate()

		self.assertRaises(expected, result)

	def test_to_bytes(self):
		print("""[to_bytes]""")
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

		circuit = Crypto.Circuit()
		circuit.add_gate(gate1)
		circuit.add_gate(gate2)
		circuit.add_gate(gate)

		expected = b"\x11\x10\x00\x01\x01\x00\x01\x02\x12\x01\x02\x00\x01\x02"

		result = gate.to_bytes()

		self.assertEqual(result, expected)

	def test_from_bytes(self):
		print("""[from_bytes]""")
		circuit = b"\x11\x10\x00\x01\x01\x00\x01\x02\x12\x01\x02\x00\x01\x02"
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

		expected = Crypto.Circuit()
		expected.add_gate(gate1)
		expected.add_gate(gate2)
		expected.add_gate(gate)

		result = Crypto.Circuit.from_bytes(circuit)

		self.assertEqual(result, expected)

	def test_from_bytes_error(self):
		print("""[from_bytes] with ADD circuit""")
		circuit = b"\x10\x10\x10\x00\01\x01\x00\x01\x02\x00\x01\x03"

		expected = Crypto.CircuitTranslationError

		result = lambda: Crypto.Circuit.from_bytes(circuit)

		self.assertRaises(expected, result)

	def test_get_input_ids(self):
		print("""[get_input_ids]""")
		expected = [1,2]
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

		circuit = Crypto.Circuit()
		circuit.add_gate(gate1)
		circuit.add_gate(gate2)
		circuit.add_gate(gate)

		result = circuit.get_input_ids()

		self.assertEqual(result, expected)


if __name__ == '__main__':
	unittest.main()