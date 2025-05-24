#!/bin/bash/python3
#encoding: utf-8

import random

import sys

BYTEORDER = sys.byteorder

if __name__ != '__main__':
	from . import Octets

class GateCreationException(Exception):
	pass

class GateInputException(Exception):
	pass

class UnknownGateException(Exception):
	pass

class CircuitTranslationError(Exception):
	pass

class ComputationError(Exception):
	pass

class Gate:
	ADD = 0
	MUL = 1
	CMUL = 2
	SHARE = 3
	CONST = 4
	def __init__(self, type, value = None):
		self.type = type
		self.input_number = 0
		if self.type == Gate.ADD or self.type == Gate.MUL:
			self.input_number = 2
		elif self.type == Gate.CMUL or self.type == Gate.SHARE:
			self.input_number = 1
		self.inputs = []
		if value and (type != Gate.CMUL and type != Gate.SHARE and type != Gate.CONST):
			raise GateCreationException("This gate does not accept value assignment.")
		elif not value and (type == Gate.SHARE or type == Gate.CMUL):
			raise GateCreationException(f"This gate needs a value to be assigned to it. But {value} has been provided.")
		self.value = value # for SHARE, the pid it is reserved for
		self.prime_number = None

	def __repr__(self):
		return f"Gate: {self.type}, inputs = {self.inputs}, value = {self.value}"

	def __eq__(self, o):
		if type(o) != Gate:
			return False
		if self.type != o.get_type():
			return False
		if self.inputs != o.get_inputs():
			return False
		if self.value != o.get_result():
			return False

		return True

	def set_prime(self, p_n):
		"""
		Set the prime number to use in the computation.

		Arguments:
			p_n (int): prime number to use.
		"""
		self.prime_number = p_n

	def get_type(self):
		return self.type

	def get_inputs(self):
		return self.inputs

	def set_inputs(self, inputs):
		"""
		Set the gate inputs.

		Arguments:
			inputs (list): list of Gates object representing inputs.
		"""
		if len(inputs) == self.input_number:
			self.inputs = inputs
		else:
			raise ValueError(f"Incorrect number of inputs. Expected {self.input_number} but {len(inputs)} were provided.")

	def add_inputs(self, inputs):
		"""
		Add a list of gate inputs.

		Arguments:
			inputs (list): list of Gates object to append to the already existing input list.
		"""
		if len(inputs) + len(self.inputs) <= self.input_number:
			self.inputs += inputs
		else:
			raise ValueError(f"Incorrect number of inputs. Expected less than {self.input_number - len(self.inputs)} but {len(inputs)} were provided for type {self.type} gate.")

	def get_input_number(self):
		"""
		Get the expected number of inputs of the gate.

		Returns:
			The number of inputs expected by the gate.
		"""
		return self.input_number

	def compute(self):
		"""
		Computes the result of the gate depending on its type and inputs.
		"""
		if len(self.inputs) != self.input_number:
			raise GateInputException(f"Not enough input to compute the gate. Need {self.input_number} but {len(self.inputs)} were provided.")

		result = self.value

		if self.type == Gate.ADD:
			result = 0
			for i in self.inputs:
				val = i.get_result()
				if not val:
					raise GateInputException("Previous Gate has not been computed and therefore can not be used as input.")
				result += val

		elif self.type == Gate.MUL:
			result = 1
			for i in self.inputs:
				val = i.get_result()
				if not val:
					raise GateInputException("Previous Gate has not been computed and therefore can not be used as input.")
				result *= val

		elif self.type == Gate.CMUL:
			for i in self.inputs:
				val = i.get_result()
				if not val:
					raise GateInputException("Previous Gate has not been computed and therefore can not be used as input.")
				result *= val

		elif self.type == Gate.SHARE:
			result = self.inputs[0] # assign the share value instead of the pid

		result %= self.prime_number

		self.value = result

	def get_result(self):
		return self.value

	def to_bytes(self):
		"""
		Builds a sting of bytes representing the gate.

		Returns:
			The gate as bytes.
		"""
		s = b""
		if self.type == Gate.ADD:
			s += b"\x10"
		elif self.type == Gate.MUL:
			s += b"\x11"
		elif self.type == Gate.CMUL:
			s += b"\x12"
			val_len = Octets.get_len(self.value)
			s += val_len.to_bytes(1, BYTEORDER)
			s += self.value.to_bytes(val_len)
		elif self.type == Gate.SHARE:
			s += b"\x00"
			val_len = Octets.get_len(self.value)
			s += val_len.to_bytes(1, BYTEORDER)
			s += self.value.to_bytes(val_len)
		elif self.type == Gate.CONST:
			s += b"\x01"
			val_len = Octets.get_len(self.value)
			s += val_len.to_bytes(1, BYTEORDER)
			s += self.value.to_bytes(val_len)

		for i in self.inputs:
			s += i.to_bytes()

		return s

	def from_bytes(b):
		"""
		Builds a gate from bytes.

		Arguments:
			b (bytes): bytes representing the gate.

		Returns:
			The gate built and the remaining bytes.
		"""
		gate = None
		rest = None
		g_type = b[0:1]
		if g_type == b"\x10":
			gate = Gate(Gate.ADD)
			rest = b[1::]
		elif g_type == b"\x11":
			gate = Gate(Gate.MUL)
			rest = b[1::]
		elif g_type == b"\x12":
			value_len = b[1]
			value = int.from_bytes(b[2:2+value_len], BYTEORDER)
			gate = Gate(Gate.CMUL, value = value)
			rest = b[2+value_len::]
		elif g_type == b"\x00":
			value_len = b[1]
			value = int.from_bytes(b[2:2+value_len], BYTEORDER)
			gate = Gate(Gate.SHARE, value = value)
			rest = b[2+value_len::]
		elif g_type == b"\x01":
			value_len = b[1]
			value = int.from_bytes(b[2:2+value_len], BYTEORDER)
			gate = Gate(Gate.CONST, value = value)
			rest = b[2+value_len::]
		else:
			raise UnknownGateException(f"Unknown gate type {int.from_bytes(g_type, BYTEORDER)}.")

		return (gate, rest)

class Circuit:
	def __init__(self):
		self.gates = []
		self.current = 0

	def __repr__(self):
		return f"{self.gates}"

	def __eq__(self, o):
		if type(o) != Circuit:
			return False

		if self.gates == o.gates:
			return True

		return False

	def __len__(self):
		return len(self.gates)

	def set_prime(self, p_n):
		"""
		Set the prime number used in the computation to every gates.

		Arguments:
			p_n (int): prime number to use
		"""
		for gate in self.gates:
			gate.set_prime(p_n)
			for input_gate in gate.get_inputs():
				input_gate.set_prime(p_n)

	def add_gate(self, gate):
		"""
		Add another gate in the circuit.
		The order on which the gates have to be computed follows the order the gates are added in the circuit.

		Arguments:
			gate (Gate): the gate to add in the circuit.
		"""
		self.gates.append(gate)

	def get_gate_by_id(self, id):
		"""
		Get a specific gate in the circuit.

		Arguments:
			id (int): the identifier of the gate in the circuit.

		Returns:
			The gate corresponding to the given id.
		"""
		return self.gates[id]

	def get_gates(self):
		"""
		Get all the gates stored in the circuit.

		Returns:
			The list of gates in the circuit.
		"""
		return self.gates

	def get_next_gate(self):
		"""
		Get the next gate to process.
		
		Returns:
			The next gate to process.

		Raises:
			IndexError: no more gate to compute.
		"""
		if self.current >= len(self.gates):
			raise IndexError("No more gate to compute.")

		gate = self.gates[self.current]
		self.current += 1

		return gate

	def to_bytes(self):
		"""
		Builds a sting of bytes representing the circuit.

		Returns:
			The circuit and all its gates as bytes.
		"""
		if len(self.gates) == 0:
			raise ValueError("Circuit is empty.")
		root = self.gates[-1]

		return root.to_bytes()

	def from_bytes(b):
		"""
		Builds a circuit from bytes.

		Arguments:
			b (bytes): bytes representing the circuit.

		Returns:
			The circuit.
		"""
		circuit = Circuit()
		temp = []
		counts = []
		previous_node = None
		while b != b"":
			gate, b = Gate.from_bytes(b)
			
			if len(temp) > 0:
				if counts[-1] == temp[-1].get_input_number():
					circuit.add_gate(temp.pop())
					counts.pop()
				temp[-1].add_inputs([gate])
				counts[-1] += 1

			if gate.type == Gate.ADD or gate.type == Gate.MUL or gate.type == Gate.CMUL:
				temp.append(gate)
				counts.append(0)

		left = len(temp)
		for i in range(left):
			if counts[left-1-i] != temp[left-1-i].get_input_number():
				raise CircuitTranslationError("Circuit is incomplete and can therefore not be translated.")
			gate = temp[left-1-i]
			circuit.add_gate(gate)

		return circuit

	def get_input_ids(self):
		"""
		Get the list of party identifiers used in the circuit.

		Returns:
			The list of ids.
		"""
		ids = []
		for gate in self.gates:
			for input_gate in gate.get_inputs():
				if input_gate.get_type() == Gate.SHARE:
					id = input_gate.get_result()
					if not id in ids:
						ids.append(id)

		return ids


def generateRandomPrime(a, b):
	"""
	Allows the generation of prime numbers in a given range.

	Arguments:
		a (int): lower boundary of the range.
		b (int): higher boundary of the range.

	Returns:
		A random prime number in the given range. (int)
	"""
	# if a.type() != int:
	# 	raise TypeError(f"Parameter a should be Interger values, not {a.type()}.")
	# if b.type() != int:
	# 	raise TypeError(f"Parameter b should be Interger values, not {b.type()}.")
	bound = (a, b)
	if b <= a:
		#raise ValueError("The higher boundary (b) must be a greater integer than the lower boundary (a).")
		bound = (b, a)

	v, w = bound

	prime = random.randint(v, w)
	
	while not isPrime(prime):
		prime = random.randint(v, w)

	return prime

def create_shares(secret, ids, k, p, pceas_prime = None):
	"""
	Allows Creation of shares from a secret.

	Arguments:
		secret (int): the secret to encrypt
		ids (list): players' identifiers
		k (int): the threshold that determine how many shares are needed to reconstruct the secret
		p (int): field generator
		pceas_prime (int): the prime generator used for pceas protocol (optional, default: None)

	Returns:
		Set of shares [xi, f(xi)]. (dict)
		If pceas_prime is set, also return the B vector used in VSS
	"""
	if 0 in ids:
		raise ValueError("0 should never be in the list of ids while creating shares.")

	if p <= secret:
		raise ValueError("Size of the secret should be lower than the finite field size.")

	if len(ids) <= k:
		raise ValueError("Threshold t must be lower than the number of players n.")

	d = k-1
	coeff = [secret] + list(random.randint(0, p) for _ in range(d))
	#f = secret + c1*x + c2*x**2 + ... + cd*x**d
	print("coeff", coeff)

	shares = {}

	for i in ids:
		shares[i] = 0
		for j in range(d+1):
			shares[i] = (shares[i] + coeff[j] * i**j)%p

	if pceas_prime:
		b_vect = list((c*pceas_prime)%p for c in coeff)
		return (shares, b_vect)

	return shares

def compute_recombination_vector(parties_id, modulo):
	"""
	"""
	vector = {}

	for i in parties_id:
		delta_i = 1
		for j in parties_id:
			if i == j:
				continue
			delta_i *= -j/(i-j)
		vector[i] = int(delta_i)%modulo

	return vector

def compute_MPC_result(r_vector, results, p):
	n = len(results)
	if n != len(r_vector):
		raise ComputationError(f"Number of results differ from size of the recombination vector. {n} != {len(r_vector)}.")
	if not all(elmnt in list(r_vector.keys()) for elmnt in list(results.keys())):
		raise ComputationError(f"Recombination vector does not match the result (party ids do not match).")
	final_result = 0
	for i in list(results.keys()):
		final_result += (results[i]*r_vector[i])%p

	return final_result%p

def isPrime(n):    
	"""
	Miller-Rabin primality test. source: https://gist.github.com/tbenjis/c8a8cf8c4bf6272f2be0
 
	A return value of False means n is certainly not prime. A return value of
	True means n is very likely a prime.
	"""
	
	num_trials = 5 # number of bases to test
	assert n >= 2 # make sure n >= 2 else throw error
	# special case 2
	if n == 2:
		return True
	# ensure n is odd
	if n % 2 == 0:
		return False
	# write n-1 as 2**s * d
	# repeatedly try to divide n-1 by 2
	s = 0
	d = n-1
	while True:
		quotient, remainder = divmod(d, 2) # here we get the quotient and the remainder
		if remainder == 1:
			break
		s += 1
		d = quotient
	assert(2**s * d == n-1) # make sure 2**s*d = n-1
 
	# test the base a to see whether it is a witness for the compositeness of n
	def try_composite(a):
		if pow(a, d, n) == 1: # defined as pow(x, y) % z = 1
			return False
		for i in range(s):
			if pow(a, 2**i * d, n) == n-1:
				return False
		return True # n is definitely composite
 
	for i in range(num_trials):
		# try several trials to check for composite
		a = random.randrange(2, n)
		if try_composite(a):
			return False
 
	return True # no base tested showed n as composite


if __name__ == "__main__":
	import time
	import sys

	#print(sys.argv)
	# if len(sys.argv) == 2:
	# 	secret = int(sys.argv[1])
	# 	print("secret :", secret)
	# else:
	# 	secret = int(input("Entrez votre nombre secret: "))

	secrets = []
	shares = []
	r_vector = {}
	results = {}

	start = time.time()
	#field order should be 2^(arch type bits related) : 2^64 for computers
	#generate a great prime number that will be used to get number in its finite field
	p = generateRandomPrime(2**31, (2**32)-1)
	mid = time.time()
	k = 3
	n = 5
	print("Parameters: {\n\r\t k : %i\n\r\t n : %i\n\r\t p : %i\n\r}" % (k,n,p))

	r_vector = compute_recombination_vector(list(range(1, n+1)), p)
	print(r_vector)

	for i in range(k):
		secret = random.randint(20,30)
		secrets.append(secret)
		shares.append(create_shares(secret, list(range(1, n+1)), k, p))

	print("result should be: ", (sum(secrets)/k)%p)

	print("shares =", shares)

	for party_id in range(1, n+1):
		r = 0
		for i in range(k):
			r = (r + shares[i][party_id])%p

		results[party_id] = r

	result = compute_MPC_result(r_vector, results, p)

	print("result =", result/k)

	print("\n\rexecution time: %.3fs; prime generation: %.3fs\n\n" % (time.time()-start, mid-start))


