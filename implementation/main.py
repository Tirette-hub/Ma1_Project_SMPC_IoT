import network
import time
import socket
import machine
import sys
import random


LAST_RCVD_TIME = 0
SANITY_PASSED = False
GATE_COUNT = 0


class UnknownVersionException(Exception):
	pass

class UnknownTypeException(Exception):
	pass

class GateCreationException(Exception):
	pass

class GateInputException(Exception):
	pass

class UnknownGateException(Exception):
	pass

class CircuitTranslationError(Exception):
	pass

class Crypto:
	def generateRandomPrime(a, b):
		bound = (a, b)
		if b <= a:
			bound = (b, a)

		v, w = bound

		prime = random.randint(v, w)

		while not Crypto.isPrime(prime):
			prime = random.randint(v, w)

		return prime

	def create_shares(secret, ids, k, p, pceas_prime = None):
		if 0 in ids:
			raise ValueError("0 should never be in the list of ids while creating shares.")

		if p <= secret:
			raise ValueError("Size of the secret should be lower than the finite field size.")

		if len(ids) <= k:
			raise ValueError("Threshold t must be lower than the number of players n.")

		d = k - 1
		coeff = [secret] + list(random.randint(0, p) for _ in range(d))
		# f = secret + c1*x + c2*x**2 + ... + cd*x**d

		shares = {}

		for i in ids:
			shares[i] = 0
			for j in range(d + 1):
				shares[i] = (shares[i] + coeff[j] * i ** j) % p

		if pceas_prime:
			b_vect = list((c*pceas_prime)%p for c in coeff)
			return (shares, b_vect)

		return shares

	def compute_recombination_vector(parties_id, modulo):
		vector = {}

		for i in parties_id:
			delta_i = 1
			for j in parties_id:
				if i == j:
					continue
				delta_i *= -j / (i - j)
			vector[i] = int(delta_i) % modulo

		return vector

	def isPrime(n):
		num_trials = 5
		if n < 2:
			return False
		if n == 2:
			return True
		if n % 2 == 0:
			return False
		s = 0
		d = n - 1
		while True:
			quotient, remainder = divmod(d, 2)
			if remainder == 1:
				break
			s += 1
			d = quotient
		assert (2 ** s * d == n - 1)

		def try_composite(a):
			if pow(a, d, n) == 1:
				return False
			for i in range(s):
				if pow(a, 2 ** i * d, n) == n - 1:
					return False
			return True

		for i in range(num_trials):
			a = random.randrange(2, n)
			if try_composite(a):
				return False

		return True

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
		self.value = value
		self.prime_number = None

	def __repr__(self):
		return f"Gate: {self.type}, inputs = {self.inputs}, value = {self.value}"

	def __eq__(self, o):
		if type(o) != Gate:
			return False
		if self.type != o.type:
			return False
		if self.inputs != o.get_inputs():
			return False
		if self.value != o.get_result():
			return False

		return True

	def get_inputs(self):
		return self.inputs

	def set_prime(self, p_n):
		self.prime_number = p_n

	def add_inputs(self, inputs):
		if len(inputs) + len(self.inputs) <= self.input_number:
			self.inputs += inputs
		else:
			raise ValueError(f"Incorrect number of inputs. Expected less than {self.input_number - len(self.inputs)} but {len(inputs)} were provided for type {self.type} gate.")

	def get_input_number(self):
		return self.input_number

	def compute(self):
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
			result = self.inputs[0]

		result %= self.prime_number

		self.value = result

	def get_result(self):
		return self.value

	def to_bytes(self):
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
		for gate in self.gates:
			gate.set_prime(p_n)
			for input_gate in gate.get_inputs():
				input_gate.set_prime(p_n)

	def add_gate(self, gate):
		self.gates.append(gate)

	def get_gate_by_id(self, id):
		return self.gates[id]

	def set_share_by_id(self, party_id, value):
		for gate in self.gates:
			for input_gate in gate.get_inputs():
				if input_gate.type == Gate.SHARE:
					if input_gate.value == party_id:
						input_gate.value = value

	def get_gates(self):
		return self.gates

	def get_next_gate(self):
		if self.current >= len(self.gates):
			return None

		gate = self.gates[self.current]
		self.current += 1

		return gate

	def to_bytes(self):
		if len(self.gates) == 0:
			raise ValueError("Circuit is empty.")
		root = self.gates[-1]

		return root.to_bytes()

	def from_bytes(b):
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
		ids = []
		for gate in self.gates:
			for input_gate in gate.get_inputs():
				if input_gate.type == Gate.SHARE:
					id = input_gate.get_result()
					if not id in ids:
						ids.append(id)

		return ids

class Octets:
	def get_len(val):
			i = 1
			while True:
				if val < 2**(8*i):
					return i
				i += 1

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

	def from_bytes(b):
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

		start_payload = 2 + origin_len + 1

		if 0 <= t < 4 or 4 < t <= 6:
			payload = int.from_bytes(b[start_payload:start_payload+payload_len], BYTEORDER)
		elif t == 4 and v == 0:
			p_len = int.from_bytes(b[start_payload:start_payload+1], BYTEORDER)
			p = int.from_bytes(b[start_payload+1:start_payload+1+p_len], BYTEORDER)
			circuit = Circuit.from_bytes(b[start_payload+1+p_len:start_payload+1+p_len+payload_len-1])
			circuit.set_prime(p)
			payload = (p, circuit)
		elif t == 4 and v == 1:
			p_len = int.from_bytes(b[start_payload:start_payload+1], BYTEORDER)
			p = int.from_bytes(b[start_payload+1:start_payload+1+p_len], BYTEORDER)
			g_len =  int.from_bytes(b[start_payload+1+p_len:start_payload+2+p_len], BYTEORDER)
			g = int.from_bytes(b[start_payload+2+p_len:start_payload+2+p_len+g_len], BYTEORDER)
			circuit = Circuit.from_bytes(b[start_payload+2+p_len+g_len:start_payload+payload_len])
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

class Party:
	START = 0
	AWAITING = 1 # 25
	SYNC = 2 # 26
	COMP = 3 # 32
	GATE_COMP = 4
	RES = 5 # 33

	def __init__(self, p_id):
		self.party_id = p_id
		self.state = Party.START
		self.shares = {}
		self.B_vectors = {}
		self.circuit = None
		self.applicant = None
		self.k = 0
		self.prime_p = 0
		self.prime_g = 0
		self.results = {}
		self.r_vect = {}
		self.final_result = None
		self.known_parties = {}
		self.isProvider = False
		self.blacklist = []

	def sanity_check(self):
		if self.k < 2:
			return False

		begin = time.time()
		n = len(self.known_parties)
		while n < self.k:
			if time.time() - begin > TIMEOUT:
				self.clean()
				log("missing known parties: " + str(n) + " < " + str(self.k) + ".")
				return False

			n = len(self.known_parties)+1

		if Crypto.isPrime(self.prime_p):
			return True

		log("prime_p is not prime.")

		return False

	def clean(self):
		global LAST_RCVD_TIME
		global SANITY_PASSED
		global GATE_COUNT
		global SHARES_CHECKED
		global INPUT_SET

		self.shares = {}
		self.B_vectors = {}
		self.circuit = None
		self.applicant = None
		self.k = 0
		self.prime_p = 0
		self.prime_g = 0
		self.results = {}
		self.r_vect = {}
		self.final_result = None
		self.isProvider = False

		LAST_RCVD_TIME = 0
		SANITY_PASSED = False
		GATE_COUNT = 0
		SHARES_CHECKED = False
		INPUT_SET = False

		self.state = Party.AWAITING


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
		addr = []

		frame = Frame.from_bytes(b[:])

		return Message(Message.FRAME, None, frame)

QUIT = False
SHARES_CHECKED = False

ssid = %SSID%
password = %PASSWORD%

WLAN = None
PARTY_ID = %party_id%

IP = None
PORT = 5005

S = None

BYTEORDER = 'little'

SELF = Party(PARTY_ID)

TIMEOUT = 20

VERSION = None

BEGIN_TIME = 0
START_ADVERT_COUNT = 0

start_pin = machine.Pin(25, machine.Pin.OUT)
awaiting_pin = machine.Pin(26, machine.Pin.OUT)
sync_pin = machine.Pin(27, machine.Pin.OUT)
comp_pin = machine.Pin(32, machine.Pin.OUT)
res_pin = machine.Pin(33, machine.Pin.OUT)

INPUT_SET = False

def log(message):
	print("\r[" + str(time.time()) + " - PARTY:" + str(PARTY_ID) + "]", message)

def connect_to_wifi(ssid, password, timeout_ms=5000):
	wlan = network.WLAN(network.STA_IF)
	wlan.active(True)
	if not wlan.isconnected():
		print('connecting to network...')
		wlan.connect(ssid, password)

		while not wlan.isconnected():
			print('.', end="")
			time.sleep_ms(500)
			timeout_ms -= 500
			if timeout_ms <= 0:
				print("")
				return None

	return wlan

def start():
	global WLAN
	global S
	global SELF
	global IP
	global BEGIN_TIME
	global VERSION
	global QUIT

	start_pin.off()
	awaiting_pin.off()
	sync_pin.off()
	comp_pin.off()
	res_pin.off()


	WLAN = connect_to_wifi(ssid, password)
	if not WLAN:
		log("failed to connect to wifi")
		QUIT = True
		return False

	print("started")
	start_pin.on()

	S = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	S.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	IP = WLAN.ifconfig()[0]
	log(IP)
	S.bind((IP, PORT))
	S.settimeout(.1)
	SELF.known_parties[PARTY_ID] = (IP, PORT)
	BEGIN_TIME = time.time()
	SELF.state = Party.AWAITING
	awaiting_pin.on()
	VERSION = Frame.PCEPS

	BROADCAST_ADDR = %BROADCAST ADDRESS%
def loop():
	global SELF
	global LAST_RCVD_TIME
	global VERSION
	global TIMEOUT
	global SANITY_PASSED
	global GATE_COUNT
	global START_ADVERT_COUNT
	global BEGIN_TIME
	global QUIT
	global SHARES_CHECKED
	global INPUT_SET

	try:
		data, (addr, port) = S.recvfrom(128)
	except OSError as e:
		data = None

	if SELF.state == Party.AWAITING:
		t = time.time()
		delta = t - BEGIN_TIME
		if START_ADVERT_COUNT < 3 and delta >= TIMEOUT//2:
			new_frame = Frame(Frame.ADVERT, Frame.PCEPS, PARTY_ID, PARTY_ID)
			new_message = Message(Message.FRAME, (IP, PORT), new_frame)
			log("broadcasting advertisement")
			S.sendto(new_message.to_bytes(), (BROADCAST_ADDR, PORT))

			BEGIN_TIME = time.time()
			START_ADVERT_COUNT += 1

	if data:
		message = Message.from_bytes(data)
		message.set_origin((addr, port))
		_, origin, frame = message.get()
		log("message received from (" + addr + ":" + str(port) + ") with payload " + str(frame) + " in state " + str(SELF.state))
		if not frame.origin in SELF.blacklist:
			if SELF.state == Party.AWAITING:
				if frame.type == Frame.ADVERT:
					LAST_RCVD_TIME = time.time()
					party = frame.payload
					if not party in SELF.known_parties.keys():
						SELF.known_parties[party] = origin
						log("new party " + str(party) + " entered the network.")
						new_frame = Frame(Frame.ADVERT, VERSION, PARTY_ID, PARTY_ID)
						new_message = Message(Message.FRAME, (IP, PORT), new_frame)
						#log("ADVERTISING with version " + str(VERSION) + ".")
						S.sendto(new_message.to_bytes(), (BROADCAST_ADDR, PORT))

				elif frame.type == Frame.LEAVE:
					LAST_RCVD_TIME = time.time()
					party = frame.payload
					log(str(party) + " left the network.")
					SELF.known_parties.pop(party, None)

				elif frame.type == Frame.REQUEST:
					LAST_RCVD_TIME = time.time()
					VERSION = frame.version
					SELF.applicant = frame.payload
					SELF.state = Party.SYNC
					# START current monitoring
					awaiting_pin.off()
					sync_pin.on()
					# STOP
					log("waiting for sync")

			elif SELF.state == Party.SYNC:
				if frame.type == Frame.LEAVE:
					LAST_RCVD_TIME = time.time()
					party = frame.payload
					log(str(party) + " left the network.")
					SELF.known_parties.pop(party, None)

				elif frame.type == Frame.SYNC:
					LAST_RCVD_TIME = time.time()
					party = frame.origin
					version = frame.version
					if version == VERSION:
						if version == Frame.PCEPS:
							SELF.prime_p, SELF.circuit = frame.payload
						elif version == Frame.PCEAS:
							SELF.prime_p, SELF.prime_g, SELF.circuit = frame.payload

						SELF.k = len(SELF.circuit.get_input_ids())
						if PARTY_ID in SELF.known_parties.keys():
							log("I'm a provider")
							SELF.isProvider = True
						log("COMPUTE")
						SELF.state = Party.COMP
						# START current monitoring
						sync_pin.off()
						comp_pin.on()
						# STOP
					else:
						log("Received SYNC frame from " + str(party) + " but versions do not match. Expected " + str(VERSION) + " but received" + str(version) + ".")

			elif SELF.state == Party.COMP or SELF.state == Party.GATE_COMP:
				if frame.type == Frame.LEAVE:
					LAST_RCVD_TIME = time.time()
					party = frame.payload
					log(str(party) + " left the network.")
					SELF.known_parties.pop(party, None)

				elif frame.type == Frame.SHARE:
					LAST_RCVD_TIME = time.time()
					#recover share
					share = frame.payload%SELF.prime_p
					p_id = frame.origin
					version = frame.version
					log(str(p_id) + " shared " + str(share))
					if version == VERSION:
						if p_id:
							if not p_id in SELF.shares.keys():
								SELF.shares[p_id] = share
					else:
						log("Received SHARE frame from " + str(p_id) + " but versions do not match. Expected " + str(VERSION) + " but received" + str(version) + ".")

				elif frame.type == Frame.BVECT:
					if VERSION == Frame.PCEAS:
						vect = frame.payload
						party = frame.origin
						if party in SELF.known_parties and party != SELF.B_vectors.keys():
							log("Received a B vector from "+str(frame.origin)+": " + str(vect))
							SELF.B_vectors[party] = vect

				elif frame.type == Frame.MUL:
					pass

				elif frame.type == Frame.RESULT:
					LAST_RCVD_TIME = time.time()
					SELF.state = Party.RES
					# START current monitoring
					comp_pin.off()
					res_pin.on()
					# STOP
					result = frame.payload
					p_id = frame.origin
					version = frame.version
					log("Received " + str(result) + " from " + str(origin))
					if version == VERSION:
						if p_id:
							SELF.results[p_id] = result
					else:
						log("Received RESULT frame from " + str(p_id) + " but versions do not match. Expected " + str(VERSION) + " but received" + str(version) + ".")

				elif frame.type == Frame.MALICIOUS:
					suspected = frame.payload
					origin = frame.origin
					if VERSION == Frame.PCEAS:
						if not all(e in SELF.blacklist for e in suspected):
							for e in suspected:
								if e == PARTY_ID:
									continue
								if e not in SELF.blacklist:
									SELF.blacklist.append(e)
									log("Blacklisted " + str(e))
								if e in SELF.known_parties.keys():
									SELF.known_parties.pop(e)
							new_frame = Frame(Frame.MALICIOUS, VERSION, PARTY_ID, suspected)
							new_message = Message(Message.FRAME, (IP, PORT), new_frame)
							S.sendto(new_message.to_bytes(), (BROADCAST_ADDR, PORT))
							SELF.clean()

					comp_pin.off()
					awaiting_pin.on()

			elif SELF.state == Party.RES:
				if frame.type == Frame.LEAVE:
					LAST_RCVD_TIME = time.time()
					party = frame.payload
					log(str(party) + " left the network.")
					SELF.known_parties.pop(party, None)

		else:
			log("rejected because it was blacklisted.")

	t = time.time()
	if LAST_RCVD_TIME:
		delta_t = t - LAST_RCVD_TIME
		if SELF.state == Party.SYNC:
			if delta_t >= TIMEOUT:
				LAST_RCVD_TIME = 0
				SANITY_PASSED = False
				GATE_COUNT = 0
				SELF.clean()
				sync_pin.off()
				awaiting_pin.on()
				log("Never received the SYNC frame before timeout")

		elif SELF.state == Party.COMP:
			if not SANITY_PASSED:
				if not SELF.sanity_check():
					LAST_RCVD_TIME = 0
					SANITY_PASSED = False
					GATE_COUNT = 0
					SELF.clean()
					comp_pin.off()
					awaiting_pin.on()
					log("Sanity check did not pass yet")
				else:
					SANITY_PASSED = True
					SELF.r_vect = Crypto.compute_recombination_vector(list(SELF.known_parties.keys()), SELF.prime_p)
			else:
				secret = random.randint(15,25)
				log("secret = " + str(secret))
				if VERSION == Frame.PCEPS:
					shares = Crypto.create_shares(secret, list(SELF.known_parties.keys()), SELF.k, SELF.prime_p)
				elif VERSION == Frame.PCEAS:
					result = Crypto.create_shares(secret, list(SELF.known_parties.keys()), SELF.k, SELF.prime_p, pceas_prime=SELF.prime_g)
					log("Result= " + str(result))
					shares, b_vect = result
					log("B = " + str(b_vect))

					SELF.B_vectors[PARTY_ID] = b_vect

					log("broadcasting B vect to:" + str(SELF.known_parties) + ".")
					new_frame = Frame(Frame.BVECT, VERSION, PARTY_ID, b_vect)
					new_message = Message(Message.FRAME, (IP, PORT), new_frame)
					S.sendto(new_message.to_bytes(), (BROADCAST_ADDR, PORT))

				log("shares = " + str(shares))

				for s_id in shares.keys():
					if s_id == PARTY_ID:
						SELF.shares[s_id] = shares[s_id]
						log("my shares = " + str(shares[s_id]))
					else:
						log("sending share " + str(shares[s_id]) + " to " + str(s_id) + ' ' + str(SELF.known_parties[s_id]))
						if s_id == 2:
							#create malicious payload here such as:
							"""
							log("sending malicious payload to pid 2!")
							new_frame = Frame(Frame.SHARE, VERSION, PARTY_ID, (shares[s_id]+2000)%SELF.prime_p)

							#instead of
							"""
							new_frame = Frame(Frame.SHARE, VERSION, PARTY_ID, shares[s_id] % SELF.prime_p)
						else:
							new_frame = Frame(Frame.SHARE, VERSION, PARTY_ID, shares[s_id])
						new_message = Message(Message.FRAME, (IP, PORT), new_frame)
						S.sendto(new_message.to_bytes(), SELF.known_parties[s_id])

				log("SLEF.shares: " + str(SELF.shares))

				LAST_RCVD_TIME = time.time()
				SELF.state = Party.GATE_COMP

		elif SELF.state == Party.GATE_COMP:
			delta_t = t - LAST_RCVD_TIME
			if VERSION == Frame.PCEAS:
				if not all(e in list(SELF.B_vectors.keys()) for e in SELF.circuit.get_input_ids()) and not INPUT_SET:
					if delta_t >= TIMEOUT:
						party_copy = list(SELF.known_parties.keys()).copy()
						party_copy.remove(PARTY_ID)
						for party in SELF.B_vectors.keys():
							party_copy.remove(party)

						for party in party_copy:
							if party not in SELF.blacklist:
								SELF.blacklist.append(party)
								log("Blacklisted " + str(party))
							if party in SELF.known_parties.keys():
								SELF.known_parties.pop(party)

						if len(party_copy) > 0:
							new_frame = Frame(Frame.MALICIOUS, VERSION, PARTY_ID, party_copy)
							new_message = Message(Message.FRAME, (IP, PORT), new_frame)
							S.sendto(new_message.to_bytes(), (BROADCAST_ADDR, PORT))

						SELF.clean()
						comp_pin.off()
						awaiting_pin.on()
						log("A party failed to participate.")

					return

			if not all(e in list(SELF.shares.keys()) for e in SELF.circuit.get_input_ids()) and not INPUT_SET:
				if delta_t >= TIMEOUT:
					if VERSION == Frame.PCEAS:
						party_copy = list(SELF.known_parties.keys()).copy()
						party_copy.remove(PARTY_ID)
						for party in SELF.B_vectors.keys():
							party_copy.remove(party)

						for party in party_copy:
							if party not in SELF.blacklist:
								SELF.blacklist.append(party)
								log("Blacklisted " + str(party))
							if party in SELF.known_parties.keys():
								SELF.known_parties.pop(party)

						if len(party_copy) > 0:
							new_frame = Frame(Frame.MALICIOUS, VERSION, PARTY_ID, party_copy)
							new_message = Message(Message.FRAME, (IP, PORT), new_frame)
							S.sendto(new_message.to_bytes(), (BROADCAST_ADDR, PORT))

					SELF.clean()
					comp_pin.off()
					awaiting_pin.on()
					log("A party failed to participate. May never receive anymore shares then stop the computation.")

				return
			else:
				if not SHARES_CHECKED:
					suspected = []
					log("shares = " + str(SELF.shares) + ", B = " + str(SELF.B_vectors) + ", inputs = " + str(SELF.circuit.get_input_ids()) + ".")
					if len(SELF.shares) == len(SELF.B_vectors) == len(SELF.circuit.get_input_ids()):
						for party, share in SELF.shares.items():
							if not party == PARTY_ID:
								tot = 0
								log("B vectors = ")
								for i in range(SELF.k):
									tot = (tot + SELF.B_vectors[party][i]*(PARTY_ID**i))%SELF.prime_p
								if (share*SELF.prime_g)%SELF.prime_p != tot%SELF.prime_p:
									log(str(party) + "failed either with shares or with B vect:")
									suspected.append(party)

						for party in suspected:
							if party not in SELF.blacklist:
								SELF.blacklist.append(party)
								log("Blacklisted " + str(party))
							if party in SELF.known_parties.keys():
								SELF.known_parties.pop(party)

						if len(suspected) > 0:
							new_frame = Frame(Frame.MALICIOUS, VERSION, PARTY_ID, suspected)
							new_message = Message(Message.FRAME, (IP, PORT), new_frame)
							S.sendto(new_message.to_bytes(), (BROADCAST_ADDR, PORT))

							SELF.clean()
							log("VSS did not pass")
							comp_pin.off()
							awaiting_pin.on()
							return

						SHARES_CHECKED = True

				gate = SELF.circuit.get_next_gate()
				log("curcuit = " + str(SELF.circuit) + ", position = " + str(gate))
				if gate:
					log("computing gate " + str(gate))
					for input_gate in gate.get_inputs():
						if input_gate.type == Gate.SHARE:
							input_gate.add_inputs([SELF.shares[input_gate.get_result()]])
							input_gate.compute()

					INPUT_SET = True
					gate.compute()
					if gate.type == Gate.MUL:
						log("cannot compute MUL gate for now. WIP")
				else:
					SELF.state = Party.RES
					# START current monitoring
					comp_pin.off()
					res_pin.on()
					# STOP

		elif SELF.state == Party.RES:
			result = SELF.circuit.get_gates()[-1].get_result()
			new_frame = Frame(Frame.RESULT, VERSION, PARTY_ID, result)
			new_message = Message(Message.FRAME, (IP, PORT), new_frame)
			log("sending result " + str(result) + " to " + str(SELF.applicant))
			S.sendto(new_message.to_bytes(), SELF.known_parties[SELF.applicant])
			SELF.clean()
			SELF.state = Party.AWAITING
			# START current monitoring
			res_pin.off()
			awaiting_pin.on()
			# STOP

	time.sleep_ms(1)

start()
while not QUIT:
	loop()